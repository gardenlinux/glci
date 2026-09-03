package publisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/errorreport"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/resilience"
)

// Unpublish unpublishes a release from all configured cloud providers.
func (p *Publisher) Unpublish(ctx context.Context, version, commit string, steamroll bool) error {
	ctx = log.WithValues(ctx, "op", "unpublish", "version", version, "commit", commit)

	ctx = resilience.WithStatePersistor(ctx, p.state, fmt.Sprintf("%s-%.8s", version, commit))
	err := p.unpublish(ctx, version, commit, steamroll)
	stateErr := resilience.PersistorError(ctx)
	if stateErr != nil {
		criticalStateErr := errorreport.MarkCritical(fmt.Errorf("cannot maintain state: %w", stateErr))
		if errors.Is(err, stateErr) {
			err = criticalStateErr
		} else {
			err = errors.Join(err, criticalStateErr)
		}
	}
	return err
}

func (p *Publisher) unpublish(ctx context.Context, version, commit string, steamroll bool) error {
	rollbackHandlers := make([]resilience.RollbackHandler, 0, len(p.targets))
	for _, target := range p.targets {
		if !target.CanUnpublish() {
			continue
		}

		rollbackHandlers = append(rollbackHandlers, target)
	}
	err := resilience.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	resilience.ClearState(ctx)
	err = resilience.PersistorError(ctx)
	if err != nil {
		return err
	}

	var publications []publication
	var groupPublications []groupPublication
	publications, groupPublications, _, err = p.fetchAllManifests(ctx, version, commit, steamroll)
	if err != nil {
		return fmt.Errorf("cannot fetch manifests: %w", err)
	}

	var tasks []publishingTask
	tasks, err = p.classifyUnpublishTasks(ctx, publications, groupPublications)
	if err != nil {
		return err
	}

	type fusion struct {
		*groupPublication
	}

	for i := range tasks {
		pub, ok := tasks[i].(*groupPublication)
		if !ok {
			continue
		}

		tasks = append(tasks, fusion{
			pub,
		})
	}

	groups := make(map[string]*groupPublication)
	for i := range groupPublications {
		groups[groupPublications[i].Group] = &groupPublications[i]
	}

	dependencies := func(t publishingTask) ([]publishingTask, error) {
		switch pub := t.(type) {
		case *publication:
			if pub.PublishingGroup == "" {
				return nil, nil
			}

			return []publishingTask{fusion{
				groups[pub.PublishingGroup],
			}}, nil

		case *groupPublication:
			deps := make([]publishingTask, len(pub.publications))
			for i := range pub.publications {
				deps[i] = pub.publications[i]
			}

			return deps, nil

		case fusion:
			return nil, nil

		default:
			return nil, fmt.Errorf("unknown publishing task type %T", pub)
		}
	}

	run := func(ctx context.Context, t publishingTask) error {
		switch t := t.(type) {
		case *publication:
			return p.unpublishFlavor(ctx, *t, steamroll)

		case *groupPublication:
			return p.unpublishGroup(ctx, t)

		case fusion:
			return p.unfuseGroup(ctx, t.groupPublication, steamroll)

		default:
			return fmt.Errorf("unknown publishing task type %T", t)
		}
	}

	log.Info(ctx, "Unpublishing flavors", "count", p.countFlavors(tasks))
	err = concurrency.RunTasks(ctx, tasks, dependencies, run, concurrency.FailureModeSkipDependents)
	if err != nil {
		return fmt.Errorf("cannot unpublish targets: %w", err)
	}

	log.Info(ctx, "Unpublishing completed successfully")
	return nil
}

func (*Publisher) classifyUnpublishTasks(ctx context.Context, publications []publication, groupPublications []groupPublication) (
	[]publishingTask, error,
) {
	var tasks []publishingTask

	for i := range publications {
		if publications[i].PublishingGroup != "" {
			continue
		}

		isPublished, err := publications[i].Target.IsPublished(publications[i].Manifest)
		if err != nil {
			return nil, fmt.Errorf("cannot determine publishing status for %s: %w", publications[i].Flavor, err)
		}
		if !isPublished {
			continue
		}

		if !publications[i].Target.CanUnpublish() {
			log.Info(ctx, "Skipping flavor that cannot be unpublished", "flavor", publications[i].Flavor)
			continue
		}

		tasks = append(tasks, &publications[i])
	}

	for i := range groupPublications {
		if !groupPublications[i].isPublished() {
			continue
		}

		if !groupPublications[i].Target.CanUnpublish() {
			for j := range groupPublications[i].publications {
				log.Info(ctx, "Skipping flavor that cannot be unpublished", "flavor", groupPublications[i].publications[j].Flavor)
			}
			continue
		}

		for j := range groupPublications[i].publications {
			tasks = append(tasks, groupPublications[i].publications[j])
		}
		tasks = append(tasks, &groupPublications[i])
	}

	return tasks, nil
}

func (p *Publisher) unpublishFlavor(ctx context.Context, pub publication, steamroll bool) error {
	ctx = log.WithValues(ctx, "flavor", pub.Flavor, "targetType", pub.Target.Type())
	if pub.PublishingGroup != "" {
		ctx = log.WithValues(ctx, "group", pub.PublishingGroup)
	}

	if pub.PublishingGroup != "" {
		if steamroll && pub.Manifest.IndividualPublishedImageMetadata == nil {
			log.Debug(ctx, "Flavor not published but the steamroller keeps going")

			return nil
		}

		pub.Manifest.PublishedImageMetadata = pub.Manifest.IndividualPublishedImageMetadata
	}

	log.Info(ctx, "Unpublishing flavor")
	err := pub.Target.Unpublish(ctx, pub.Manifest, steamroll)
	if err != nil {
		return fmt.Errorf("cannot unpublish %s from %s: %w", pub.Flavor, pub.Target.Type(), err)
	}

	if pub.PublishingGroup == "" {
		pub.Manifest.PublishedImageMetadata = nil

		log.Info(ctx, "Updating manifest")
		err = cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.Manifest)
		if err != nil {
			return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.Flavor, err))
		}
	}

	return nil
}

func (p *Publisher) unpublishGroup(ctx context.Context, groupPub *groupPublication) error {
	ctx = log.WithValues(ctx, "group", groupPub.Group, "targetType", groupPub.Target.Type())

	for _, pub := range groupPub.publications {
		pub.Manifest.PublishedImageMetadata = nil
		pub.Manifest.IndividualPublishedImageMetadata = nil

		log.Info(log.WithValues(ctx, "flavor", pub.Flavor), "Updating manifest")
		err := cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.Manifest)
		if err != nil {
			return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.Flavor, err))
		}
	}

	groupPub.GroupManifest.Manifests = nil

	log.Info(ctx, "Updating group manifest")
	err := cloudprovider.PutGroupManifest(ctx, p.manifestTarget, groupPub.manifestKey(), groupPub.GroupManifest)
	if err != nil {
		return errorreport.MarkCritical(fmt.Errorf("cannot put group manifest for %s: %w", groupPub.Group, err))
	}

	return nil
}

func (*Publisher) unfuseGroup(ctx context.Context, groupPub *groupPublication, steamroll bool) error {
	ctx = log.WithValues(ctx, "group", groupPub.Group, "targetType", groupPub.Target.Type())

	for _, pub := range groupPub.publications {
		if steamroll && pub.Manifest.PublishedImageMetadata == nil {
			log.Debug(ctx, "Group not fused but the steamroller keeps going")

			return nil
		}
	}

	manifests := make([]gardenlinux.FlavorManifest, len(groupPub.publications))
	for i, pub := range groupPub.publications {
		manifests[i] = pub.FlavorManifest
	}

	log.Info(ctx, "Unfusing group")
	err := groupPub.Target.Unfuse(ctx, manifests, steamroll)
	if err != nil {
		return fmt.Errorf("cannot unfuse group %s from %s: %w", groupPub.Group, groupPub.Target.Type(), err)
	}

	return nil
}
