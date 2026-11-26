package publisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/errorreport"
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
		if target.RollbackDomain() == "" {
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

	var flavors []*flavor
	var groupPublications []groupPublication
	flavors, groupPublications, _, err = p.assembleFlavors(ctx, version, commit)
	if err != nil {
		return fmt.Errorf("cannot assemble flavors: %w", err)
	}

	var publications []publication
	for _, f := range flavors {
		publications = append(publications, f.publications...)
	}

	err = p.validatePreconditions(flavors, groupPublications, steamroll)
	if err != nil {
		return err
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

	groups := make(map[publication]*groupPublication)
	for i := range groupPublications {
		for j := range groupPublications[i].publications {
			groups[groupPublications[i].publications[j]] = &groupPublications[i]
		}
	}

	dependencies := func(t publishingTask) ([]publishingTask, error) {
		switch pub := t.(type) {
		case publication:
			if !pub.target.CanFuse() {
				return nil, nil
			}

			return []publishingTask{fusion{
				groups[pub],
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
		case publication:
			return p.unpublishFlavor(ctx, t, steamroll)

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

	for _, pub := range publications {
		if pub.target.CanFuse() {
			continue
		}

		isPublished, err := pub.target.IsPublished(pub.flavor.manifest, pub.destinationKey)
		if err != nil {
			return nil, fmt.Errorf("cannot determine publishing status for %s: %w", pub.flavor.manifest.Flavor, err)
		}
		if !isPublished {
			continue
		}

		if !pub.reversible {
			log.Info(ctx, "Skipping flavor that cannot be unpublished", "flavor", pub.flavor.manifest.Flavor)
			continue
		}

		tasks = append(tasks, pub)
	}

	for i := range groupPublications {
		if !groupPublications[i].isPublished() {
			continue
		}

		if !groupPublications[i].publications[0].reversible {
			for j := range groupPublications[i].publications {
				log.Info(ctx, "Skipping flavor that cannot be unpublished", "flavor",
					groupPublications[i].publications[j].flavor.manifest.Flavor)
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
	ctx = log.WithValues(ctx, "flavor", pub.flavor.manifest.Flavor, "targetType", pub.target.Type())
	group := pub.publishingGroup()
	if group != "" {
		ctx = log.WithValues(ctx, "publishingGroup", group)
	}

	dest := pub.destination().String()

	if pub.target.CanFuse() {
		var published bool
		func() {
			pub.flavor.manifestMtx.Lock()
			defer pub.flavor.manifestMtx.Unlock()

			published = pub.flavor.manifest.IndividualPublishedImageMetadata[dest] != nil
			if steamroll && !published {
				return
			}

			if pub.flavor.manifest.PublishedImageMetadata == nil {
				pub.flavor.manifest.PublishedImageMetadata = make(map[string]any)
			}
			pub.flavor.manifest.PublishedImageMetadata[dest] = pub.flavor.manifest.IndividualPublishedImageMetadata[dest]
		}()
		if steamroll && !published {
			log.Debug(ctx, "Flavor not published but the steamroller keeps going")
			return nil
		}
	}

	log.Info(ctx, "Unpublishing flavor")
	err := pub.target.Unpublish(ctx, pub.flavor.manifest, pub.destinationKey, steamroll)
	if err != nil {
		return fmt.Errorf("cannot unpublish %s from %s: %w", pub.flavor.manifest.Flavor, pub.target.Type(), err)
	}

	if !pub.target.CanFuse() {
		err = func() error {
			pub.flavor.manifestMtx.Lock()
			defer pub.flavor.manifestMtx.Unlock()

			delete(pub.flavor.manifest.PublishedImageMetadata, dest)

			log.Info(ctx, "Updating manifest")
			inErr := cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.flavor.manifest)
			if inErr != nil {
				return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.flavor.manifest.Flavor, inErr))
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Publisher) unpublishGroup(ctx context.Context, groupPub *groupPublication) error {
	ctx = log.WithValues(ctx, "publishingGroup", groupPub.group, "targetType", groupPub.target.Type())

	for _, pub := range groupPub.publications {
		dest := pub.destination().String()

		err := func() error {
			pub.flavor.manifestMtx.Lock()
			defer pub.flavor.manifestMtx.Unlock()

			delete(pub.flavor.manifest.PublishedImageMetadata, dest)
			delete(pub.flavor.manifest.IndividualPublishedImageMetadata, dest)

			log.Info(log.WithValues(ctx, "flavor", pub.flavor.manifest.Flavor), "Updating manifest")
			inErr := cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.flavor.manifest)
			if inErr != nil {
				return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.flavor.manifest.Flavor, inErr))
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	groupPub.groupManifest.Manifests = nil
	groupPub.groupManifest.GLCIVersion = cli.Version(ctx)

	log.Info(ctx, "Updating group manifest")
	err := cloudprovider.PutGroupManifest(ctx, p.manifestTarget, groupPub.manifestKey(), groupPub.groupManifest)
	if err != nil {
		return errorreport.MarkCritical(fmt.Errorf("cannot put group manifest for %s: %w", groupPub.group, err))
	}

	return nil
}

func (*Publisher) unfuseGroup(ctx context.Context, groupPub *groupPublication, steamroll bool) error {
	ctx = log.WithValues(ctx, "publishingGroup", groupPub.group, "targetType", groupPub.target.Type())

	manifests := groupPub.manifests
	seen := make(map[string]struct{}, len(groupPub.publications))
	for i := range groupPub.publications {
		pub := groupPub.publications[i]

		_, ok := seen[pub.destinationKey]
		if ok {
			continue
		}
		seen[pub.destinationKey] = struct{}{}

		dest := pub.destination().String()

		var fused bool
		func() {
			pub.flavor.manifestMtx.Lock()
			defer pub.flavor.manifestMtx.Unlock()

			fused = pub.flavor.manifest.PublishedImageMetadata[dest] != nil
		}()
		if steamroll && !fused {
			log.Debug(ctx, "Group not fused but the steamroller keeps going")
			continue
		}

		log.Info(ctx, "Unfusing group")
		err := groupPub.target.Unfuse(ctx, manifests, pub.destinationKey, steamroll)
		if err != nil {
			return fmt.Errorf("cannot unfuse group %s from %s: %w", groupPub.group, groupPub.target.Type(), err)
		}
	}

	return nil
}
