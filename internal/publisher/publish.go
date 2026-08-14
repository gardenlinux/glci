package publisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/errorreport"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm"
	"github.com/gardenlinux/glci/internal/resilience"
)

// Publish publishes a release to all configured cloud providers.
func (p *Publisher) Publish(ctx context.Context, version, commit string, omitIrreversible, omitComponentDescriptor bool) error {
	ctx = log.WithValues(ctx, "op", "publish", "version", version, "commit", commit)

	ctx = resilience.WithStatePersistor(ctx, p.state, fmt.Sprintf("%s-%.8s", version, commit))
	err := p.publish(ctx, version, commit, omitIrreversible, omitComponentDescriptor)
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

func (p *Publisher) publish(ctx context.Context, version, commit string, omitIrreversible, omitComponentDescriptor bool) error {
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

	var publications []publication
	var groupPublications []groupPublication
	publications, groupPublications, commit, err = p.fetchManifests(ctx, version, commit, false)
	if err != nil {
		return fmt.Errorf("cannot fetch manifests: %w", err)
	}

	manifestsInDescriptor := make([]gardenlinux.FlavorManifest, 0, len(publications))
	for _, pub := range publications {
		if pub.InComponentDescriptor {
			manifestsInDescriptor = append(manifestsInDescriptor, pub.FlavorManifest)
		}
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, p.manifestSource, manifestsInDescriptor, p.ocmTarget, p.aliases, cli.Version(ctx),
		version, commit)
	if err != nil {
		return fmt.Errorf("cannot build component descriptor: %w", err)
	}

	var reversibleTasks, irreversibleTasks []publishingTask
	reversibleTasks, irreversibleTasks, err = p.classifyPublishTasks(publications, groupPublications)
	if err != nil {
		return err
	}

	dependencies := func(t publishingTask) ([]publishingTask, error) {
		switch pub := t.(type) {
		case *publication:
			return nil, nil

		case *groupPublication:
			deps := make([]publishingTask, len(pub.publications))
			for i := range pub.publications {
				deps[i] = pub.publications[i]
			}

			return deps, nil

		default:
			return nil, fmt.Errorf("unknown publishing task type %T", pub)
		}
	}

	run := func(ctx context.Context, t publishingTask) error {
		switch pub := t.(type) {
		case *publication:
			return p.publishFlavor(ctx, *pub)

		case *groupPublication:
			return p.publishGroup(ctx, pub)

		default:
			return fmt.Errorf("unknown publishing task type %T", t)
		}
	}

	count := p.countFlavors(reversibleTasks)
	if !omitIrreversible {
		count += p.countFlavors(irreversibleTasks)
	}
	log.Info(ctx, "Publishing flavors", "count", count)

	err = concurrency.RunTasks(ctx, reversibleTasks, dependencies, run, concurrency.FailureModeSkipDependents)
	if err != nil {
		return fmt.Errorf("cannot publish targets: %w", err)
	}

	resilience.ClearState(ctx)
	err = resilience.PersistorError(ctx)
	if err != nil {
		return err
	}

	if omitIrreversible {
		cnt := p.countFlavors(irreversibleTasks)
		if cnt > 0 {
			log.Info(ctx, "Skipping flavors that cannot be unpublished", "count", cnt)
		}
	} else {
		err = concurrency.RunTasks(ctx, irreversibleTasks, dependencies, run, concurrency.FailureModeSkipDependents)
		if err != nil {
			return fmt.Errorf("cannot publish irreversible targets: %w", err)
		}
	}

	if omitIrreversible || omitComponentDescriptor {
		log.Info(ctx, "Skipping component descriptor")
	} else {
		log.Debug(ctx, "Finalizing component descriptor")
		err = ocm.AddPublicationOutput(descriptor, manifestsInDescriptor)
		if err != nil {
			return fmt.Errorf("cannot add publication output to component descriptor: %w", err)
		}

		var descriptorYAML []byte
		descriptorYAML, err = descriptor.ToYAML()
		if err != nil {
			return fmt.Errorf("invalid component descriptor: %w", err)
		}

		ctx = log.WithValues(ctx, "ocmRepoBase", p.ocmTarget.OCMRepositoryBase())
		log.Info(ctx, "Publishing component descriptor")
		err = p.ocmTarget.PublishComponentDescriptor(ctx, version, descriptorYAML)
		if err != nil {
			return fmt.Errorf("cannot publish component descriptor: %w", err)
		}
	}

	log.Info(ctx, "Publishing completed successfully")
	return nil
}

func (*Publisher) classifyPublishTasks(publications []publication, groupPublications []groupPublication) ([]publishingTask,
	[]publishingTask, error,
) {
	var reversibleTasks, irreversibleTasks []publishingTask

	for i := range publications {
		if publications[i].PublishingGroup != "" {
			continue
		}

		isPublished, err := publications[i].Target.IsPublished(publications[i].Manifest)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot determine publishing status for %s: %w", publications[i].Flavor, err)
		}
		if isPublished {
			continue
		}

		tasks := &reversibleTasks
		if !publications[i].Target.CanUnpublish() {
			tasks = &irreversibleTasks
		}
		*tasks = append(*tasks, &publications[i])
	}

	for i := range groupPublications {
		if groupPublications[i].isPublished() {
			continue
		}

		tasks := &reversibleTasks
		if !groupPublications[i].Target.CanUnpublish() {
			tasks = &irreversibleTasks
		}
		for j := range groupPublications[i].publications {
			*tasks = append(*tasks, groupPublications[i].publications[j])
		}
		*tasks = append(*tasks, &groupPublications[i])
	}

	return reversibleTasks, irreversibleTasks, nil
}

func (p *Publisher) publishFlavor(ctx context.Context, pub publication) error {
	ctx = log.WithValues(ctx, "flavor", pub.Flavor, "targetType", pub.Target.Type())
	if pub.PublishingGroup != "" {
		ctx = log.WithValues(ctx, "group", pub.PublishingGroup)
	}

	uptime := cli.ExecTime(ctx)
	if uptime != 0 && uptime.Hours() > 5 {
		return errors.New("publishing taking too long, restart to resume")
	}

	batch := pub.Flavor
	if pub.PublishingGroup != "" {
		batch = pub.PublishingGroup
	}
	ctx = resilience.WithDomain(resilience.WithUndeadMode(resilience.WithBatch(ctx, batch), true), pub.Target.RollbackDomain())

	pub.Manifest.PublishedImageMetadata = nil
	pub.Manifest.IndividualPublishedImageMetadata = nil

	log.Info(ctx, "Publishing flavor")
	output, err := pub.Target.Publish(ctx, pub.Flavor, pub.Manifest)
	if err != nil {
		return fmt.Errorf("cannot publish %s to %s: %w", pub.Flavor, pub.Target.Type(), err)
	}

	if pub.PublishingGroup != "" {
		pub.Manifest.IndividualPublishedImageMetadata = output
	} else {
		pub.Manifest.PublishedImageMetadata = output
	}

	if pub.PublishingGroup == "" {
		log.Info(ctx, "Updating manifest")
		resilience.RemoveCompletedOperations(ctx, pub.Flavor)
		err = cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.Manifest)
		if err != nil {
			return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.Flavor, err))
		}
	}

	return nil
}

func (p *Publisher) publishGroup(ctx context.Context, groupPub *groupPublication) error {
	ctx = log.WithValues(ctx, "group", groupPub.Group, "targetType", groupPub.Target.Type())
	ctx = resilience.WithDomain(resilience.WithUndeadMode(resilience.WithBatch(ctx, groupPub.Group), true),
		groupPub.Target.RollbackDomain())

	manifests := make([]gardenlinux.FlavorManifest, len(groupPub.publications))
	for i, pub := range groupPub.publications {
		manifests[i] = pub.FlavorManifest
	}

	log.Info(ctx, "Fusing group", "count", len(groupPub.publications))
	output, err := groupPub.Target.Fuse(ctx, manifests)
	if err != nil {
		return fmt.Errorf("cannot fuse group %s to %s: %w", groupPub.Group, groupPub.Target.Type(), err)
	}

	manifestKeys := make([]string, len(groupPub.publications))
	for i, pub := range groupPub.publications {
		manifestKeys[i] = pub.manifestKey()

		pub.Manifest.PublishedImageMetadata = output

		log.Info(log.WithValues(ctx, "flavor", pub.Flavor), "Updating manifest")
		err = cloudprovider.PutManifest(ctx, p.manifestTarget, manifestKeys[i], pub.Manifest)
		if err != nil {
			return fmt.Errorf("cannot put manifest for %s: %w", pub.Flavor, err)
		}
	}

	groupPub.GroupManifest = &gardenlinux.GroupManifest{
		Version:         groupPub.publications[0].Manifest.Version,
		BuildCommittish: groupPub.publications[0].Manifest.BuildCommittish,
		Manifests:       manifestKeys,
	}

	log.Info(ctx, "Updating group manifest")
	resilience.RemoveCompletedOperations(ctx, groupPub.Group)
	err = cloudprovider.PutGroupManifest(ctx, p.manifestTarget, groupPub.manifestKey(), groupPub.GroupManifest)
	if err != nil {
		return errorreport.MarkCritical(fmt.Errorf("cannot put group manifest for %s: %w", groupPub.Group, err))
	}

	return nil
}
