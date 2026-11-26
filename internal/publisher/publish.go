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
		if target.RollbackDomain() == "" {
			continue
		}

		rollbackHandlers = append(rollbackHandlers, target)
	}
	err := resilience.Rollback(ctx, rollbackHandlers)
	if err != nil {
		return fmt.Errorf("cannot roll back: %w", err)
	}

	var flavors []*flavor
	var groupPublications []groupPublication
	flavors, groupPublications, commit, err = p.assembleFlavors(ctx, version, commit)
	if err != nil {
		return fmt.Errorf("cannot assemble flavors: %w", err)
	}

	var publications []publication
	for _, f := range flavors {
		publications = append(publications, f.publications...)
	}

	err = p.validatePreconditions(flavors, groupPublications, false)
	if err != nil {
		return err
	}

	var manifestsInDescriptor []ocm.ManifestDestination
	manifestsInDescriptor, err = p.manifestsInDescriptor(publications)
	if err != nil {
		return fmt.Errorf("cannot determine component descriptor flavors: %w", err)
	}

	var descriptor *ocm.ComponentDescriptor
	descriptor, err = ocm.BuildComponentDescriptor(ctx, p.manifestSource, manifestsInDescriptor, p.cfg.OCM.ProjectRepository,
		p.cfg.OCM.Provider, p.cfg.OCM.Responsibles, p.ocmTarget, p.aliases, cli.Version(ctx), version, commit)
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
		case publication:
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
		case publication:
			return p.publishFlavor(ctx, pub)

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
		err = ocm.AddPublicationOutput(ctx, descriptor, manifestsInDescriptor)
		if err != nil {
			return fmt.Errorf("cannot add publishing output to component descriptor: %w", err)
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

func (p *Publisher) manifestsInDescriptor(publications []publication) ([]ocm.ManifestDestination, error) {
	flavorPublications := make(map[string][]publication)
	for _, pub := range publications {
		f := pub.flavor.manifest.Flavor
		flavorPublications[f] = append(flavorPublications[f], pub)
	}

	var manifestDestinations []ocm.ManifestDestination
	for _, flavorCfg := range p.cfg.OCM.Flavors {
		pubs := flavorPublications[flavorCfg.Flavor]

		var selectedPublications []publication
		if len(flavorCfg.Destinations) > 0 {
			for _, dest := range flavorCfg.Destinations {
				var found bool
				for _, pub := range pubs {
					if p.destinationMatches(pub.destination(), dest) {
						selectedPublications = append(selectedPublications, pub)
						found = true
					}
				}
				if !found {
					return nil, fmt.Errorf("flavor %q not published to destination %q", flavorCfg.Flavor, dest)
				}
			}
		} else {
			selectedPublications = pubs
		}

		for _, pub := range selectedPublications {
			manifestDestinations = append(manifestDestinations, ocm.ManifestDestination{
				Manifest: pub.flavor.manifest,
				Target:   pub.target,
				Key:      pub.destinationKey,
			})
		}
	}

	return manifestDestinations, nil
}

func (*Publisher) classifyPublishTasks(publications []publication, groupPublications []groupPublication) ([]publishingTask,
	[]publishingTask, error,
) {
	var reversibleTasks, irreversibleTasks []publishingTask

	for _, pub := range publications {
		if pub.target.CanFuse() {
			continue
		}

		isPublished, err := pub.target.IsPublished(pub.flavor.manifest, pub.destinationKey)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot determine publishing status for %s: %w", pub.flavor.manifest.Flavor, err)
		}
		if isPublished {
			continue
		}

		tasks := &reversibleTasks
		if !pub.reversible {
			tasks = &irreversibleTasks
		}
		*tasks = append(*tasks, pub)
	}

	for i := range groupPublications {
		if groupPublications[i].isPublished() {
			continue
		}

		tasks := &reversibleTasks
		if !groupPublications[i].publications[0].reversible {
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
	ctx = log.WithValues(ctx, "flavor", pub.flavor.manifest.Flavor, "targetType", pub.target.Type())
	group := pub.publishingGroup()
	if group != "" {
		ctx = log.WithValues(ctx, "publishingGroup", group)
	}

	uptime := cli.ExecTime(ctx)
	if uptime != 0 && uptime.Hours() > 5 {
		return errors.New("publishing taking too long, restart to resume")
	}

	batch := pub.flavor.manifest.Flavor
	if group != "" {
		batch = group
	}
	ctx = resilience.WithDomain(resilience.WithUndeadMode(resilience.WithBatch(ctx, batch), true), pub.target.RollbackDomain())

	dest := pub.destination().String()

	func() {
		pub.flavor.manifestMtx.Lock()
		defer pub.flavor.manifestMtx.Unlock()

		delete(pub.flavor.manifest.PublishedImageMetadata, dest)
		delete(pub.flavor.manifest.IndividualPublishedImageMetadata, dest)
	}()

	log.Info(ctx, "Publishing flavor")
	output, err := pub.target.Publish(ctx, pub.flavor.manifest.Flavor, pub.flavor.manifest, pub.destinationKey)
	if err != nil {
		return fmt.Errorf("cannot publish %s to %s: %w", pub.flavor.manifest.Flavor, pub.target.Type(), err)
	}

	err = func() error {
		pub.flavor.manifestMtx.Lock()
		defer pub.flavor.manifestMtx.Unlock()

		if pub.target.CanFuse() {
			if pub.flavor.manifest.IndividualPublishedImageMetadata == nil {
				pub.flavor.manifest.IndividualPublishedImageMetadata = make(map[string]any)
			}
			pub.flavor.manifest.IndividualPublishedImageMetadata[dest] = output

			return nil
		}

		if pub.flavor.manifest.PublishedImageMetadata == nil {
			pub.flavor.manifest.PublishedImageMetadata = make(map[string]any)
		}
		pub.flavor.manifest.PublishedImageMetadata[dest] = output

		log.Info(ctx, "Updating manifest")
		resilience.RemoveCompletedOperations(ctx, pub.flavor.manifest.Flavor)
		inErr := cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.flavor.manifest)
		if inErr != nil {
			return errorreport.MarkCritical(fmt.Errorf("cannot put manifest for %s: %w", pub.flavor.manifest.Flavor, inErr))
		}

		return nil
	}()
	if err != nil {
		return err
	}

	return nil
}

func (p *Publisher) publishGroup(ctx context.Context, groupPub *groupPublication) error {
	ctx = log.WithValues(ctx, "publishingGroup", groupPub.group, "targetType", groupPub.target.Type())
	ctx = resilience.WithDomain(resilience.WithUndeadMode(resilience.WithBatch(ctx, groupPub.group), true),
		groupPub.target.RollbackDomain())

	log.Info(ctx, "Fusing group", "count", len(groupPub.manifests))

	outputs := make(map[string]any, len(groupPub.publications))
	for i := range groupPub.publications {
		pub := groupPub.publications[i]

		output, ok := outputs[pub.destinationKey]
		if !ok {
			var err error
			output, err = groupPub.target.Fuse(ctx, groupPub.manifests, pub.destinationKey)
			if err != nil {
				return fmt.Errorf("cannot fuse group %s to %s: %w", groupPub.group, groupPub.target.Type(), err)
			}

			outputs[pub.destinationKey] = output
		}

		dest := pub.destination().String()
		err := func() error {
			pub.flavor.manifestMtx.Lock()
			defer pub.flavor.manifestMtx.Unlock()

			if pub.flavor.manifest.PublishedImageMetadata == nil {
				pub.flavor.manifest.PublishedImageMetadata = make(map[string]any)
			}
			pub.flavor.manifest.PublishedImageMetadata[dest] = output

			log.Info(log.WithValues(ctx, "flavor", pub.flavor.manifest.Flavor), "Updating manifest")
			inErr := cloudprovider.PutManifest(ctx, p.manifestTarget, pub.manifestKey(), pub.flavor.manifest)
			if inErr != nil {
				return fmt.Errorf("cannot put manifest for %s: %w", pub.flavor.manifest.Flavor, inErr)
			}

			return nil
		}()
		if err != nil {
			return err
		}
	}

	groupPub.groupManifest = &gardenlinux.GroupManifest{
		Version:         groupPub.publications[0].flavor.manifest.Version,
		BuildCommittish: groupPub.publications[0].flavor.manifest.BuildCommittish,
		GLCIVersion:     cli.Version(ctx),
		Manifests:       groupPub.manifestKeys,
	}

	log.Info(ctx, "Updating group manifest")
	resilience.RemoveCompletedOperations(ctx, groupPub.group)
	err := cloudprovider.PutGroupManifest(ctx, p.manifestTarget, groupPub.manifestKey(), groupPub.groupManifest)
	if err != nil {
		return errorreport.MarkCritical(fmt.Errorf("cannot put group manifest for %s: %w", groupPub.group, err))
	}

	return nil
}
