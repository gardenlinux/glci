package publisher

import (
	"context"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/log"
)

// Replicate copies the artifacts of all configured flavors that need a China source from their origin artifact source to their
// China artifact source, without publishing anything.
func (p *Publisher) Replicate(ctx context.Context, version, commit string) error {
	ctx = log.WithValues(ctx, "op", "replicate", "version", version, "commit", commit)

	replications, err := p.gatherReplications(ctx, version, commit)
	if err != nil {
		return fmt.Errorf("cannot gather replications: %w", err)
	}

	log.Info(ctx, "Replicating artifacts", "count", len(replications))

	replicate := concurrency.NewActivity(ctx)
	for _, replication := range replications {
		replicate.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "key", replication.Key, "originRepo", replication.Origin.Repository(), "destinationRepo",
				replication.Destination.Repository())

			log.Info(ctx, "Replicating artifact")
			inErr := cloudprovider.ReplicateArtifact(ctx, replication.Origin, replication.Destination, replication.Key)
			if inErr != nil {
				return fmt.Errorf("cannot replicate %s: %w", replication.Key, inErr)
			}

			return nil
		})
	}
	err = replicate.Wait()
	if err != nil {
		return fmt.Errorf("cannot replicate artifacts: %w", err)
	}

	log.Info(ctx, "Replication completed successfully")
	return nil
}

func (p *Publisher) gatherReplications(ctx context.Context, version, commit string) ([]cloudprovider.Replication, error) {
	replicationsByFlavor := make([][]cloudprovider.Replication, len(p.flavors))
	gather := concurrency.NewActivitySync(ctx)
	for i, flavorConfig := range p.flavors {
		gather.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			manifestKey := fmt.Sprintf("meta/singles/%s-%s-%.8s", flavorConfig.Flavor, version, commit)
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			log.Debug(ctx, "Retrieving manifest")
			manifest, er := cloudprovider.GetManifest(ctx, p.manifestSource, manifestKey)
			if er != nil {
				return nil, fmt.Errorf("cannot get manifest for %s: %w", flavorConfig.Flavor, er)
			}
			if manifest.Version != version {
				return nil, fmt.Errorf("manifest for %s has incorrect version %s", flavorConfig.Flavor, manifest.Version)
			}
			if manifest.BuildCommittish != commit && fmt.Sprintf("%.8s", manifest.BuildCommittish) != commit {
				return nil, fmt.Errorf("manifest for %s has incorrect commit %s", flavorConfig.Flavor, manifest.BuildCommittish)
			}

			var replications []cloudprovider.Replication
			for _, target := range p.targets {
				targetReplications, replErr := target.Replications(manifest)
				if replErr != nil {
					return nil, fmt.Errorf("cannot determine replications for %s: %w", flavorConfig.Flavor, replErr)
				}

				replications = append(replications, targetReplications...)
			}

			return func() error {
				replicationsByFlavor[i] = replications

				return nil
			}, nil
		})
	}
	err := gather.Wait()
	if err != nil {
		return nil, err
	}

	var replications []cloudprovider.Replication
	seen := make(map[cloudprovider.Replication]struct{})
	for _, flavorReplications := range replicationsByFlavor {
		for _, replication := range flavorReplications {
			_, ok := seen[replication]
			if ok {
				continue
			}

			seen[replication] = struct{}{}
			replications = append(replications, replication)
		}
	}

	return replications, nil
}
