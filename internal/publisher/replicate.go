package publisher

import (
	"context"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/log"
)

// Replicate copies artifacts requiring replication between artifact sources.
func (p *Publisher) Replicate(ctx context.Context, version, commit string) error {
	ctx = log.WithValues(ctx, "op", "replicate", "version", version, "commit", commit)

	requiredReplications := make([][]cloudprovider.Replication, len(p.flavors))
	gatherReplications := concurrency.NewActivity(ctx)
	for i, flavorConfig := range p.flavors {
		gatherReplications.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "flavor", flavorConfig.Flavor)

			manifest, inErr := p.fetchManifest(ctx, flavorConfig.Flavor, version, commit)
			if inErr != nil {
				return inErr
			}

			var target cloudprovider.PublishingTarget
			target, inErr = p.selectTarget(manifest, flavorConfig.Flavor)
			if inErr != nil {
				return inErr
			}

			var replications []cloudprovider.Replication
			replications, inErr = target.RequiredReplications(manifest)
			if inErr != nil {
				return fmt.Errorf("cannot determine replications for %s: %w", flavorConfig.Flavor, inErr)
			}
			requiredReplications[i] = replications

			return nil
		})
	}
	err := gatherReplications.Wait()
	if err != nil {
		return fmt.Errorf("cannot gather replications: %w", err)
	}

	var replications []cloudprovider.Replication
	seen := make(map[cloudprovider.Replication]struct{})
	for _, flavorReplications := range requiredReplications {
		for _, replication := range flavorReplications {
			_, ok := seen[replication]
			if ok {
				continue
			}
			seen[replication] = struct{}{}

			replications = append(replications, replication)
		}
	}

	log.Info(ctx, "Replicating artifacts", "count", len(replications))

	type object struct {
		source cloudprovider.ArtifactSource
		key    string
	}

	objectReplications := make(map[object][]cloudprovider.Replication)
	for _, r := range replications {
		destination := object{
			source: r.Destination,
			key:    r.Key,
		}
		objectReplications[destination] = append(objectReplications[destination], r)
	}

	err = concurrency.RunTasks(ctx, replications, func(replication cloudprovider.Replication) ([]cloudprovider.Replication, error) {
		origin := object{
			source: replication.Origin,
			key:    replication.Key,
		}

		return objectReplications[origin], nil
	}, func(ctx context.Context, replication cloudprovider.Replication) error {
		ctx = log.WithValues(ctx, "key", replication.Key, "origin", replication.OriginID, "destination", replication.DestinationID)

		alreadyReplicated, inErr := replication.IsReplicated(ctx)
		if inErr != nil {
			return fmt.Errorf("cannot check replication status of %s: %w", replication.Key, inErr)
		}
		if alreadyReplicated {
			return nil
		}

		log.Info(ctx, "Replicating artifact")
		inErr = cloudprovider.ReplicateArtifact(ctx, replication.Origin, replication.Destination, replication.Key)
		if inErr != nil {
			return fmt.Errorf("cannot replicate %s: %w", replication.Key, inErr)
		}

		return nil
	}, concurrency.FailureModeSkipDependents)
	if err != nil {
		return fmt.Errorf("cannot replicate artifacts: %w", err)
	}

	log.Info(ctx, "Replicating completed successfully")
	return nil
}
