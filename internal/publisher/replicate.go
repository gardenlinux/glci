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

	replications, err := p.gatherReplications(ctx, version, commit)
	if err != nil {
		return err
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

		replicated, inErr := replication.IsReplicated(ctx)
		if inErr != nil {
			return fmt.Errorf("cannot check replication status of %s: %w", replication.Key, inErr)
		}
		if replicated {
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
