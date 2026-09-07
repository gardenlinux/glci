package publisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/log"
)

// Unreplicate deletes the artifacts that replication would copy between artifact sources.
func (p *Publisher) Unreplicate(ctx context.Context, version, commit string, steamroll bool) error {
	ctx = log.WithValues(ctx, "op", "unreplicate", "version", version, "commit", commit)

	replications, err := p.gatherReplications(ctx, version, commit)
	if err != nil {
		return err
	}

	log.Info(ctx, "Unreplicating artifacts", "count", len(replications))

	type object struct {
		source cloudprovider.ArtifactSource
		key    string
	}

	originReplications := make(map[object][]cloudprovider.Replication)
	for _, r := range replications {
		origin := object{
			source: r.Origin,
			key:    r.Key,
		}
		originReplications[origin] = append(originReplications[origin], r)
	}

	err = concurrency.RunTasks(ctx, replications, func(replication cloudprovider.Replication) ([]cloudprovider.Replication, error) {
		destination := object{
			source: replication.Destination,
			key:    replication.Key,
		}

		return originReplications[destination], nil
	}, func(ctx context.Context, replication cloudprovider.Replication) error {
		ctx = log.WithValues(ctx, "key", replication.Key, "origin", replication.OriginID, "destination", replication.DestinationID)

		replicated, inErr := replication.IsReplicated(ctx)
		if inErr != nil {
			return fmt.Errorf("cannot check replication status of %s: %w", replication.Key, inErr)
		}
		if !replicated {
			if !steamroll {
				_, inErr = replication.Destination.GetObjectProperties(ctx, replication.Key)
				_, ok := errors.AsType[*cloudprovider.KeyNotFoundError](inErr)
				if ok {
					return nil
				}
				if inErr != nil {
					return fmt.Errorf("cannot check replication status of %s: %w", replication.Key, inErr)
				}

				return fmt.Errorf("invalid replicated artifact %s", replication.Key)
			}

			log.Debug(ctx, "Artifact not replicated but the steamroller keeps going")
		}

		log.Info(ctx, "Unreplicating artifact")
		inErr = replication.Destination.DeleteObject(ctx, replication.Key, steamroll)
		if inErr != nil {
			return fmt.Errorf("cannot unreplicate %s: %w", replication.Key, inErr)
		}

		return nil
	}, concurrency.FailureModeSkipDependents)
	if err != nil {
		return fmt.Errorf("cannot unreplicate artifacts: %w", err)
	}

	log.Info(ctx, "Unreplicating completed successfully")
	return nil
}
