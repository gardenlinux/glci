package cloudprovider

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/opencontainers/go-digest"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"

	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(PublishingTargetCategory, "OCI", func(b *module.Base) PublishingTarget {
		p := &containerTarget{
			ociTarget: &ociTarget{
				base:     b,
				typeName: "OCI",
			},
		}
		p.self = p

		return p
	})
}

type containerTarget struct {
	*ociTarget
}

func (*containerTarget) CanPublish(manifest *gardenlinux.Manifest) bool {
	return manifest.Platform == "container"
}

func (p *containerTarget) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	pl := platform(flavor)
	if pl != "container" {
		return nil, fmt.Errorf("invalid flavor %s for target %s", flavor, p.Type())
	}
	if pl != manifest.Platform {
		return nil, fmt.Errorf("flavor %s does not match platform %s", flavor, manifest.Platform)
	}

	repo, err := p.repository(flavor)
	if err != nil {
		return nil, err
	}
	environment := p.environment(repo)

	var imagePath gardenlinux.S3ReleaseFile
	imagePath, err = manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	ctx = log.WithValues(ctx, "key", imagePath.S3Key, "repository", repo, "source", p.pubCfg.Source)

	log.Info(ctx, "Publishing OCI artifact")
	var archive string
	archive, err = getObjectFile(ctx, p.source, imagePath.S3Key)
	if err != nil {
		return nil, fmt.Errorf("cannot download OCI archive: %w", err)
	}
	defer func() {
		_ = os.Remove(archive)
	}()

	var store *orasoci.ReadOnlyStore
	store, err = orasoci.NewFromTar(ctx, archive)
	if err != nil {
		return nil, fmt.Errorf("cannot open OCI archive: %w", err)
	}

	var descriptor specsv1.Descriptor
	descriptor, err = store.Resolve(ctx, flavor)
	if errors.Is(err, errdef.ErrNotFound) {
		descriptor, err = p.findArtifactRootDescriptor(archive)
		if err != nil {
			return nil, fmt.Errorf("cannot find artifact root descriptor: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve OCI artifact: %w", err)
	}

	log.Debug(ctx, "Copying artifact", "digest", descriptor.Digest)
	err = environment.retrier.Do(ctx, "copy graph", func(ctx context.Context) error {
		return oras.CopyGraph(ctx, store, environment.repository, descriptor, oras.DefaultCopyGraphOptions)
	})
	if err != nil {
		return nil, fmt.Errorf("cannot copy OCI artifact: %w", err)
	}

	err = os.Remove(archive)
	if err != nil {
		return nil, fmt.Errorf("cannot remove OCI archive: %w", err)
	}

	return ociIndividualOutput{
		Repository:   repo,
		Digest:       descriptor.Digest.String(),
		Size:         descriptor.Size,
		Architecture: manifest.Architecture,
	}, nil
}

func (*containerTarget) findArtifactRootDescriptor(archive string) (specsv1.Descriptor, error) {
	f, err := os.Open(archive)
	if err != nil {
		return specsv1.Descriptor{}, fmt.Errorf("cannot open OCI archive: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	r := tar.NewReader(f)
	for {
		var header *tar.Header
		header, err = r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return specsv1.Descriptor{}, fmt.Errorf("cannot read OCI archive: %w", err)
		}
		if header.Name != "index.json" {
			continue
		}

		var index specsv1.Index
		err = json.NewDecoder(r).Decode(&index)
		if err != nil {
			return specsv1.Descriptor{}, fmt.Errorf("invalid OCI archive index: %w", err)
		}
		if len(index.Manifests) != 1 {
			return specsv1.Descriptor{}, fmt.Errorf("expected exactly one manifest in OCI archive, got %d", len(index.Manifests))
		}

		return index.Manifests[0], nil
	}

	return specsv1.Descriptor{}, errors.New("OCI archive missing index.json")
}

func (p *containerTarget) Fuse(ctx context.Context, flavorManifests []gardenlinux.FlavorManifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	repo, err := p.repository(flavorManifests[0].Flavor)
	if err != nil {
		return nil, err
	}
	environment := p.environment(repo)

	descriptors := make([]specsv1.Descriptor, 0, len(flavorManifests))
	for _, flavorManifest := range flavorManifests {
		var output ociIndividualOutput
		output, err = individualPublishingOutputFromManifest[ociIndividualOutput](flavorManifest.Manifest)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", flavorManifest.Flavor, err)
		}

		if output.Repository != repo {
			return nil, fmt.Errorf("artifact repository %s does not match target repository %s", output.Repository, repo)
		}

		var arch string
		arch, err = p.architecture(output.Architecture)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", flavorManifest.Flavor, err)
		}

		descriptors = append(descriptors, specsv1.Descriptor{
			MediaType: specsv1.MediaTypeImageManifest,
			Digest:    digest.Digest(output.Digest),
			Size:      output.Size,
			Platform: &specsv1.Platform{
				Architecture: arch,
				OS:           "linux",
			},
		})
	}
	ctx = log.WithValues(ctx, "repository", repo, "tag", flavorManifests[0].Manifest.Version)

	index := specsv1.Index{
		SchemaVersion: 2,
		MediaType:     specsv1.MediaTypeImageIndex,
		Manifests:     descriptors,
	}

	var rawIndex []byte
	rawIndex, err = json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("cannot encode image index: %w", err)
	}

	descriptor := specsv1.Descriptor{
		MediaType: specsv1.MediaTypeImageIndex,
		Digest:    digest.FromBytes(rawIndex),
		Size:      int64(len(rawIndex)),
	}

	ctx = resilience.BeginOperation(ctx, "fuse/"+repo+"/"+flavorManifests[0].Manifest.Version, &ociOperationState{})

	log.Info(ctx, "Fusing OCI artifacts", "digest", descriptor.Digest)
	err = environment.retrier.Do(ctx, "push reference", func(ctx context.Context) error {
		return environment.repository.PushReference(ctx, descriptor, bytes.NewReader(rawIndex), flavorManifests[0].Manifest.Version)
	})
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot push image index: %w", err))
	}
	resilience.UpdateOperation(ctx, func(s *ociOperationState) *ociOperationState {
		s.Repository = repo
		s.Tag = flavorManifests[0].Manifest.Version
		return s
	})
	resilience.CompleteOperation(ctx)

	return ociPublishingOutput{
		Repository: repo,
		Tag:        flavorManifests[0].Manifest.Version,
		Digest:     descriptor.Digest.String(),
	}, nil
}
