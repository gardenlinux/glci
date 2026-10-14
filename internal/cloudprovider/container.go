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
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"

	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(PublishingTargetCategory, "Container", func(b *module.Base) PublishingTarget {
		p := &containerTarget{
			ociTarget: &ociTarget{
				base:     b,
				typeName: "Container",
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

	repo, err := p.repository(manifest.PublishingGroup)
	if err != nil {
		return nil, err
	}
	var imagePath gardenlinux.S3ReleaseFile
	imagePath, err = manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	ctx = log.WithValues(ctx, "key", imagePath.S3Key, "repository", repo, "source", p.pubCfg.Source)

	log.Info(ctx, "Publishing OCI container")

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

	var manifestDescriptor specsv1.Descriptor
	manifestDescriptor, err = store.Resolve(ctx, flavor)
	if errors.Is(err, errdef.ErrNotFound) {
		manifestDescriptor, err = p.findArtifactRootDescriptor(archive)
		if err != nil {
			return nil, fmt.Errorf("cannot find artifact root descriptor: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot resolve OCI artifact: %w", err)
	}
	ctx = log.WithValues(ctx, "digest", manifestDescriptor.Digest)

	environment := p.environment(repo)

	log.Debug(ctx, "Copying artifact")
	err = environment.copyGraph(ctx, store, manifestDescriptor)
	if err != nil {
		return nil, err
	}

	err = os.Remove(archive)
	if err != nil {
		return nil, fmt.Errorf("cannot remove OCI archive: %w", err)
	}

	return ociIndividualOutput{
		Repository:   repo,
		Digest:       manifestDescriptor.Digest.String(),
		Size:         manifestDescriptor.Size,
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
			return specsv1.Descriptor{}, fmt.Errorf("cannot decode OCI archive index: %w", err)
		}
		if len(index.Manifests) != 1 {
			return specsv1.Descriptor{}, fmt.Errorf("expected exactly one manifest in OCI archive, got %d", len(index.Manifests))
		}

		return index.Manifests[0], nil
	}

	return specsv1.Descriptor{}, errors.New("OCI archive missing index.json")
}

func (p *containerTarget) Fuse(ctx context.Context, manifests []*gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	repo, err := p.repository(manifests[0].PublishingGroup)
	if err != nil {
		return nil, err
	}
	environment := p.environment(repo)

	descriptors := make([]specsv1.Descriptor, 0, len(manifests))
	for _, manifest := range manifests {
		var output ociIndividualOutput
		output, err = individualPublishingOutputFromManifest[ociIndividualOutput](manifest)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", manifest.Flavor, err)
		}

		if output.Repository != repo {
			return nil, fmt.Errorf("artifact repository %s does not match target repository %s", output.Repository, repo)
		}

		var arch string
		arch, err = p.architecture(output.Architecture)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", manifest.Flavor, err)
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
	ctx = log.WithValues(ctx, "repository", repo, "tag", manifests[0].Version)

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
	ctx = log.WithValues(ctx, "digest", descriptor.Digest)

	ctx = resilience.BeginOperation(ctx, "fuse/"+repo+"/"+manifests[0].Version, &ociOperationState{})

	log.Info(ctx, "Fusing OCI artifacts")

	log.Debug(ctx, "Tagging artifact")
	err = environment.retrier.Do(ctx, "push reference", func(ctx context.Context) error {
		inErr := environment.repository.PushReference(ctx, descriptor, bytes.NewReader(rawIndex), manifests[0].Version)
		if inErr != nil {
			return fmt.Errorf("cannot push image index: %w", inErr)
		}

		return nil
	})
	if err != nil {
		return nil, resilience.FailOperation(ctx, err)
	}
	resilience.UpdateOperation(ctx, func(s *ociOperationState) *ociOperationState {
		s.Repository = repo
		s.Tag = manifests[0].Version
		return s
	})
	resilience.CompleteOperation(ctx)

	return ociPublishingOutput{
		Repository: repo,
		Tag:        manifests[0].Version,
		Digest:     descriptor.Digest.String(),
	}, nil
}

func (p *containerTarget) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "container"
}
