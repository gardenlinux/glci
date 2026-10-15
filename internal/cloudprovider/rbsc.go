package cloudprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/ocm/access"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(PublishingTargetCategory, "RBSC", func(b *module.Base) PublishingTarget {
		p := &rbscTarget{
			ociTarget: &ociTarget{
				base:     b,
				typeName: "RBSC",
			},
		}
		p.self = p

		return p
	})
}

type rbscTarget struct {
	*ociTarget
}

func (p *rbscTarget) CanPublish(manifest *gardenlinux.Manifest) bool {
	_, ok := p.pubCfg.Repositories[manifest.PublishingGroup]

	return ok
}

func (p *rbscTarget) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	commit := fmt.Sprintf("%.8s", manifest.BuildCommittish)
	baseName := fmt.Sprintf("%s-%s-%s", flavor, manifest.Version, commit)
	features := strings.Join(manifest.Modifiers, ",")

	repo, err := p.repository(manifest.PublishingGroup)
	if err != nil {
		return nil, err
	}
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, err
	}
	ctx = log.WithValues(ctx, "repository", repo, "architecture", arch, "source", p.pubCfg.Source)

	var buildTime time.Time
	buildTime, err = time.ParseInLocation("2006-01-02 15:04:05.999999", manifest.BuildTimestamp, time.UTC)
	if err != nil {
		return nil, fmt.Errorf("invalid build timestamp %q: %w", manifest.BuildTimestamp, err)
	}

	objectFiles := make([]string, len(manifest.Paths))
	defer func() {
		for _, f := range objectFiles {
			if f != "" {
				_ = os.Remove(f)
			}
		}
	}()

	log.Info(ctx, "Publishing OCI artifact")

	var storeDir string
	storeDir, err = os.MkdirTemp("", "")
	if err != nil {
		return nil, fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(storeDir)
	}()

	var store *orasfile.Store
	store, err = orasfile.New(storeDir)
	if err != nil {
		return nil, fmt.Errorf("cannot create local store in %s: %w", storeDir, err)
	}
	defer func() {
		_ = store.Close()
	}()

	objectDescriptors := make([]specsv1.Descriptor, len(objectFiles))

	addObjects := concurrency.NewActivity(ctx)
	for i, path := range manifest.Paths {
		addObjects.Go(func(ctx context.Context) error {
			var inErr error
			objectDescriptors[i], objectFiles[i], inErr = p.addObject(ctx, store, path, arch)
			if inErr != nil {
				return fmt.Errorf("cannot add object %s: %w", path.S3Key, inErr)
			}

			return nil
		})
	}
	err = addObjects.Wait()
	if err != nil {
		return nil, err
	}

	rawConfig := []byte("{}")
	configDescriptor := specsv1.Descriptor{
		MediaType: "application/vnd.unknown.config.v1+json",
		Digest:    digest.FromBytes(rawConfig),
		Size:      int64(len(rawConfig)),
		Annotations: map[string]string{
			"base_name":    baseName,
			"architecture": arch,
		},
	}
	err = store.Push(ctx, configDescriptor, bytes.NewReader(rawConfig))
	if err != nil {
		return nil, fmt.Errorf("cannot push config: %w", err)
	}

	var manifestDescriptor specsv1.Descriptor
	manifestDescriptor, err = oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, "", oras.PackManifestOptions{
		Layers:           objectDescriptors,
		ConfigDescriptor: &configDescriptor,
		ManifestAnnotations: map[string]string{
			"version":                          manifest.Version,
			"base_name":                        baseName,
			"architecture":                     arch,
			"features":                         features,
			"commit":                           commit,
			"org.opencontainers.image.created": buildTime.UTC().Format(time.RFC3339),
			"org.opencontainers.image.description": fmt.Sprintf("Base name: %s Cname: %s Architecture: %s Features: %s Commit: %s ",
				baseName, cname(flavor), arch, features, commit),
			"org.opencontainers.image.title":    "Garden Linux",
			"org.opencontainers.image.source":   "https://github.com/gardenlinux/gardenlinux",
			"org.opencontainers.image.url":      "https://gardenlinux.org",
			"org.opencontainers.image.vendor":   "Garden Linux",
			"org.opencontainers.image.version":  manifest.Version,
			"org.opencontainers.image.revision": commit,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("cannot pack image manifest: %w", err)
	}
	ctx = log.WithValues(ctx, "digest", manifestDescriptor.Digest)

	environment := p.environment(repo)

	log.Debug(ctx, "Copying artifact")
	err = environment.copyGraph(ctx, store, manifestDescriptor)
	if err != nil {
		return nil, err
	}

	err = store.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close local store: %w", err)
	}

	err = os.RemoveAll(storeDir)
	if err != nil {
		return nil, fmt.Errorf("cannot remove temporary directory: %w", err)
	}

	for _, f := range objectFiles {
		err = os.Remove(f)
		if err != nil {
			return nil, fmt.Errorf("cannot remove object file %s: %w", f, err)
		}
	}

	return ociIndividualOutput{
		Repository:   repo,
		Digest:       manifestDescriptor.Digest.String(),
		Size:         manifestDescriptor.Size,
		Architecture: manifest.Architecture,
	}, nil
}

func (p *rbscTarget) addObject(ctx context.Context, store *orasfile.Store, path gardenlinux.S3ReleaseFile, arch string) (
	specsv1.Descriptor, string, error,
) {
	properties, err := p.source.GetObjectProperties(ctx, path.S3Key)
	if err != nil {
		return specsv1.Descriptor{}, "", fmt.Errorf("cannot get object properties: %w", err)
	}

	var f string
	f, err = getObjectFile(ctx, p.source, path.S3Key)
	if err != nil {
		return specsv1.Descriptor{}, "", fmt.Errorf("cannot download object: %w", err)
	}

	var descriptor specsv1.Descriptor
	descriptor, err = store.Add(ctx, path.Name, properties.ContentType, f)
	if err != nil {
		return specsv1.Descriptor{}, f, fmt.Errorf("cannot add object to local store: %w", err)
	}
	descriptor.Annotations["io.gardenlinux.image.layer.architecture"] = arch

	return descriptor, f, nil
}

func (*rbscTarget) ImageAccess(_ context.Context, manifest *gardenlinux.Manifest) (access.Spec, error) {
	output, err := individualPublishingOutputFromManifest[ociIndividualOutput](manifest)
	if err != nil {
		return nil, err
	}

	return access.OCI(output.Repository + "@" + output.Digest), nil
}

func (p *rbscTarget) RootfsAccess(ctx context.Context, manifest *gardenlinux.Manifest) (access.Spec, error) {
	return objectAccess(ctx, p.source, manifest, ".tar")
}

func (p *rbscTarget) Fuse(ctx context.Context, manifests []*gardenlinux.Manifest) (PublishingOutput, error) {
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
			Annotations: map[string]string{
				"base_name":    fmt.Sprintf("%s-%s-%.8s", manifest.Flavor, manifest.Version, manifest.BuildCommittish),
				"architecture": arch,
				"features":     strings.Join(manifest.Modifiers, ","),
			},
			Platform: &specsv1.Platform{
				Architecture: arch,
				OS:           "gardenlinux",
				OSVersion:    manifest.Version,
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

func (p *rbscTarget) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "rbsc"
}
