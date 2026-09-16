package cloudprovider

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/opencontainers/go-digest"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

const (
	repoSuffix = "/component-descriptors/" + gardenlinux.GardenLinuxRepo
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(PublishingTargetCategory, "OCI", func(b *module.Base) PublishingTarget {
		return &ociTarget{
			base: b,
		}
	})

	module.RegisterImpl(OCMTargetCategory, "OCI", func(b *module.Base) OCMTarget {
		p := &ociOCMTarget{
			base: b,
		}
		p.world.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() int {
			return int(p.world.credsGen.Load())
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})
}

func (*ociTarget) Type() string {
	return "OCI"
}

type ociTarget struct {
	noReplicationsTarget

	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource

	pubCfg ociPublishingConfig

	environments map[string]*ociEnvironment
}

type ociEnvironment struct {
	registryCredential ociRegistryCredential
	credsGen           atomic.Int64
	retrier            guard.Retrier
	repository         *remote.Repository
}

type ociRegistryCredential struct {
	credentials atomic.Pointer[ociCredentials]
	registry    string
}

func (c *ociRegistryCredential) credential(_ context.Context, hostport string) (auth.Credential, error) {
	if hostport != c.registry {
		return auth.EmptyCredential, nil
	}

	creds := c.credentials.Load()
	if creds == nil {
		return auth.EmptyCredential, errors.New("credentials not set")
	}

	return auth.Credential{
		Username: creds.Username,
		Password: creds.Password,
	}, nil
}

type ociPublishingConfig struct {
	Source       string                         `mapstructure:"source"`
	Repositories map[string]ociRepositoryConfig `mapstructure:"repositories"`
}

type ociRepositoryConfig struct {
	Repository   string `mapstructure:"repository"`
	Config       string `mapstructure:"config"`
	AllowsDelete bool   `mapstructure:"allows_delete,omitzero"`
}

func (p *ociTarget) isConfigured() bool {
	if len(p.environments) == 0 {
		return false
	}

	for _, environment := range p.environments {
		if environment.repository == nil {
			return false
		}
	}

	return true
}

type ociOperationState struct {
	Repository string `json:"repository,omitzero"`
	Tag        string `json:"tag,omitzero"`
}

type ociPublishingOutput struct {
	Repository string `yaml:"repository,omitzero"`
	Tag        string `yaml:"tag,omitzero"`
	Digest     string `yaml:"digest,omitzero"`
}

type ociIndividualOutput struct {
	Repository   string
	Digest       string
	Size         int64
	Architecture gardenlinux.Architecture
}

func (p *ociTarget) applyCredentials(_ context.Context, repo string, rawCreds map[string]any) error {
	creds, err := parseOCICredentials(ociCredsType(repo), rawCreds)
	if err != nil {
		return err
	}

	environment := p.environment(repo)
	environment.registryCredential.credentials.Store(&creds)
	environment.credsGen.Add(1)

	if environment.repository != nil {
		return nil
	}

	var repository *remote.Repository
	repository, err = newOCIRepository(repo, &environment.registryCredential)
	if err != nil {
		return err
	}

	environment.repository = repository

	return nil
}

func (p *ociTarget) environment(repo string) *ociEnvironment {
	return p.environments[repo]
}

func (p *ociTarget) repository(flavor string) (string, error) {
	repoCfg, ok := p.pubCfg.Repositories[cname(flavor)]
	if !ok {
		return "", fmt.Errorf("missing repository for flavor %s", flavor)
	}

	return repoCfg.Repository, nil
}

func (*ociTarget) ImageSuffix() string {
	return ".oci"
}

func (*ociTarget) CanPublish(manifest *gardenlinux.Manifest) bool {
	return manifest.Platform == "container"
}

func (p *ociTarget) ValidateFlavors(flavors []string) error {
	for _, flavor := range flavors {
		_, err := p.repository(flavor)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *ociTarget) IsPublished(manifest *gardenlinux.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	ociOutput, err := publishingOutputFromManifest[ociPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return ociOutput.Repository != "" && ociOutput.Tag != "" && ociOutput.Digest != "", nil
}

func (p *ociTarget) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
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

func (*ociTarget) findArtifactRootDescriptor(archive string) (specsv1.Descriptor, error) {
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

func (p *ociTarget) CanReverse(flavor string) bool {
	repoCfg, ok := p.pubCfg.Repositories[cname(flavor)]
	if !ok {
		return false
	}

	return repoCfg.AllowsDelete
}

func (*ociTarget) Unpublish(context.Context, *gardenlinux.Manifest, bool) error {
	return nil
}

func (*ociTarget) CanFuse() bool {
	return true
}

func (p *ociTarget) Fuse(ctx context.Context, flavorManifests []gardenlinux.FlavorManifest) (PublishingOutput, error) {
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

func (p *ociTarget) Unfuse(ctx context.Context, flavorManifests []gardenlinux.FlavorManifest, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	output, err := publishingOutput[ociPublishingOutput](flavorManifests[0].Manifest.PublishedImageMetadata)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if output.Tag == "" {
		return errors.New("missing tag")
	}

	environment := p.environment(output.Repository)
	if environment == nil {
		return fmt.Errorf("repository %s not configured", output.Repository)
	}
	ctx = log.WithValues(ctx, "repository", output.Repository, "tag", output.Tag)

	err = p.deleteTag(ctx, environment, output.Tag, steamroll)
	if err != nil {
		return fmt.Errorf("cannot delete tag %s: %w", output.Tag, err)
	}

	return nil
}

func (*ociTarget) deleteTag(ctx context.Context, environment *ociEnvironment, tag string, steamroll bool) error {
	var descriptor specsv1.Descriptor
	err := environment.retrier.Do(ctx, "resolve tag", func(ctx context.Context) error {
		var inErr error
		descriptor, inErr = environment.repository.Resolve(ctx, tag)
		return inErr
	})
	if err != nil {
		if steamroll && errors.Is(err, errdef.ErrNotFound) {
			log.Debug(ctx, "Tag not found but the steamroller keeps going")
			return nil
		}

		return fmt.Errorf("cannot resolve tag: %w", err)
	}

	log.Info(ctx, "Deleting image index", "digest", descriptor.Digest)
	err = environment.retrier.Do(ctx, "delete manifest", func(ctx context.Context) error {
		return environment.repository.Manifests().Delete(ctx, descriptor)
	})
	if err != nil {
		if steamroll && errors.Is(err, errdef.ErrNotFound) {
			log.Debug(ctx, "Image index not found but the steamroller keeps going")
			return nil
		}

		return fmt.Errorf("cannot delete image index %s: %w", descriptor.Digest, err)
	}

	return nil
}

func (*ociTarget) architecture(arch gardenlinux.Architecture) (string, error) {
	switch arch {
	case gardenlinux.ArchitectureAMD64:
		return "amd64", nil

	case gardenlinux.ArchitectureARM64:
		return "arm64", nil

	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (p *ociTarget) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "oci"
}

func (p *ociTarget) Rollback(ctx context.Context, operations map[string]resilience.Operation) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	for _, op := range operations {
		state, err := resilience.ParseOperationState[*ociOperationState](op.State)
		if err != nil {
			return err
		}

		if state.Tag == "" {
			continue
		}

		environment := p.environment(state.Repository)
		if environment == nil {
			return fmt.Errorf("repository %s not configured", state.Repository)
		}

		lctx := log.WithValues(ctx, "repository", state.Repository, "tag", state.Tag)
		err = p.deleteTag(lctx, environment, state.Tag, true)
		if err != nil {
			return fmt.Errorf("cannot delete tag %s: %w", state.Tag, err)
		}
	}

	return nil
}

func (p *ociTarget) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.pubCfg)
	if err != nil {
		return err
	}

	switch {
	case p.pubCfg.Source == "":
		return errors.New("missing source")
	case len(p.pubCfg.Repositories) == 0:
		return errors.New("missing repositories")
	}

	p.environments = make(map[string]*ociEnvironment, len(p.pubCfg.Repositories))
	for flavor, repoCfg := range p.pubCfg.Repositories {
		switch {
		case repoCfg.Repository == "":
			return fmt.Errorf("missing repository for %s", flavor)
		case repoCfg.Config == "":
			return fmt.Errorf("missing config for %s", flavor)
		}

		_, ok := p.environments[repoCfg.Repository]
		if ok {
			return fmt.Errorf("repository %s configured for multiple flavors", repoCfg.Repository)
		}

		environment := &ociEnvironment{}
		environment.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() int {
			return int(environment.credsGen.Load())
		}), guard.DelegatingTimeoutPolicy{})

		p.environments[repoCfg.Repository] = environment
	}

	err = p.base.RegisterTypeRef[credsprovider.CredsSource](p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	err = p.base.RegisterRef[ArtifactSource](p, &p.source, p.pubCfg.Source)
	if err != nil {
		return fmt.Errorf("cannot register source: %w", err)
	}

	return nil
}

func (*ociTarget) Configurables() []module.Configurable {
	return nil
}

func (p *ociTarget) Start(ctx context.Context) error {
	acquireCreds := concurrency.NewActivity(ctx)
	for _, repoCfg := range p.pubCfg.Repositories {
		acquireCreds.Go(func(ctx context.Context) error {
			err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
				Type:      fmt.Sprintf("%s_%s", p.Type(), ociCredsType(repoCfg.Repository)),
				Config:    repoCfg.Config,
				Qualifier: repoCfg.Repository,
				Role:      "target",
			}, func(ctx context.Context, creds map[string]any) error {
				return p.applyCredentials(ctx, repoCfg.Repository, creds)
			})
			if err != nil {
				return fmt.Errorf("cannot acquire credentials for config %s: %w", repoCfg.Config, err)
			}

			return nil
		})
	}
	return acquireCreds.Wait()
}

func (p *ociTarget) Stop(ctx context.Context) error {
	for _, repoCfg := range p.pubCfg.Repositories {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:      fmt.Sprintf("%s_%s", p.Type(), ociCredsType(repoCfg.Repository)),
			Config:    repoCfg.Config,
			Qualifier: repoCfg.Repository,
			Role:      "target",
		})
	}

	return nil
}

func (*ociOCMTarget) Type() string {
	return "OCI"
}

type ociOCMTarget struct {
	base *module.Base

	credsSource credsprovider.CredsSource

	ocmCfg    ociOCMConfig
	credsType string

	world ociEnvironment
}

type ociOCMConfig struct {
	Config     string `mapstructure:"config"`
	Repository string `mapstructure:"repository"`
}

func (p *ociOCMTarget) isConfigured() bool {
	return p.environment().repository != nil
}

type ociCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ociGCPCredentials struct {
	Token string `mapstructure:"token"`
}

func ociCredsType(repository string) string {
	switch {
	case strings.HasPrefix(repository, "europe-docker.pkg.dev/"):
		return "GCP"

	default:
		return "userpass"
	}
}

func parseOCICredentials(credsType string, rawCreds map[string]any) (ociCredentials, error) {
	var creds ociCredentials
	switch credsType {
	case "GCP":
		var gcpCreds ociGCPCredentials
		err := parseCredentials(rawCreds, &gcpCreds)
		if err != nil {
			return ociCredentials{}, err
		}

		creds.Username = "oauth2accesstoken"
		creds.Password = gcpCreds.Token

	case "userpass":
		err := parseCredentials(rawCreds, &creds)
		if err != nil {
			return ociCredentials{}, err
		}

	default:
		return ociCredentials{}, fmt.Errorf("unknown credentials type %s", credsType)
	}

	return creds, nil
}

func newOCIRepository(repo string, registryCredential *ociRegistryCredential) (*remote.Repository, error) {
	repository, err := remote.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI repository %s: %w", repo, err)
	}

	registryCredential.registry = repository.Reference.Registry

	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected default transport type")
	}

	t = t.Clone()
	t.ResponseHeaderTimeout = guard.Timeout
	transport := retry.NewTransport(t)
	transport.Policy = func() retry.Policy {
		return &retry.GenericPolicy{
			Retryable: retry.DefaultPredicate,
			Backoff:   retry.DefaultBackoff,
			MinWait:   guard.RetryBaseDelay,
			MaxWait:   guard.RetryMaxDelay,
			MaxRetry:  guard.Retries,
		}
	}

	repository.Client = &auth.Client{
		Client: &http.Client{
			Transport: transport,
		},
		Cache:      auth.NewCache(),
		Credential: registryCredential.credential,
	}

	return repository, nil
}

func (p *ociOCMTarget) applyCredentials(_ context.Context, rawCreds map[string]any) error {
	creds, err := parseOCICredentials(p.credsType, rawCreds)
	if err != nil {
		return err
	}

	environment := p.environment()
	environment.registryCredential.credentials.Store(&creds)
	environment.credsGen.Add(1)

	if environment.repository != nil {
		return nil
	}

	var repository *remote.Repository
	repository, err = newOCIRepository(p.ocmCfg.Repository+repoSuffix, &environment.registryCredential)
	if err != nil {
		return err
	}
	environment.repository = repository

	return nil
}

func (p *ociOCMTarget) environment() *ociEnvironment {
	return &p.world
}

func (*ociOCMTarget) OCMType() string {
	return "OCIRegistry"
}

func (p *ociOCMTarget) OCMRepositoryBase() string {
	return p.ocmCfg.Repository
}

func (p *ociOCMTarget) PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	log.Debug(ctx, "Creating tarball")
	var tarBuf bytes.Buffer
	tarball := tar.NewWriter(&tarBuf)
	defer func() {
		_ = tarball.Close()
	}()

	err := tarball.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     "component-descriptor.yaml",
		Size:     int64(len(descriptor)),
		Mode:     0o644,
		Format:   tar.FormatPAX,
	})
	if err != nil {
		return fmt.Errorf("cannot write tar header: %w", err)
	}

	_, err = tarball.Write(descriptor)
	if err != nil {
		return fmt.Errorf("cannot write tar contents: %w", err)
	}

	err = tarball.Close()
	if err != nil {
		return fmt.Errorf("cannot close tar: %w", err)
	}

	var tmpDir string
	tmpDir, err = os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	log.Debug(ctx, "Creating local OCI store", "dir", tmpDir)
	var store *orasfile.Store
	store, err = orasfile.New(tmpDir)
	if err != nil {
		return fmt.Errorf("cannot create local OCI store in %s: %w", tmpDir, err)
	}
	defer func() {
		_ = store.Close()
	}()

	tarDescriptor := specsv1.Descriptor{
		MediaType: "application/vnd.gardener.cloud.cnudie.component-descriptor.v2+yaml+tar",
		Digest:    digest.FromBytes(tarBuf.Bytes()),
		Size:      int64(tarBuf.Len()),
	}
	log.Debug(ctx, "Pushing tarball", "digest", tarDescriptor.Digest)
	err = store.Push(ctx, tarDescriptor, &tarBuf)
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest config to local OCI store: %w", err)
	}

	var rawConfig []byte
	rawConfig, err = json.Marshal(map[string]map[string]any{
		"componentDescriptorLayer": {
			"digest":    tarDescriptor.Digest.String(),
			"mediaType": tarDescriptor.MediaType,
			"size":      tarDescriptor.Size,
		},
	})
	if err != nil {
		return fmt.Errorf("invalid artifact config: %w", err)
	}

	configDescriptor := specsv1.Descriptor{
		MediaType: "application/vnd.gardener.cloud.cnudie.component.config.v1+json",
		Digest:    digest.FromBytes(rawConfig),
		Size:      int64(len(rawConfig)),
	}
	log.Debug(ctx, "Pushing config", "digest", configDescriptor.Digest)
	err = store.Push(ctx, configDescriptor, bytes.NewReader(rawConfig))
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest config to local OCI store: %w", err)
	}

	var manifestDescriptor specsv1.Descriptor
	manifestDescriptor, err = oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, tarDescriptor.MediaType, oras.PackManifestOptions{
		Layers: []specsv1.Descriptor{
			tarDescriptor,
		},
		ManifestAnnotations: map[string]string{
			specsv1.AnnotationCreated: "1970-01-01T00:00:00Z",
		},
		ConfigDescriptor: &configDescriptor,
	})
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest to local OCI store: %w", err)
	}

	log.Debug(ctx, "Tagging manifest", "size", manifestDescriptor.Size, "digest", manifestDescriptor.Digest)
	err = store.Tag(ctx, manifestDescriptor, version)
	if err != nil {
		return fmt.Errorf("cannot tag OCI manifest: %w", err)
	}

	log.Debug(ctx, "Copying artifact")
	err = p.environment().retrier.Do(ctx, "copy tag", func(ctx context.Context) error {
		_, inErr := oras.Copy(ctx, store, version, p.environment().repository, version, oras.DefaultCopyOptions)
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot upload OCI artifact: %w", err)
	}

	err = store.Close()
	if err != nil {
		return fmt.Errorf("cannot close local OCI store: %w", err)
	}

	err = os.RemoveAll(tmpDir)
	if err != nil {
		return fmt.Errorf("cannot remove temporary directory %s: %w", tmpDir, err)
	}

	return nil
}

func (p *ociOCMTarget) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.ocmCfg)
	if err != nil {
		return err
	}

	switch {
	case p.ocmCfg.Config == "":
		return errors.New("missing config")
	case p.ocmCfg.Repository == "":
		return errors.New("missing repository")
	}

	p.credsType = ociCredsType(p.ocmCfg.Repository)

	err = p.base.RegisterTypeRef[credsprovider.CredsSource](p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	return nil
}

func (*ociOCMTarget) Configurables() []module.Configurable {
	return nil
}

func (p *ociOCMTarget) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   fmt.Sprintf("%s_%s", p.Type(), p.credsType),
		Config: p.ocmCfg.Config,
		Role:   "oci",
	}, p.applyCredentials)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.ocmCfg.Config, err)
	}

	return nil
}

func (p *ociOCMTarget) Stop(ctx context.Context) error {
	if p.ocmCfg.Config != "" {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:   fmt.Sprintf("%s_%s", p.Type(), p.credsType),
			Config: p.ocmCfg.Config,
			Role:   "oci",
		})
	}

	return nil
}
