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
	"sync"
	"sync/atomic"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"
	orasoci "oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

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
		p := &ociTarget{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})

	module.RegisterImpl(OCMTargetCategory, "OCI", func(b *module.Base) OCMTarget {
		p := &ociOCMTarget{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})
}

func (*ociTarget) Type() string {
	return "OCI"
}

type ociTarget struct {
	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource

	pubCfg    ociPublishingConfig
	credsType string
	retrier   guard.Retrier

	clientsMtx sync.RWMutex
	clients    ociTargetClients
	clientsGen atomic.Uint64
}

type ociTargetClients struct {
	repository *remote.Repository
}

type ociPublishingConfig struct {
	Source       string `mapstructure:"source"`
	Config       string `mapstructure:"config"`
	Repository   string `mapstructure:"repository"`
	AllowsDelete bool   `mapstructure:"allows_delete,omitzero"`
}

func (p *ociTarget) isConfigured() bool {
	return p.repository() != nil
}

type ociOperationState struct {
	Tag string `json:"tag,omitzero"`
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

func (p *ociTarget) createClients(_ context.Context, rawCreds map[string]any) error {
	creds, err := parseOCICredentials(p.credsType, rawCreds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	var repository *remote.Repository
	repository, err = newOCIRepository(p.pubCfg.Repository, creds)
	if err != nil {
		return err
	}
	p.clients.repository = repository
	p.clientsGen.Add(1)

	return nil
}

func (p *ociTarget) getClients() ociTargetClients {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.clients
}

func (p *ociTarget) repository() *remote.Repository {
	return p.getClients().repository
}

func (*ociTarget) ImageSuffix() string {
	return ".oci"
}

func (p *ociTarget) CanPublish(manifest *gardenlinux.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return manifest.Platform == "container"
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

	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	ctx = log.WithValues(ctx, "key", imagePath.S3Key, "repository", p.pubCfg.Repository)

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
	err = p.retrier.Do(ctx, "copy graph", func(ctx context.Context) error {
		return oras.CopyGraph(ctx, store, p.repository(), descriptor, oras.DefaultCopyGraphOptions)
	})
	if err != nil {
		return nil, fmt.Errorf("cannot copy OCI artifact: %w", err)
	}

	err = os.Remove(archive)
	if err != nil {
		return nil, fmt.Errorf("cannot remove OCI archive: %w", err)
	}

	return ociIndividualOutput{
		Repository:   p.pubCfg.Repository,
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

func (p *ociTarget) CanUnpublish() bool {
	return p.pubCfg.AllowsDelete
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

	descriptors := make([]specsv1.Descriptor, 0, len(flavorManifests))
	for _, flavorManifest := range flavorManifests {
		output, err := individualPublishingOutputFromManifest[ociIndividualOutput](flavorManifest.Manifest)
		if err != nil {
			return nil, fmt.Errorf("invalid manifest %s: %w", flavorManifest.Flavor, err)
		}

		if output.Repository != p.pubCfg.Repository {
			return nil, fmt.Errorf("artifact repository %s does not match target repository %s", output.Repository, p.pubCfg.Repository)
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
	ctx = log.WithValues(ctx, "repository", p.pubCfg.Repository, "tag", flavorManifests[0].Manifest.Version)

	index := specsv1.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: specsv1.MediaTypeImageIndex,
		Manifests: descriptors,
	}

	rawIndex, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("cannot encode image index: %w", err)
	}

	descriptor := specsv1.Descriptor{
		MediaType: specsv1.MediaTypeImageIndex,
		Digest:    digest.FromBytes(rawIndex),
		Size:      int64(len(rawIndex)),
	}

	ctx = resilience.BeginOperation(ctx, "fuse/"+flavorManifests[0].Manifest.Version, &ociOperationState{})

	log.Info(ctx, "Fusing OCI artifacts", "digest", descriptor.Digest)
	err = p.retrier.Do(ctx, "push reference", func(ctx context.Context) error {
		return p.repository().PushReference(ctx, descriptor, bytes.NewReader(rawIndex), flavorManifests[0].Manifest.Version)
	})
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot push image index: %w", err))
	}
	resilience.UpdateOperation(ctx, func(s *ociOperationState) *ociOperationState {
		s.Tag = flavorManifests[0].Manifest.Version
		return s
	})
	resilience.CompleteOperation(ctx)

	return ociPublishingOutput{
		Repository: p.pubCfg.Repository,
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
	ctx = log.WithValues(ctx, "repository", p.pubCfg.Repository, "tag", output.Tag)

	err = p.deleteTag(ctx, output.Tag, steamroll)
	if err != nil {
		return fmt.Errorf("cannot delete tag %s: %w", output.Tag, err)
	}

	return nil
}

func (p *ociTarget) deleteTag(ctx context.Context, tag string, steamroll bool) error {
	var descriptor specsv1.Descriptor
	err := p.retrier.Do(ctx, "resolve tag", func(ctx context.Context) error {
		var inErr error
		descriptor, inErr = p.repository().Resolve(ctx, tag)
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
	err = p.retrier.Do(ctx, "delete manifest", func(ctx context.Context) error {
		return p.repository().Manifests().Delete(ctx, descriptor)
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

		lctx := log.WithValues(ctx, "repository", p.pubCfg.Repository, "tag", state.Tag)
		err = p.deleteTag(lctx, state.Tag, true)
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
	case p.pubCfg.Config == "":
		return errors.New("missing config")
	case p.pubCfg.Repository == "":
		return errors.New("missing repository")
	}

	p.credsType = ociCredsType(p.pubCfg.Repository)

	err = module.RegisterTypeRef[credsprovider.CredsSource](p.base, p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	err = module.RegisterRef[ArtifactSource](p.base, p, &p.source, p.pubCfg.Source)
	if err != nil {
		return fmt.Errorf("cannot register source: %w", err)
	}

	return nil
}

func (*ociTarget) Configurables() []module.Configurable {
	return nil
}

func (p *ociTarget) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   fmt.Sprintf("%s_%s", p.Type(), p.credsType),
		Config: p.pubCfg.Config,
		Role:   "target",
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	return nil
}

func (p *ociTarget) Stop() error {
	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(context.Background(), credsprovider.CredsID{
			Type:   fmt.Sprintf("%s_%s", p.Type(), p.credsType),
			Config: p.pubCfg.Config,
			Role:   "target",
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
	retrier   guard.Retrier

	clientsMtx sync.RWMutex
	clients    ociOCMTargetClients
	clientsGen atomic.Uint64
}

type ociOCMTargetClients struct {
	repository *remote.Repository
}

type ociOCMConfig struct {
	Config     string `mapstructure:"config"`
	Repository string `mapstructure:"repository"`
}

func (p *ociOCMTarget) isConfigured() bool {
	return p.repository() != nil
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

func newOCIRepository(repo string, creds ociCredentials) (*remote.Repository, error) {
	repository, err := remote.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI repository %s: %w", repo, err)
	}

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
		Cache: auth.NewCache(),
		Credential: auth.StaticCredential(repository.Reference.Registry, auth.Credential{
			Username: creds.Username,
			Password: creds.Password,
		}),
	}

	return repository, nil
}

func (p *ociOCMTarget) createClients(_ context.Context, rawCreds map[string]any) error {
	creds, err := parseOCICredentials(p.credsType, rawCreds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	var repository *remote.Repository
	repository, err = newOCIRepository(p.ocmCfg.Repository+repoSuffix, creds)
	if err != nil {
		return err
	}
	p.clients.repository = repository
	p.clientsGen.Add(1)

	return nil
}

func (p *ociOCMTarget) getClients() ociOCMTargetClients {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.clients
}

func (p *ociOCMTarget) repository() *remote.Repository {
	return p.getClients().repository
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
	err = p.retrier.Do(ctx, "copy tag", func(ctx context.Context) error {
		_, inErr := oras.Copy(ctx, store, version, p.repository(), version, oras.DefaultCopyOptions)
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

	err = module.RegisterTypeRef[credsprovider.CredsSource](p.base, p, &p.credsSource)
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
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.ocmCfg.Config, err)
	}

	return nil
}

func (p *ociOCMTarget) Stop() error {
	if p.ocmCfg.Config != "" {
		p.credsSource.ReleaseCreds(context.Background(), credsprovider.CredsID{
			Type:   fmt.Sprintf("%s_%s", p.Type(), p.credsType),
			Config: p.ocmCfg.Config,
			Role:   "oci",
		})
	}

	return nil
}
