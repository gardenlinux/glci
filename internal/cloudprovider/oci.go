package cloudprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/graph"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

func (p *ociTarget) Type() string {
	return p.typeName
}

type ociTarget struct {
	noReplicationsTarget

	base     *module.Base
	self     module.Configurable
	typeName string

	credsSource credsprovider.CredsSource
	source      ArtifactSource

	pubCfg ociPublishingConfig

	environments map[ociRegistryConfig]*ociEnvironment
	repositories map[string]*ociRepository
}

type ociRegistryConfig struct {
	registry string
	config   string
}

type ociEnvironment struct {
	registryCredential ociRegistryCredential
	credsGen           atomic.Int64
	retrier            guard.Retrier
	client             *ociClient
}

type ociClient struct {
	registryClient remote.Client
	ghcrClient     *http.Client
	retrier        guard.Retrier

	ghcrCachesMtx     sync.Mutex
	ghcrVersionCaches map[string]*ghcrVersionCache
}

type ghcrVersionCache struct {
	versionsMtx  sync.Mutex
	ownerSegment string
	versionIDs   map[string]int64
}

type ociRepository struct {
	environment *ociEnvironment
	repository  *remote.Repository
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
		if environment.client == nil {
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

type ociCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ociGCPCredentials struct {
	Token string `mapstructure:"token"`
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

func (p *ociTarget) applyCredentials(_ context.Context, registryConfig ociRegistryConfig, rawCreds map[string]any) error {
	creds, err := parseOCICredentials(ociCredsType(registryConfig.registry), rawCreds)
	if err != nil {
		return err
	}

	environment := p.environments[registryConfig]
	environment.registryCredential.credentials.Store(&creds)
	environment.credsGen.Add(1)

	if environment.client != nil {
		return nil
	}

	var client *ociClient
	client, err = newOCIClient(&environment.registryCredential, environment.retrier)
	if err != nil {
		return fmt.Errorf("cannot create OCI client: %w", err)
	}
	environment.client = client

	return nil
}

func ociCredsType(registry string) string {
	switch registry {
	case "europe-docker.pkg.dev":
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

func (p *ociTarget) repository(ref string) *ociRepository {
	return p.repositories[ref]
}

func (p *ociTarget) repositoryRef(group string) (string, error) {
	repoCfg, ok := p.pubCfg.Repositories[group]
	if !ok {
		return "", fmt.Errorf("missing repository for group %s", group)
	}

	return repoCfg.Repository, nil
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

func (p *ociTarget) ValidateFlavors(manifests []*gardenlinux.Manifest) error {
	for _, manifest := range manifests {
		if manifest.PublishingGroup == "" {
			return fmt.Errorf("flavor %s has no publishing group", manifest.Flavor)
		}

		_, err := p.repositoryRef(manifest.PublishingGroup)
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

func (p *ociTarget) CanReverse(manifest *gardenlinux.Manifest) bool {
	repoCfg, ok := p.pubCfg.Repositories[manifest.PublishingGroup]
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

func (p *ociTarget) FlavorsDestination(manifests []*gardenlinux.Manifest) (string, error) {
	var destination string
	for _, manifest := range manifests {
		ref, err := p.repositoryRef(manifest.PublishingGroup)
		if err != nil {
			return "", err
		}

		if destination != "" && ref != destination {
			return "", fmt.Errorf("flavors route to different repositories %s and %s", destination, ref)
		}
		destination = ref
	}
	if destination == "" {
		return "", errors.New("missing flavors")
	}

	return destination, nil
}

func (p *ociTarget) Unfuse(ctx context.Context, manifests []*gardenlinux.Manifest, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	output, err := publishingOutput[ociPublishingOutput](manifests[0].PublishedImageMetadata)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if output.Tag == "" {
		return errors.New("missing tag")
	}

	repository := p.repository(output.Repository)
	if repository == nil {
		return fmt.Errorf("repository %s not configured", output.Repository)
	}
	ctx = log.WithValues(ctx, "repository", output.Repository, "tag", output.Tag)

	err = repository.deleteTag(ctx, output.Tag, steamroll)
	if err != nil {
		return fmt.Errorf("cannot delete tag %s: %w", output.Tag, err)
	}

	return nil
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

		repository := p.repository(state.Repository)
		if repository == nil {
			return fmt.Errorf("repository %s not configured", state.Repository)
		}

		lctx := log.WithValues(ctx, "repository", state.Repository, "tag", state.Tag)
		err = repository.deleteTag(lctx, state.Tag, true)
		if err != nil {
			return fmt.Errorf("cannot delete tag %s: %w", state.Tag, err)
		}
	}

	return nil
}

func (r *ociRepository) deleteTag(ctx context.Context, tag string, steamroll bool) error {
	log.Debug(ctx, "Resolving tag")
	var descriptor specsv1.Descriptor
	err := r.environment.retrier.Do(ctx, "resolve tag", func(ctx context.Context) error {
		var inErr error
		descriptor, inErr = r.repository.Resolve(ctx, tag)
		if inErr != nil {
			return fmt.Errorf("cannot resolve tag: %w", inErr)
		}

		return nil
	})
	if err != nil {
		if steamroll && errors.Is(err, errdef.ErrNotFound) {
			log.Debug(ctx, "Tag not found but the steamroller keeps going")
			return nil
		}

		return err
	}

	log.Info(ctx, "Deleting image index")
	return r.environment.client.deleteIndex(ctx, r.repository, descriptor, steamroll)
}

func (c *ociClient) deleteIndex(ctx context.Context, repository *remote.Repository, descriptor specsv1.Descriptor, steamroll bool) error {
	if c.ghcrClient != nil {
		return c.deleteGHCRVersionTree(ctx, repository, descriptor, steamroll)
	}

	err := c.retrier.Do(ctx, "delete manifest", func(ctx context.Context) error {
		inErr := repository.Manifests().Delete(ctx, descriptor)
		if inErr != nil {
			return fmt.Errorf("cannot delete image index %s: %w", descriptor.Digest, inErr)
		}

		return nil
	})
	if err != nil {
		if steamroll && errors.Is(err, errdef.ErrNotFound) {
			log.Debug(ctx, "Image index not found but the steamroller keeps going")
			return nil
		}

		return err
	}

	return nil
}

func (c *ociClient) deleteGHCRVersionTree(ctx context.Context, repository *remote.Repository, descriptor specsv1.Descriptor, steamroll bool,
) error {
	owner, pkg, ok := strings.Cut(repository.Reference.Repository, "/")
	if !ok {
		return fmt.Errorf("invalid ghcr repository %q: expected owner/package", repository.Reference.Repository)
	}

	return graph.WalkTree(descriptor, func(d specsv1.Descriptor) ([]specsv1.Descriptor, error) {
		if d.MediaType != specsv1.MediaTypeImageIndex {
			return nil, nil
		}

		log.Debug(ctx, "Fetching image index", "digest", d.Digest)
		var rawIndex []byte
		inErr := c.retrier.Do(ctx, "fetch image index", func(ctx context.Context) error {
			reader, inInErr := repository.Fetch(ctx, d)
			if inInErr != nil {
				return fmt.Errorf("cannot fetch image index: %w", inInErr)
			}
			defer func() {
				_ = reader.Close()
			}()

			rawIndex, inInErr = content.ReadAll(reader, d)
			if inInErr != nil {
				return fmt.Errorf("cannot read image index: %w", inInErr)
			}

			inInErr = reader.Close()
			if inInErr != nil {
				return fmt.Errorf("cannot close image index: %w", inInErr)
			}

			return nil
		})
		if inErr != nil {
			return nil, inErr
		}

		var index specsv1.Index
		inErr = json.Unmarshal(rawIndex, &index)
		if inErr != nil {
			return nil, fmt.Errorf("cannot decode image index: %w", inErr)
		}

		return index.Manifests, nil
	}, graph.PostOrder, func(d specsv1.Descriptor, _ int) error {
		var id int64
		var segment string
		var inErr error
		id, segment, ok, inErr = c.findGHCRVersionID(ctx, owner, pkg, d.Digest.String())
		if inErr != nil {
			return fmt.Errorf("cannot find version %s: %w", d.Digest, inErr)
		}

		if !ok {
			if steamroll {
				log.Debug(ctx, "Version not found but the steamroller keeps going", "digest", d.Digest)
				return nil
			}

			return fmt.Errorf("version %s not found", d.Digest)
		}

		log.Debug(ctx, "Deleting package version", "digest", d.Digest)
		inErr = c.deleteGHCRVersion(ctx, segment, owner, pkg, id)
		if inErr != nil {
			return fmt.Errorf("cannot delete version %s: %w", d.Digest, inErr)
		}

		return nil
	})
}

func (c *ociClient) findGHCRVersionID(ctx context.Context, owner, pkg, digest string) (int64, string, bool, error) {
	var cache *ghcrVersionCache
	func() {
		c.ghcrCachesMtx.Lock()
		defer c.ghcrCachesMtx.Unlock()

		repository := owner + "/" + pkg
		var ok bool
		cache, ok = c.ghcrVersionCaches[repository]
		if !ok {
			cache = &ghcrVersionCache{}
			c.ghcrVersionCaches[repository] = cache
		}
	}()

	cache.versionsMtx.Lock()
	defer cache.versionsMtx.Unlock()

	if cache.versionIDs == nil {
		segment, err := c.resolveGHCROwnerSegment(ctx, owner)
		if err != nil {
			return 0, "", false, err
		}

		var versionIDs map[string]int64
		versionIDs, err = c.listGHCRVersionIDs(ctx, segment, owner, pkg)
		if err != nil {
			return 0, "", false, err
		}

		cache.ownerSegment = segment
		cache.versionIDs = versionIDs
	}

	id, ok := cache.versionIDs[digest]

	return id, cache.ownerSegment, ok, nil
}

func (c *ociClient) resolveGHCROwnerSegment(ctx context.Context, owner string) (string, error) {
	log.Debug(ctx, "Resolving package owner type")
	var ownerType string
	err := c.retrier.Do(ctx, "get owner", func(ctx context.Context) error {
		req, inErr := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/users/"+url.PathEscape(owner), nil)
		if inErr != nil {
			return fmt.Errorf("cannot create request: %w", inErr)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-Github-Api-Version", "2026-03-10")

		var resp *http.Response
		resp, inErr = c.ghcrClient.Do(req)
		if inErr != nil {
			return fmt.Errorf("cannot get owner: %w", inErr)
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusOK {
			var message []byte
			message, inErr = io.ReadAll(resp.Body)
			if inErr != nil {
				return fmt.Errorf("unexpected status %q", resp.Status)
			}

			return fmt.Errorf("unexpected status %q: %q", resp.Status, strings.TrimSpace(string(message)))
		}

		var account struct {
			Type string `json:"type"`
		}
		inErr = json.NewDecoder(resp.Body).Decode(&account)
		if inErr != nil {
			return fmt.Errorf("cannot decode owner: %w", inErr)
		}

		inErr = resp.Body.Close()
		if inErr != nil {
			return fmt.Errorf("cannot close response body: %w", inErr)
		}

		ownerType = account.Type

		return nil
	})
	if err != nil {
		return "", err
	}

	switch ownerType {
	case "Organization":
		return "orgs", nil

	case "User":
		return "users", nil

	default:
		return "", errors.New("invalid owner type")
	}
}

func (c *ociClient) listGHCRVersionIDs(ctx context.Context, segment, owner, pkg string) (map[string]int64, error) {
	type ghcrVersion struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}

	log.Debug(ctx, "Listing package versions")
	versionsURL := fmt.Sprintf("https://api.github.com/%s/%s/packages/container/%s/versions?per_page=100", segment, url.PathEscape(owner),
		url.PathEscape(pkg))
	versionIDs := make(map[string]int64)
	page := 1
	for {
		var versions []ghcrVersion
		err := c.retrier.Do(ctx, "list package versions", func(ctx context.Context) error {
			req, inErr := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s&page=%d", versionsURL, page), nil)
			if inErr != nil {
				return fmt.Errorf("cannot create request: %w", inErr)
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-Github-Api-Version", "2026-03-10")

			var resp *http.Response
			resp, inErr = c.ghcrClient.Do(req)
			if inErr != nil {
				return fmt.Errorf("cannot list package versions: %w", inErr)
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != http.StatusOK {
				var message []byte
				message, inErr = io.ReadAll(resp.Body)
				if inErr != nil {
					return fmt.Errorf("unexpected status %q", resp.Status)
				}

				return fmt.Errorf("unexpected status %q: %q", resp.Status, strings.TrimSpace(string(message)))
			}

			inErr = json.NewDecoder(resp.Body).Decode(&versions)
			if inErr != nil {
				return fmt.Errorf("cannot decode package versions: %w", inErr)
			}

			inErr = resp.Body.Close()
			if inErr != nil {
				return fmt.Errorf("cannot close response body: %w", inErr)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}

		for _, version := range versions {
			versionIDs[version.Name] = version.ID
		}

		if len(versions) < 100 {
			break
		}
		page++
	}

	return versionIDs, nil
}

func (c *ociClient) deleteGHCRVersion(ctx context.Context, segment, owner, pkg string, id int64) error {
	return c.retrier.Do(ctx, "delete package version", func(ctx context.Context) error {
		req, inErr := http.NewRequestWithContext(ctx, http.MethodDelete,
			fmt.Sprintf("https://api.github.com/%s/%s/packages/container/%s/versions/%d", segment, url.PathEscape(owner),
				url.PathEscape(pkg), id), nil)
		if inErr != nil {
			return fmt.Errorf("cannot create request: %w", inErr)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-Github-Api-Version", "2026-03-10")

		var resp *http.Response
		resp, inErr = c.ghcrClient.Do(req)
		if inErr != nil {
			return fmt.Errorf("cannot delete package version: %w", inErr)
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusNoContent {
			var message []byte
			message, inErr = io.ReadAll(resp.Body)
			if inErr != nil {
				return fmt.Errorf("unexpected status %q", resp.Status)
			}

			return fmt.Errorf("unexpected status %q: %q", resp.Status, strings.TrimSpace(string(message)))
		}

		inErr = resp.Body.Close()
		if inErr != nil {
			return fmt.Errorf("cannot close response body: %w", inErr)
		}

		return nil
	})
}

func (r *ociRepository) copyGraph(ctx context.Context, source content.ReadOnlyStorage, descriptor specsv1.Descriptor) error {
	return r.environment.retrier.Do(ctx, "copy graph", func(ctx context.Context) error {
		inErr := oras.CopyGraph(ctx, source, r.repository, descriptor, oras.DefaultCopyGraphOptions)
		if inErr != nil {
			return fmt.Errorf("cannot copy OCI artifact: %w", inErr)
		}

		return nil
	})
}

func (r *ociRepository) tag(ctx context.Context, descriptor specsv1.Descriptor, tag string) error {
	return r.environment.retrier.Do(ctx, "tag", func(ctx context.Context) error {
		inErr := r.repository.Tag(ctx, descriptor, tag)
		if inErr != nil {
			return fmt.Errorf("cannot tag OCI artifact: %w", inErr)
		}

		return nil
	})
}

func (r *ociRepository) pushReference(ctx context.Context, descriptor specsv1.Descriptor, reader io.Reader, tag string) error {
	return r.environment.retrier.Do(ctx, "push reference", func(ctx context.Context) error {
		inErr := r.repository.PushReference(ctx, descriptor, reader, tag)
		if inErr != nil {
			return fmt.Errorf("cannot push image index: %w", inErr)
		}

		return nil
	})
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

	p.environments = make(map[ociRegistryConfig]*ociEnvironment)
	p.repositories = make(map[string]*ociRepository)
	seen := make(map[string]struct{}, len(p.pubCfg.Repositories))
	for group, repoCfg := range p.pubCfg.Repositories {
		switch {
		case repoCfg.Repository == "":
			return fmt.Errorf("missing repository for %s", group)
		case repoCfg.Config == "":
			return fmt.Errorf("missing config for %s", group)
		}

		_, ok := seen[repoCfg.Repository]
		if ok {
			return fmt.Errorf("repository %s configured for multiple groups", repoCfg.Repository)
		}
		seen[repoCfg.Repository] = struct{}{}

		var repository *remote.Repository
		repository, err = remote.NewRepository(repoCfg.Repository)
		if err != nil {
			return fmt.Errorf("invalid OCI repository %s: %w", repoCfg.Repository, err)
		}

		registryConfig := ociRegistryConfig{
			registry: repository.Reference.Registry,
			config:   repoCfg.Config,
		}

		var environment *ociEnvironment
		environment, ok = p.environments[registryConfig]
		if !ok {
			environment = &ociEnvironment{}
			environment.registryCredential.registry = registryConfig.registry
			environment.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() int {
				return int(environment.credsGen.Load())
			}), guard.DelegatingTimeoutPolicy{})

			p.environments[registryConfig] = environment
		}

		p.repositories[repoCfg.Repository] = &ociRepository{
			environment: environment,
			repository:  repository,
		}
	}

	err = p.base.RegisterTypeRef[credsprovider.CredsSource](p.self, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	err = p.base.RegisterRef[ArtifactSource](p.self, &p.source, p.pubCfg.Source)
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
	for registryConfig := range p.environments {
		acquireCreds.Go(func(ctx context.Context) error {
			err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
				Type:      "OCI_" + ociCredsType(registryConfig.registry),
				Config:    registryConfig.config,
				Qualifier: registryConfig.registry,
				Role:      "target",
			}, func(ctx context.Context, creds map[string]any) error {
				return p.applyCredentials(ctx, registryConfig, creds)
			})
			if err != nil {
				return fmt.Errorf("cannot acquire credentials for config %s: %w", registryConfig.config, err)
			}

			return nil
		})
	}
	err := acquireCreds.Wait()
	if err != nil {
		return err
	}

	for _, repository := range p.repositories {
		repository.repository.Client = repository.environment.client.registryClient
	}

	return nil
}

func (p *ociTarget) Stop(ctx context.Context) error {
	for registryConfig := range p.environments {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:      "OCI_" + ociCredsType(registryConfig.registry),
			Config:    registryConfig.config,
			Qualifier: registryConfig.registry,
			Role:      "target",
		})
	}

	return nil
}

func newOCIClient(registryCredential *ociRegistryCredential, retrier guard.Retrier) (*ociClient, error) {
	transport, err := newRetryTransport()
	if err != nil {
		return nil, err
	}

	client := &ociClient{
		registryClient: &auth.Client{
			Client: &http.Client{
				Transport: transport,
			},
			Cache:      auth.NewCache(),
			Credential: registryCredential.credential,
		},
		retrier: retrier,
	}

	switch registryCredential.registry {
	case "ghcr.io":
		client.ghcrClient, err = newGHCRClient(registryCredential)
		if err != nil {
			return nil, fmt.Errorf("cannot create GHCR client: %w", err)
		}

		client.ghcrVersionCaches = make(map[string]*ghcrVersionCache)

	default:
	}

	return client, nil
}

func newOCIRepository(ref string, environment *ociEnvironment) (*ociRepository, error) {
	repository, err := remote.NewRepository(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid OCI repository %s: %w", ref, err)
	}

	repository.Client = environment.client.registryClient

	return &ociRepository{
		environment: environment,
		repository:  repository,
	}, nil
}

type ghcrTransport struct {
	registryCredential *ociRegistryCredential
	transport          http.RoundTripper
}

func (t *ghcrTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	creds := t.registryCredential.credentials.Load()
	if creds == nil {
		return nil, errors.New("credentials not set")
	}

	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+creds.Password)

	return t.transport.RoundTrip(req)
}

func newGHCRClient(registryCredential *ociRegistryCredential) (*http.Client, error) {
	transport, err := newRetryTransport()
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &ghcrTransport{
			registryCredential: registryCredential,
			transport:          transport,
		},
	}, nil
}

func newRetryTransport() (*retry.Transport, error) {
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

	return transport, nil
}
