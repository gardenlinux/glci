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

	environments map[string]*ociEnvironment
}

type ociEnvironment struct {
	registryCredential ociRegistryCredential
	credsGen           atomic.Int64
	retrier            guard.Retrier
	repository         *remote.Repository
	ghcrClient         *http.Client

	ghcrVersionIDsMtx sync.Mutex
	ghcrOwnerSegment  string
	ghcrVersionIDs    map[string]int64
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

func (e *ociEnvironment) copyGraph(ctx context.Context, source content.ReadOnlyStorage, descriptor specsv1.Descriptor) error {
	return e.retrier.Do(ctx, "copy graph", func(ctx context.Context) error {
		inErr := oras.CopyGraph(ctx, source, e.repository, descriptor, oras.DefaultCopyGraphOptions)
		if inErr != nil {
			return fmt.Errorf("cannot copy OCI artifact: %w", inErr)
		}

		return nil
	})
}

func (e *ociEnvironment) tag(ctx context.Context, descriptor specsv1.Descriptor, tag string) error {
	return e.retrier.Do(ctx, "tag", func(ctx context.Context) error {
		inErr := e.repository.Tag(ctx, descriptor, tag)
		if inErr != nil {
			return fmt.Errorf("cannot tag OCI artifact: %w", inErr)
		}

		return nil
	})
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

	switch environment.registryCredential.registry {
	case "ghcr.io":
		var ghcrClient *http.Client
		ghcrClient, err = newGHCRClient(&environment.registryCredential)
		if err != nil {
			return err
		}

		environment.ghcrClient = ghcrClient

	default:
	}

	return nil
}

func (p *ociTarget) environment(repo string) *ociEnvironment {
	return p.environments[repo]
}

func (p *ociTarget) repository(group string) (string, error) {
	repoCfg, ok := p.pubCfg.Repositories[group]
	if !ok {
		return "", fmt.Errorf("missing repository for group %s", group)
	}

	return repoCfg.Repository, nil
}

func (p *ociTarget) ValidateFlavors(manifests []*gardenlinux.Manifest) error {
	for _, manifest := range manifests {
		if manifest.PublishingGroup == "" {
			return fmt.Errorf("flavor %s has no publishing group", manifest.Flavor)
		}

		_, err := p.repository(manifest.PublishingGroup)
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
		repo, err := p.repository(manifest.PublishingGroup)
		if err != nil {
			return "", err
		}

		if destination != "" && repo != destination {
			return "", fmt.Errorf("flavors route to different repositories %s and %s", destination, repo)
		}
		destination = repo
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

func (*ociTarget) deleteTag(ctx context.Context, environment *ociEnvironment, tag string, steamroll bool) error {
	log.Debug(ctx, "Resolving tag")
	var descriptor specsv1.Descriptor
	err := environment.retrier.Do(ctx, "resolve tag", func(ctx context.Context) error {
		var inErr error
		descriptor, inErr = environment.repository.Resolve(ctx, tag)
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
	switch environment.repository.Reference.Registry {
	case "ghcr.io":
		return environment.deleteGHCRVersionTree(ctx, descriptor, steamroll)

	default:
		err = environment.retrier.Do(ctx, "delete manifest", func(ctx context.Context) error {
			inErr := environment.repository.Manifests().Delete(ctx, descriptor)
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
}

func (e *ociEnvironment) deleteGHCRVersionTree(ctx context.Context, descriptor specsv1.Descriptor, steamroll bool) error {
	owner, pkg, ok := strings.Cut(e.repository.Reference.Repository, "/")
	if !ok {
		return fmt.Errorf("invalid ghcr repository %q: expected owner/package", e.repository.Reference.Repository)
	}

	return graph.WalkTree(descriptor, func(d specsv1.Descriptor) ([]specsv1.Descriptor, error) {
		if d.MediaType != specsv1.MediaTypeImageIndex {
			return nil, nil
		}

		log.Debug(ctx, "Fetching image index", "digest", d.Digest)
		var rawIndex []byte
		inErr := e.retrier.Do(ctx, "fetch image index", func(ctx context.Context) error {
			r, inInErr := e.repository.Fetch(ctx, d)
			if inInErr != nil {
				return fmt.Errorf("cannot fetch image index: %w", inInErr)
			}
			defer func() {
				_ = r.Close()
			}()

			rawIndex, inInErr = content.ReadAll(r, d)
			if inInErr != nil {
				return fmt.Errorf("cannot read image index: %w", inInErr)
			}

			inInErr = r.Close()
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
		id, segment, ok, inErr = e.findGHCRVersionID(ctx, owner, pkg, d.Digest.String())
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
		inErr = e.deleteGHCRVersion(ctx, segment, owner, pkg, id)
		if inErr != nil {
			return fmt.Errorf("cannot delete version %s: %w", d.Digest, inErr)
		}

		return nil
	})
}

func (e *ociEnvironment) findGHCRVersionID(ctx context.Context, owner, pkg, digest string) (int64, string, bool, error) {
	e.ghcrVersionIDsMtx.Lock()
	defer e.ghcrVersionIDsMtx.Unlock()

	if e.ghcrVersionIDs == nil {
		segment, err := e.resolveGHCROwnerSegment(ctx, owner)
		if err != nil {
			return 0, "", false, err
		}

		var versionIDs map[string]int64
		versionIDs, err = e.listGHCRVersionIDs(ctx, segment, owner, pkg)
		if err != nil {
			return 0, "", false, err
		}

		e.ghcrOwnerSegment = segment
		e.ghcrVersionIDs = versionIDs
	}

	id, ok := e.ghcrVersionIDs[digest]

	return id, e.ghcrOwnerSegment, ok, nil
}

func (e *ociEnvironment) resolveGHCROwnerSegment(ctx context.Context, owner string) (string, error) {
	log.Debug(ctx, "Resolving package owner type")
	var ownerType string
	err := e.retrier.Do(ctx, "get owner", func(ctx context.Context) error {
		req, inErr := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/users/%s", url.PathEscape(owner)), nil)
		if inErr != nil {
			return fmt.Errorf("cannot create request: %w", inErr)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-Github-Api-Version", "2022-11-28") // fixme is this the latest?

		var resp *http.Response
		resp, inErr = e.ghcrClient.Do(req)
		if inErr != nil {
			return fmt.Errorf("cannot get owner: %w", inErr)
		}
		defer func() {
			_ = resp.Body.Close() // fixme happy path close?
		}()

		if resp.StatusCode != http.StatusOK {
			message, readErr := io.ReadAll(resp.Body) // fixme inerr
			if readErr != nil {
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

		ownerType = account.Type

		return nil
	})
	if err != nil {
		return "", err
	}

	if ownerType == "Organization" { // fixme switch
		return "orgs", nil
	}

	return "users", nil
}

func (e *ociEnvironment) listGHCRVersionIDs(ctx context.Context, segment, owner, pkg string) (map[string]int64, error) {
	type ghcrVersion struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}

	log.Debug(ctx, "Listing package versions")
	versionsURL := fmt.Sprintf("https://api.github.com/%s/%s/packages/container/%s/versions?per_page=100", segment, url.PathEscape(owner), url.PathEscape(pkg))
	versionIDs := make(map[string]int64)
	page := 1
	for {
		var versions []ghcrVersion
		err := e.retrier.Do(ctx, "list package versions", func(ctx context.Context) error {
			req, inErr := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s&page=%d", versionsURL, page), nil)
			if inErr != nil {
				return fmt.Errorf("cannot create request: %w", inErr)
			}
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-Github-Api-Version", "2022-11-28")

			var resp *http.Response
			resp, inErr = e.ghcrClient.Do(req)
			if inErr != nil {
				return fmt.Errorf("cannot list package versions: %w", inErr)
			}
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != http.StatusOK {
				message, readErr := io.ReadAll(resp.Body) // fixme inerr
				if readErr != nil {
					return fmt.Errorf("unexpected status %q", resp.Status)
				}

				return fmt.Errorf("unexpected status %q: %q", resp.Status, strings.TrimSpace(string(message)))
			}

			inErr = json.NewDecoder(resp.Body).Decode(&versions)
			if inErr != nil {
				return fmt.Errorf("cannot decode package versions: %w", inErr)
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

func (e *ociEnvironment) deleteGHCRVersion(ctx context.Context, segment, owner, pkg string, id int64) error {
	return e.retrier.Do(ctx, "delete package version", func(ctx context.Context) error {
		req, inErr := http.NewRequestWithContext(ctx, http.MethodDelete, fmt.Sprintf("https://api.github.com/%s/%s/packages/container/%s/versions/%d", segment, url.PathEscape(owner), url.PathEscape(pkg), id), nil)
		if inErr != nil {
			return fmt.Errorf("cannot create request: %w", inErr)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-Github-Api-Version", "2022-11-28")

		var resp *http.Response
		resp, inErr = e.ghcrClient.Do(req)
		if inErr != nil {
			return fmt.Errorf("cannot delete package version: %w", inErr)
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode != http.StatusNoContent {
			message, readErr := io.ReadAll(resp.Body) // fixme inerr
			if readErr != nil {
				return fmt.Errorf("unexpected status %q", resp.Status)
			}

			return fmt.Errorf("unexpected status %q: %q", resp.Status, strings.TrimSpace(string(message)))
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

	p.environments = make(map[string]*ociEnvironment, len(p.pubCfg.Repositories))
	for group, repoCfg := range p.pubCfg.Repositories {
		switch {
		case repoCfg.Repository == "":
			return fmt.Errorf("missing repository for %s", group)
		case repoCfg.Config == "":
			return fmt.Errorf("missing config for %s", group)
		}

		_, ok := p.environments[repoCfg.Repository]
		if ok {
			return fmt.Errorf("repository %s configured for multiple groups", repoCfg.Repository)
		}

		environment := &ociEnvironment{}
		environment.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() int {
			return int(environment.credsGen.Load())
		}), guard.DelegatingTimeoutPolicy{})

		p.environments[repoCfg.Repository] = environment
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
	for _, repoCfg := range p.pubCfg.Repositories {
		acquireCreds.Go(func(ctx context.Context) error {
			err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
				Type:      "OCI_" + ociCredsType(repoCfg.Repository),
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
			Type:      "OCI_" + ociCredsType(repoCfg.Repository),
			Config:    repoCfg.Config,
			Qualifier: repoCfg.Repository,
			Role:      "target",
		})
	}

	return nil
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

	var transport *retry.Transport
	transport, err = newRetryTransport()
	if err != nil {
		return nil, err
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
