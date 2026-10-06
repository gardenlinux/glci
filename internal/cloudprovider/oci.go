package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
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

func (p *ociTarget) FlavorsDestination(flavorManifests []gardenlinux.FlavorManifest) (string, error) {
	var destination string
	for _, flavorManifest := range flavorManifests {
		repo, err := p.repository(flavorManifest.Flavor)
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

func (*ociTarget) ImageSuffix() string {
	return ".oci"
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
