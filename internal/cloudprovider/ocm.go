package cloudprovider

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/opencontainers/go-digest"
	specsv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
)

const (
	repoSuffix = "/component-descriptors/" + gardenlinux.GardenLinuxRepo
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	module.RegisterImpl(OCMTargetCategory, "OCI", func(b *module.Base) OCMTarget {
		p := &ocmTarget{
			base: b,
		}
		p.world.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() int {
			return int(p.world.credsGen.Load())
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})
}

func (*ocmTarget) Type() string {
	return "OCI"
}

type ocmTarget struct {
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

func (p *ocmTarget) isConfigured() bool {
	return p.environment().repository != nil
}

func (p *ocmTarget) applyCredentials(_ context.Context, rawCreds map[string]any) error {
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

func (p *ocmTarget) environment() *ociEnvironment {
	return &p.world
}

func (*ocmTarget) OCMType() string {
	return "OCIRegistry"
}

func (p *ocmTarget) OCMRepositoryBase() string {
	return p.ocmCfg.Repository
}

func (p *ocmTarget) PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	log.Info(ctx, "Publishing OCM component descriptor")

	storeDir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(storeDir)
	}()

	var store *orasfile.Store
	store, err = orasfile.New(storeDir)
	if err != nil {
		return fmt.Errorf("cannot create local OCI store in %s: %w", storeDir, err)
	}
	defer func() {
		_ = store.Close()
	}()

	var tarBuf bytes.Buffer
	tarball := tar.NewWriter(&tarBuf)
	defer func() {
		_ = tarball.Close()
	}()

	err = tarball.WriteHeader(&tar.Header{
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

	tarDescriptor := specsv1.Descriptor{
		MediaType: "application/vnd.gardener.cloud.cnudie.component-descriptor.v2+yaml+tar",
		Digest:    digest.FromBytes(tarBuf.Bytes()),
		Size:      int64(tarBuf.Len()),
	}

	err = store.Push(ctx, tarDescriptor, &tarBuf)
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest layer to local OCI store: %w", err)
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
	ctx = log.WithValues(ctx, "digest", manifestDescriptor.Digest)

	environment := p.environment()

	log.Debug(ctx, "Copying artifact")
	err = environment.copyGraph(ctx, store, manifestDescriptor)
	if err != nil {
		return err
	}

	err = store.Close()
	if err != nil {
		return fmt.Errorf("cannot close local OCI store: %w", err)
	}

	err = os.RemoveAll(storeDir)
	if err != nil {
		return fmt.Errorf("cannot remove temporary directory: %w", err)
	}

	log.Debug(ctx, "Tagging artifact")
	err = environment.tag(ctx, manifestDescriptor, version)
	if err != nil {
		return err
	}

	return nil
}

func (p *ocmTarget) Configure(rawCfg map[string]any) error {
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

func (*ocmTarget) Configurables() []module.Configurable {
	return nil
}

func (p *ocmTarget) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   "OCI_" + p.credsType,
		Config: p.ocmCfg.Config,
		Role:   "ocm",
	}, p.applyCredentials)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.ocmCfg.Config, err)
	}

	return nil
}

func (p *ocmTarget) Stop(ctx context.Context) error {
	if p.ocmCfg.Config != "" {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:   "OCI_" + p.credsType,
			Config: p.ocmCfg.Config,
			Role:   "ocm",
		})
	}

	return nil
}
