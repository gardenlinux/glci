package cloudprovider

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"
	specv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	orasfile "oras.land/oras-go/v2/content/file"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
)

func init() {
	registerOCMTarget(func() OCMTarget {
		return &oci{}
	})
}

func (*oci) Type() string {
	return "OCI"
}

func (p *oci) SetCredentials(creds map[string]any) error {
	return setCredentials(creds, "container_registry", &p.creds)
}

func (p *oci) SetOCMConfig(_ context.Context, cfg map[string]any) error {
	err := setConfig(cfg, &p.ociCfg)
	if err != nil {
		return err
	}

	if p.creds == nil {
		return errors.New("credentials not set")
	}
	creds, ok := p.creds[p.ociCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.ociCfg.Config)
	}

	if !strings.HasSuffix(p.ociCfg.Repository, repoSuffix) {
		p.ociCfg.Repository += repoSuffix
	}
	p.repo, err = remote.NewRepository(p.ociCfg.Repository)
	if err != nil {
		return fmt.Errorf("invalid OCI repository %s: %w", p.ociCfg.Repository, err)
	}

	p.repo.Client = &auth.Client{
		Client: retry.DefaultClient,
		Cache:  auth.NewCache(),
		Credential: auth.StaticCredential(p.repo.Reference.Registry, auth.Credential{
			Username: creds.Username,
			Password: creds.Password,
		}),
	}

	return nil
}

func (*oci) Close() error {
	return nil
}

func (*oci) OCMType() string {
	return "OCIRegistry"
}

func (p *oci) OCMRepository() string {
	return p.ociCfg.Repository
}

func (p *oci) PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "repo", p.ociCfg.Repository)

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
	var fs *orasfile.Store
	fs, err = orasfile.New(tmpDir)
	if err != nil {
		return fmt.Errorf("cannot create local OCI store in %s: %w", tmpDir, err)
	}
	defer func() {
		_ = fs.Close()
	}()

	tarDescriptor := specv1.Descriptor{
		MediaType: "application/vnd.gardener.cloud.cnudie.component-descriptor.v2+yaml+tar",
		Digest:    digest.FromBytes(tarBuf.Bytes()),
		Size:      int64(tarBuf.Len()),
	}
	log.Debug(ctx, "Pushing tarball", "digest", tarDescriptor.Digest)
	err = fs.Push(ctx, tarDescriptor, &tarBuf)
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest config to local OCI store: %w", err)
	}

	var configJSON []byte
	configJSON, err = json.Marshal(map[string]map[string]any{
		"componentDescriptorLayer": {
			"digest":    tarDescriptor.Digest.String(),
			"mediaType": tarDescriptor.MediaType,
			"size":      tarDescriptor.Size,
		},
	})
	if err != nil {
		return fmt.Errorf("invalid artifact config: %w", err)
	}

	configDescriptor := specv1.Descriptor{
		MediaType: "application/vnd.gardener.cloud.cnudie.component.config.v1+json",
		Digest:    digest.FromBytes(configJSON),
		Size:      int64(len(configJSON)),
	}
	log.Debug(ctx, "Pushing config", "digest", configDescriptor.Digest)
	err = fs.Push(ctx, configDescriptor, bytes.NewReader(configJSON))
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest config to local OCI store: %w", err)
	}

	var manifestDescriptor specv1.Descriptor
	manifestDescriptor, err = oras.PackManifest(ctx, fs, oras.PackManifestVersion1_1, tarDescriptor.MediaType, oras.PackManifestOptions{
		Layers: []specv1.Descriptor{
			tarDescriptor,
		},
		ManifestAnnotations: map[string]string{
			specv1.AnnotationCreated: "1970-01-01T00:00:00Z",
		},
		ConfigDescriptor: &configDescriptor,
	})
	if err != nil {
		return fmt.Errorf("cannot add OCI manifest to local OCI store: %w", err)
	}

	log.Debug(ctx, "Tagging manifest", "size", manifestDescriptor.Size, "digest", manifestDescriptor.Digest)
	err = fs.Tag(ctx, manifestDescriptor, version)
	if err != nil {
		return fmt.Errorf("cannot tag OCI manifest: %w", err)
	}

	log.Debug(ctx, "Copying artifact")
	_, err = oras.Copy(ctx, fs, version, p.repo, version, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("cannot upload OCI artifact to %s: %w", p.ociCfg.Repository, err)
	}

	err = fs.Close()
	if err != nil {
		return fmt.Errorf("cannot close local OCI store: %w", err)
	}

	err = os.RemoveAll(tmpDir)
	if err != nil {
		return fmt.Errorf("cannot remove temporary directory %s: %w", tmpDir, err)
	}

	return nil
}

type oci struct {
	creds  map[string]ociCredentials
	ociCfg ociOCMConfig
	repo   *remote.Repository
}

const (
	repoSuffix = "/component-descriptors/" + gl.GardenLinuxRepo
)

type ociCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ociOCMConfig struct {
	Config     string `mapstructure:"config"`
	Repository string `mapstructure:"repository"`
}

func (p *oci) isConfigured() bool {
	return p.repo != nil
}
