package cloudprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
	"time"

	computev1 "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/hsh"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ptr"
)

func init() {
	env.Clean("EXPERIMENTAL_GOOGLE_")
	env.Clean("GCE_")
	env.Clean("GOOGLE_")
	env.Clean("GRPC_")
	env.Clean("OTEL_")
	env.Clean("STORAGE_EMULATOR_HOST")

	registerPublishingTarget(func() PublishingTarget {
		return &gcp{}
	})
}

func (*gcp) Type() string {
	return "GCP"
}

func (p *gcp) SetCredentials(creds map[string]any) error {
	err := setCredentials(creds, "gcp", &p.creds)
	if err != nil {
		return err
	}

	for cfg, gcpCreds := range p.creds {
		gcpCreds.serviceAccountKeyJSON, err = json.Marshal(gcpCreds.ServiceAccountKey)
		if err != nil {
			return fmt.Errorf("invalid credentials for config %s: %w", cfg, err)
		}
		gcpCreds.ServiceAccountKey = nil
		p.creds[cfg] = gcpCreds
	}

	return nil
}

func (p *gcp) SetTargetConfig(ctx context.Context, cfg map[string]any, sources map[string]ArtifactSource) error {
	err := setConfig(cfg, &p.pubCfg)
	if err != nil {
		return err
	}

	if p.creds == nil {
		return errors.New("credentials not set")
	}

	_, ok := sources[p.pubCfg.Source]
	if !ok {
		return fmt.Errorf("unknown source %s", p.pubCfg.Source)
	}

	var creds gcpCredentials
	creds, ok = p.creds[p.pubCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.pubCfg.Config)
	}

	p.storageClient, err = storage.NewClient(ctx, option.WithCredentialsJSON(creds.serviceAccountKeyJSON))
	if err != nil {
		return fmt.Errorf("cannot create storage client: %w", err)
	}

	p.imagesClient, err = computev1.NewImagesRESTClient(ctx, option.WithCredentialsJSON(creds.serviceAccountKeyJSON))
	if err != nil {
		return fmt.Errorf("cannot create images client: %w", err)
	}

	return nil
}

func (p *gcp) Close() error {
	if p.storageClient != nil {
		err := p.storageClient.Close()
		if err != nil {
			return fmt.Errorf("cannot close storage client: %w", err)
		}
	}

	if p.imagesClient != nil {
		err := p.imagesClient.Close()
		if err != nil {
			return fmt.Errorf("cannot close images client: %w", err)
		}
	}

	return nil
}

func (*gcp) ImageSuffix() string {
	return ".gcpimage.tar.gz"
}

func (p *gcp) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return flavor(manifest.Platform) == "gcp"
}

func (p *gcp) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	gcpOutput, err := publishingOutputFromManifest[gcpPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return gcpOutput.Project != "" && gcpOutput.Image != "", nil
}

func (p *gcp) AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	gcpOutput, err := publishingOutput[gcpPublishingOutput](output)
	if err != nil {
		return nil, err
	}
	var ownOutput gcpPublishingOutput
	ownOutput, err = publishingOutput[gcpPublishingOutput](own)
	if err != nil {
		return nil, err
	}

	if gcpOutput.Project != "" || gcpOutput.Image != "" {
		return nil, errors.New("cannot add publishing output to existing publishing output")
	}

	return &ownOutput, nil
}

func (p *gcp) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	_, err := publishingOutput[gcpPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *gcp) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	f := flavor(cname)
	if f != "gcp" {
		return nil, fmt.Errorf("invalid cname %s for target %s", cname, p.Type())
	}
	if f != manifest.Platform {
		return nil, fmt.Errorf("cname %s does not match platform %s", cname, manifest.Platform)
	}

	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	project := p.creds[p.pubCfg.Config].Project
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", source.Type(), "sourceRepo", source.Repository(),
		"project", project)

	var secureBoot bool
	var pk, kek, db string
	secureBoot, pk, kek, db, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "secureBoot", secureBoot)

	var blob, blobURL string
	blob, blobURL, err = p.uploadBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, fmt.Errorf("cannot upload blob for image %s in project %s: %w", image, project, err)
	}

	err = p.insertImage(ctx, blobURL, image, arch, secureBoot, pk, kek, db)
	if err != nil {
		return nil, fmt.Errorf("cannot insert image %s from blob %s in project %s: %w", image, blob, project, err)
	}

	err = p.deleteBlob(ctx, blob, false)
	if err != nil {
		return nil, fmt.Errorf("cannot delete blob %s in project %s: %w", blob, project, err)
	}

	err = p.makePublic(ctx, image)
	if err != nil {
		return nil, fmt.Errorf("cannot make image %s public in project %s: %w", image, project, err)
	}

	return &gcpPublishingOutput{
		Project: project,
		Image:   image,
	}, nil
}

func (p *gcp) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if flavor(manifest.Platform) != "gcp" {
		return fmt.Errorf("invalid manifest: invalid platform %s for target %s", manifest.Platform, p.Type())
	}

	pubOut, err := publishingOutputFromManifest[gcpPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if pubOut.Project == "" || pubOut.Image == "" {
		return errors.New("invalid manifest: missing published images")
	}
	ctx = log.WithValues(ctx, "image", pubOut.Image, "project", pubOut.Project)

	err = p.deleteImage(ctx, pubOut.Image, steamroll)
	if err != nil {
		return fmt.Errorf("cannot delete image %s: %w", pubOut.Image, err)
	}

	return nil
}

type gcp struct {
	creds         map[string]gcpCredentials
	pubCfg        gcpPublishingConfig
	storageClient *storage.Client
	imagesClient  *computev1.ImagesClient
}

type gcpCredentials struct {
	Project               string `mapstructure:"project"`
	ServiceAccountKey     any    `mapstructure:"service_account_key"`
	serviceAccountKeyJSON []byte
}

type gcpPublishingConfig struct {
	Source string `mapstructure:"source"`
	Config string `mapstructure:"config"`
	Bucket string `mapstructure:"bucket"`
}

type gcpPublishingOutput struct {
	Project string `yaml:"gcp_project_name,omitzero"`
	Image   string `yaml:"gcp_image_name,omitzero"`
}

func (p *gcp) isConfigured() bool {
	return p.storageClient != nil && p.imagesClient != nil
}

func (*gcp) imageName(cname, version, committish string) string {
	cname = hsh.Hash(fnv.New64(), cname)
	version = strings.ReplaceAll(version, ".", "-")
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", cname, version, committish)
}

func (*gcp) architecture(arch gl.Architecture) (string, error) {
	switch arch {
	case gl.ArchitectureAMD64:
		return "X86_64", nil
	case gl.ArchitectureARM64:
		return "ARM64", nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (*gcp) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gl.Manifest) (bool, string, string, string, error) {
	var pk, kek, db string

	if manifest.SecureBoot {
		pkFile, err := manifest.PathBySuffix(".secureboot.pk.der")
		if err != nil {
			return false, "", "", "", fmt.Errorf("missing secureboot PK: %w", err)
		}

		var rawPK []byte
		rawPK, err = getObjectBytes(ctx, source, pkFile.S3Key)
		if err != nil {
			return false, "", "", "", fmt.Errorf("cannot get PK: %w", err)
		}
		pk = base64.StdEncoding.EncodeToString(rawPK)

		var kekFile gl.S3ReleaseFile
		kekFile, err = manifest.PathBySuffix(".secureboot.kek.der")
		if err != nil {
			return false, "", "", "", fmt.Errorf("missing KEK: %w", err)
		}

		var rawKEK []byte
		rawKEK, err = getObjectBytes(ctx, source, kekFile.S3Key)
		if err != nil {
			return false, "", "", "", fmt.Errorf("cannot get KEK: %w", err)
		}
		kek = base64.StdEncoding.EncodeToString(rawKEK)

		var dbFile gl.S3ReleaseFile
		dbFile, err = manifest.PathBySuffix(".secureboot.db.der")
		if err != nil {
			return false, "", "", "", fmt.Errorf("missing DB: %w", err)
		}

		var rawDB []byte
		rawDB, err = getObjectBytes(ctx, source, dbFile.S3Key)
		if err != nil {
			return false, "", "", "", fmt.Errorf("cannot get DB: %w", err)
		}
		db = base64.StdEncoding.EncodeToString(rawDB)
	}

	return manifest.SecureBoot, pk, kek, db, nil
}

func (p *gcp) uploadBlob(ctx context.Context, source ArtifactSource, key, image string) (string, string, error) {
	blob := image + ".tar.gz"
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "key", key, "blob", blob)

	obj, err := source.GetObject(ctx, key)
	if err != nil {
		return "", "", fmt.Errorf("cannot get blob: %w", err)
	}
	defer func() {
		_ = obj.Close()
	}()

	log.Info(ctx, "Uploading blob")
	bucket := p.storageClient.Bucket(p.pubCfg.Bucket)
	w := bucket.Object(blob).NewWriter(ctx)
	_, err = io.Copy(w, obj)
	if err != nil {
		return "", "", fmt.Errorf("cannot write to object writer: %w", err)
	}
	err = w.Close()
	if err != nil {
		return "", "", fmt.Errorf("cannot close object writer: %w", err)
	}
	log.Debug(ctx, "Blob uploaded")

	err = obj.Close()
	if err != nil {
		return "", "", fmt.Errorf("cannot close blob: %w", err)
	}

	var url string
	url, err = bucket.SignedURL(blob, &storage.SignedURLOptions{
		Method:  "GET",
		Expires: time.Now().Add(time.Hour * 7),
		Scheme:  storage.SigningSchemeV4,
	})
	if err != nil {
		return "", "", fmt.Errorf("cannot generate signed URL for blob %s: %w", blob, err)
	}

	return blob, url, nil
}

func (p *gcp) insertImage(ctx context.Context, disk, image, arch string, secureBoot bool, pk, kek, db string) error {
	project := p.creds[p.pubCfg.Config].Project
	imageResource := &computepb.Image{
		Architecture: &arch,
		GuestOsFeatures: []*computepb.GuestOsFeature{
			{
				Type: ptr.P("VIRTIO_SCSI_MULTIQUEUE"),
			},
			{
				Type: ptr.P("UEFI_COMPATIBLE"),
			},
			{
				Type: ptr.P("GVNIC"),
			},
		},
		Name: &image,
		RawDisk: &computepb.RawDisk{
			Source: &disk,
		},
	}
	if secureBoot {
		imageResource.ShieldedInstanceInitialState = &computepb.InitialStateConfig{
			Dbs: []*computepb.FileContentBuffer{
				{
					Content:  &db,
					FileType: ptr.P("X509"),
				},
			},
			Keks: []*computepb.FileContentBuffer{
				{
					Content:  &kek,
					FileType: ptr.P("X509"),
				},
			},
			Pk: &computepb.FileContentBuffer{
				Content:  &pk,
				FileType: ptr.P("X509"),
			},
		}
	}

	log.Info(ctx, "Inserting image")
	op, err := p.imagesClient.Insert(ctx, &computepb.InsertImageRequest{
		ImageResource: imageResource,
		Project:       project,
	})
	if err != nil {
		return fmt.Errorf("cannot insert image: %w", err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("cannot insert image via operation %s: %w", op.Name(), err)
	}
	log.Info(ctx, "Image ready")

	return nil
}

func (p *gcp) deleteBlob(ctx context.Context, blob string, steamroll bool) error {
	log.Info(ctx, "Deleting blob")
	err := p.storageClient.Bucket(p.pubCfg.Bucket).Object(blob).Delete(ctx)
	if err != nil {
		var errr *googleapi.Error
		if steamroll && errors.As(err, &errr) && errr.Code == http.StatusNotFound {
			log.Debug(ctx, "Blob not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete blob %s: %w", blob, err)
	}

	return nil
}

func (p *gcp) makePublic(ctx context.Context, image string) error {
	project := p.creds[p.pubCfg.Config].Project

	log.Debug(ctx, "Setting IAM policy")
	_, err := p.imagesClient.SetIamPolicy(ctx, &computepb.SetIamPolicyImageRequest{
		GlobalSetPolicyRequestResource: &computepb.GlobalSetPolicyRequest{
			Policy: &computepb.Policy{
				AuditConfigs: nil,
				Bindings: []*computepb.Binding{
					{
						Members: []string{
							"allAuthenticatedUsers",
						},
						Role: ptr.P("roles/compute.imageUser"),
					},
				},
				Version: ptr.P(int32(3)),
			},
		},
		Project:  project,
		Resource: image,
	})
	if err != nil {
		return fmt.Errorf("cannot set IAM policy: %w", err)
	}

	return nil
}

func (p *gcp) deleteImage(ctx context.Context, image string, steamroll bool) error {
	project := p.creds[p.pubCfg.Config].Project

	log.Info(ctx, "Deleting image")
	op, err := p.imagesClient.Delete(ctx, &computepb.DeleteImageRequest{
		Image:   image,
		Project: project,
	})
	if err != nil {
		var errr *googleapi.Error
		if steamroll && errors.As(err, &errr) && errr.Code == http.StatusNotFound {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete image: %w", err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("cannot delete image via operation %s: %w", op.Name(), err)
	}

	return nil
}
