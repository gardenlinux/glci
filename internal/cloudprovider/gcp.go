package cloudprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"time"

	computev1 "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/util"
)

func init() {
	util.CleanEnv("EXPERIMENTAL_GOOGLE_")
	util.CleanEnv("GCE_")
	util.CleanEnv("GOOGLE_")
	util.CleanEnv("GRPC_")
	util.CleanEnv("OTEL_")
	util.CleanEnv("STORAGE_EMULATOR_HOST")

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

func (p *gcp) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var architecture string
	architecture, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	project := p.creds[p.pubCfg.Config].Project
	ctx = log.WithValues(ctx, "target", p.Type(), "image", image, "architecture", architecture, "sourceType", source.Type(),
		"sourceRepo", source.Repository(), "project", project)

	var secureBoot bool
	var pk, kek, db string
	secureBoot, pk, kek, db, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "secureBoot", secureBoot)

	var blob *storage.ObjectHandle
	var blobURL string
	blob, blobURL, err = p.uploadBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, fmt.Errorf("cannot upload blob for image %s in project %s: %w", image, project, err)
	}
	ctx = log.WithValues(ctx, "blob", blob.ObjectName())

	err = p.insertImage(ctx, blobURL, image, architecture, secureBoot, pk, kek, db)
	if err != nil {
		return nil, fmt.Errorf("cannot insert image %s from blob %s in project %s: %w", image, blob.ObjectName(), project, err)
	}

	err = p.deleteBlob(ctx, blob)
	if err != nil {
		return nil, fmt.Errorf("cannot delete blob %s in project %s: %w", blob.ObjectName(), project, err)
	}

	err = p.makePublic(ctx, image)
	if err != nil {
		return nil, fmt.Errorf("cannot make image %s public in project %s: %w", image, project, err)
	}

	return gcpPublishingOutput{
		Project: project,
		Name:    image,
	}, nil
}

func (p *gcp) Remove(ctx context.Context, cname string, manifest *gl.Manifest, _ map[string]ArtifactSource) error {
	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	project := p.creds[p.pubCfg.Config].Project
	ctx = log.WithValues(ctx, "target", p.Type(), "image", image, "project", project)

	err := p.deleteImage(ctx, image)
	if err != nil {
		return fmt.Errorf("cannot delete image %s in project %s: %w", image, project, err)
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
	Project string `mapstructure:"project"`
	Name    string `mapstructure:"name"`
}

func (*gcp) imageName(cname, version, committish string) string {
	cname = util.Hash(fnv.New64(), cname)
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
	secureBoot := manifest.SecureBoot != nil && *manifest.SecureBoot
	var pk, kek, db string

	if secureBoot {
		pkFile, err := manifest.PathBySuffix(".secureboot.pk.der")
		if err != nil {
			return false, "", "", "", fmt.Errorf("missing secureboot PK: %w", err)
		}

		var rawPK []byte
		rawPK, err = source.GetObjectBytes(ctx, pkFile.S3Key)
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
		rawKEK, err = source.GetObjectBytes(ctx, kekFile.S3Key)
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
		rawDB, err = source.GetObjectBytes(ctx, dbFile.S3Key)
		if err != nil {
			return false, "", "", "", fmt.Errorf("cannot get DB: %w", err)
		}
		db = base64.StdEncoding.EncodeToString(rawDB)
	}

	return secureBoot, pk, kek, db, nil
}

func (p *gcp) uploadBlob(ctx context.Context, source ArtifactSource, key, image string) (*storage.ObjectHandle, string, error) {
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "key", key)

	r, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, "", fmt.Errorf("cannot get blob: %w", err)
	}

	log.Info(ctx, "Uploading blob")
	bucket := p.storageClient.Bucket(p.pubCfg.Bucket)
	blob := bucket.Object(image + ".tar.gz")
	w := blob.NewWriter(ctx)
	_, err = io.Copy(w, r)
	if err != nil {
		return nil, "", fmt.Errorf("cannot write to object writer: %w", err)
	}
	err = w.Close()
	if err != nil {
		return nil, "", fmt.Errorf("cannot close object writer: %w", err)
	}
	log.Debug(ctx, "Blob uploaded")

	var url string
	url, err = bucket.SignedURL(blob.ObjectName(), &storage.SignedURLOptions{
		Method:  "GET",
		Expires: time.Now().Add(7 * time.Hour),
		Scheme:  storage.SigningSchemeV4,
	})
	if err != nil {
		return nil, "", fmt.Errorf("cannot generate signed URL for blob %s: %w", blob.ObjectName(), err)
	}

	return blob, url, nil
}

func (p *gcp) insertImage(ctx context.Context, disk, image, architecture string, secureBoot bool, pk, kek, db string) error {
	project := p.creds[p.pubCfg.Config].Project
	imageResource := &computepb.Image{
		Architecture: &architecture,
		GuestOsFeatures: []*computepb.GuestOsFeature{
			{
				Type: util.Ptr("VIRTIO_SCSI_MULTIQUEUE"),
			},
			{
				Type: util.Ptr("UEFI_COMPATIBLE"),
			},
			{
				Type: util.Ptr("GVNIC"),
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
					FileType: util.Ptr("X509"),
				},
			},
			Keks: []*computepb.FileContentBuffer{
				{
					Content:  &kek,
					FileType: util.Ptr("X509"),
				},
			},
			Pk: &computepb.FileContentBuffer{
				Content:  &pk,
				FileType: util.Ptr("X509"),
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

func (*gcp) deleteBlob(ctx context.Context, blob *storage.ObjectHandle) error {
	log.Info(ctx, "Deleting blob")
	err := blob.Delete(ctx)
	if err != nil {
		return fmt.Errorf("cannot delete blob %s: %w", blob.ObjectName(), err)
	}

	return nil
}

func (p *gcp) makePublic(ctx context.Context, image string) error {
	project := p.creds[p.pubCfg.Config].Project

	_, err := p.imagesClient.SetIamPolicy(ctx, &computepb.SetIamPolicyImageRequest{
		GlobalSetPolicyRequestResource: &computepb.GlobalSetPolicyRequest{
			Policy: &computepb.Policy{
				AuditConfigs: nil,
				Bindings: []*computepb.Binding{
					{
						Members: []string{
							"allAuthenticatedUsers",
						},
						Role: util.Ptr("roles/compute.imageUser"),
					},
				},
				Version: util.Ptr(int32(3)),
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

func (p *gcp) deleteImage(ctx context.Context, image string) error {
	project := p.creds[p.pubCfg.Config].Project

	log.Info(ctx, "Deleting image")
	op, err := p.imagesClient.Delete(ctx, &computepb.DeleteImageRequest{
		Image:   image,
		Project: project,
	})
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("cannot delete image via operation %s: %w", op.Name(), err)
	}

	log.Debug(ctx, "Ensuring that blob is deleted")
	bucket := p.storageClient.Bucket(p.pubCfg.Bucket)
	blob := bucket.Object(image + ".tar.gz")
	err = blob.Delete(ctx)
	if err != nil && !errors.Is(err, storage.ErrObjectNotExist) {
		return fmt.Errorf("cannot delete blob %s: %w", blob.ObjectName(), err)
	}

	return nil
}
