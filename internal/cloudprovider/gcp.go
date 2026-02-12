package cloudprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/hsh"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/task"
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

type gcp struct {
	pubCfg        gcpPublishingConfig
	credsSource   credsprovider.CredsSource
	clientsMtx    sync.RWMutex
	storageClient *storage.Client
	imagesClient  *compute.ImagesClient
	accessID      string
}

type gcpPublishingConfig struct {
	Source  string `mapstructure:"source"`
	Config  string `mapstructure:"config"`
	Project string `mapstructure:"project"`
	Bucket  string `mapstructure:"bucket"`
}

func (p *gcp) isConfigured() bool {
	stortageClient, imagesClient := p.clients()

	return stortageClient != nil && imagesClient != nil
}

func (p *gcp) SetTargetConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg map[string]any,
	sources map[string]ArtifactSource,
) error {
	p.credsSource = credsSource

	err := parseConfig(cfg, &p.pubCfg)
	if err != nil {
		return err
	}

	switch {
	case p.pubCfg.Source == "":
		return errors.New("missing source")
	case p.pubCfg.Config == "":
		return errors.New("missing config")
	case p.pubCfg.Project == "":
		return errors.New("missing project")
	case p.pubCfg.Bucket == "":
		return errors.New("missing bucket")
	}

	_, ok := sources[p.pubCfg.Source]
	if !ok {
		return fmt.Errorf("unknown source %s", p.pubCfg.Source)
	}

	err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.pubCfg.Config,
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	return nil
}

type gcpTaskState struct {
	Blob  string `json:"blob,omitzero"`
	Image string `json:"image,omitzero"`
}

type gcpPublishingOutput struct {
	Project string `yaml:"gcp_project_name,omitzero"`
	Image   string `yaml:"gcp_image_name,omitzero"`
}

type gcpCredentials struct {
	ServiceAccountEmail string `mapstructure:"service_account_email"`
	Token               string `mapstructure:"token"`
	Expiry              int64  `mapstructure:"expiry"`
}

func (p *gcp) createClients(ctx context.Context, rawCreds map[string]any) error {
	var creds gcpCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	err = p.destroyClients(p.storageClient, p.imagesClient)
	if err != nil {
		return fmt.Errorf("cannot destroy existing clients: %w", err)
	}

	tokenSrc := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: creds.Token,
		Expiry:      time.Unix(creds.Expiry, 0),
	})

	p.storageClient, err = storage.NewClient(ctx, option.WithTokenSource(tokenSrc))
	if err != nil {
		return fmt.Errorf("cannot create storage client: %w", err)
	}

	p.imagesClient, err = compute.NewImagesRESTClient(ctx, option.WithTokenSource(tokenSrc))
	if err != nil {
		return fmt.Errorf("cannot create images client: %w", err)
	}

	p.accessID = creds.ServiceAccountEmail

	return nil
}

func (p *gcp) clients() (*storage.Client, *compute.ImagesClient) {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.storageClient, p.imagesClient
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

func (*gcp) ImageSuffix() string {
	return ".gcpimage.tar.gz"
}

func (p *gcp) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return manifest.Platform == "gcp"
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

	pl := platform(cname)
	if pl != "gcp" {
		return nil, fmt.Errorf("invalid cname %s for target %s", cname, p.Type())
	}
	if pl != manifest.Platform {
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
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", source.Type(), "sourceRepo", source.Repository(),
		"project", p.pubCfg.Project)

	var secureBoot bool
	var pk, kek, db string
	secureBoot, pk, kek, db, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "secureBoot", secureBoot)

	ctx = task.Begin(ctx, "publish/"+image, &gcpTaskState{})
	var blob, blobURL string
	blob, blobURL, err = p.uploadBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot upload blob for image %s: %w", image, err))
	}

	err = p.insertImage(ctx, blobURL, image, arch, secureBoot, pk, kek, db)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot insert image %s from blob %s: %w", image, blob, err))
	}

	err = p.deleteBlob(ctx, blob, false)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot delete blob %s: %w", blob, err))
	}

	err = p.makePublic(ctx, image)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot make image %s public: %w", image, err))
	}
	task.Complete(ctx)

	return &gcpPublishingOutput{
		Project: p.pubCfg.Project,
		Image:   image,
	}, nil
}

func (*gcp) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gl.Manifest) (bool, string, string, string, error) {
	var pk, kek, db string

	if manifest.SecureBoot {
		fetchCertificates := parallel.NewActivity(ctx)

		fetchCertificates.Go(func(ctx context.Context) error {
			pkFile, er := manifest.PathBySuffix(".secureboot.pk.der")
			if er != nil {
				return fmt.Errorf("missing secureboot PK: %w", er)
			}

			var rawPK []byte
			rawPK, er = getObjectBytes(ctx, source, pkFile.S3Key)
			if er != nil {
				return fmt.Errorf("cannot get PK: %w", er)
			}
			pk = base64.StdEncoding.EncodeToString(rawPK)

			return nil
		})

		fetchCertificates.Go(func(ctx context.Context) error {
			kekFile, er := manifest.PathBySuffix(".secureboot.kek.der")
			if er != nil {
				return fmt.Errorf("missing KEK: %w", er)
			}

			var rawKEK []byte
			rawKEK, er = getObjectBytes(ctx, source, kekFile.S3Key)
			if er != nil {
				return fmt.Errorf("cannot get KEK: %w", er)
			}
			kek = base64.StdEncoding.EncodeToString(rawKEK)

			return nil
		})

		fetchCertificates.Go(func(ctx context.Context) error {
			dbFile, er := manifest.PathBySuffix(".secureboot.db.der")
			if er != nil {
				return fmt.Errorf("missing DB: %w", er)
			}

			var rawDB []byte
			rawDB, er = getObjectBytes(ctx, source, dbFile.S3Key)
			if er != nil {
				return fmt.Errorf("cannot get DB: %w", er)
			}
			db = base64.StdEncoding.EncodeToString(rawDB)

			return nil
		})

		err := fetchCertificates.Wait()
		if err != nil {
			return false, "", "", "", err
		}
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

	storageClient, _ := p.clients()

	log.Info(ctx, "Uploading blob")
	bucket := storageClient.Bucket(p.pubCfg.Bucket)
	w := bucket.Object(blob).NewWriter(ctx)
	_, err = io.Copy(w, obj)
	if err != nil {
		return "", "", fmt.Errorf("cannot write to object writer: %w", err)
	}
	err = w.Close()
	if err != nil {
		return "", "", fmt.Errorf("cannot close object writer: %w", err)
	}
	task.Update(ctx, func(s *gcpTaskState) *gcpTaskState {
		s.Blob = blob
		return s
	})
	log.Debug(ctx, "Blob uploaded")

	err = obj.Close()
	if err != nil {
		return "", "", fmt.Errorf("cannot close blob: %w", err)
	}

	var url string
	url, err = bucket.SignedURL(blob, &storage.SignedURLOptions{
		GoogleAccessID: p.accessID,
		Method:         "GET",
		Expires:        time.Now().Add(time.Hour * 7),
		Scheme:         storage.SigningSchemeV4,
	})
	if err != nil {
		return "", "", fmt.Errorf("cannot generate signed URL for blob %s: %w", blob, err)
	}

	return blob, url, nil
}

func (p *gcp) insertImage(ctx context.Context, disk, image, arch string, secureBoot bool, pk, kek, db string) error {
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

	_, imagesClient := p.clients()

	log.Info(ctx, "Inserting image")
	op, err := imagesClient.Insert(ctx, &computepb.InsertImageRequest{
		ImageResource: imageResource,
		Project:       p.pubCfg.Project,
	})
	if err != nil {
		return fmt.Errorf("cannot insert image: %w", err)
	}
	task.Update(ctx, func(s *gcpTaskState) *gcpTaskState {
		s.Image = image
		return s
	})

	err = op.Wait(ctx)
	if err != nil {
		return fmt.Errorf("cannot insert image via operation %s: %w", op.Name(), err)
	}
	log.Info(ctx, "Image ready")

	return nil
}

func (p *gcp) deleteBlob(ctx context.Context, blob string, steamroll bool) error {
	storageClient, _ := p.clients()

	log.Info(ctx, "Deleting blob")
	err := storageClient.Bucket(p.pubCfg.Bucket).Object(blob).Delete(ctx)
	if err != nil {
		var terr *googleapi.Error
		if steamroll && errors.As(err, &terr) && terr.Code == http.StatusNotFound {
			log.Debug(ctx, "Blob not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete blob %s: %w", blob, err)
	}
	task.Update(ctx, func(s *gcpTaskState) *gcpTaskState {
		s.Blob = ""
		return s
	})

	return nil
}

func (p *gcp) makePublic(ctx context.Context, image string) error {
	_, imagesClient := p.clients()

	log.Debug(ctx, "Setting IAM policy")
	_, err := imagesClient.SetIamPolicy(ctx, &computepb.SetIamPolicyImageRequest{
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
		Project:  p.pubCfg.Project,
		Resource: image,
	})
	if err != nil {
		return fmt.Errorf("cannot set IAM policy: %w", err)
	}

	return nil
}

func (p *gcp) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if manifest.Platform != "gcp" {
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

func (p *gcp) deleteImage(ctx context.Context, image string, steamroll bool) error {
	_, imagesClient := p.clients()

	log.Info(ctx, "Deleting image")
	op, err := imagesClient.Delete(ctx, &computepb.DeleteImageRequest{
		Image:   image,
		Project: p.pubCfg.Project,
	})
	if err != nil {
		var terr *googleapi.Error
		if steamroll && errors.As(err, &terr) && terr.Code == http.StatusNotFound {
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

func (p *gcp) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "gcp"
}

func (p *gcp) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := parallel.NewActivity(ctx)
	for _, t := range tasks {
		state, err := task.ParseState[*gcpTaskState](t.State)
		if err != nil {
			return err
		}

		if state.Blob != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "blob", state.Blob)

				er := p.deleteBlob(ctx, state.Blob, true)
				if er != nil {
					return fmt.Errorf("cannot delete blob %s: %w", state.Blob, er)
				}

				return nil
			})
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "image", state.Image)

				er := p.deleteImage(ctx, state.Image, true)
				if er != nil {
					return fmt.Errorf("cannot delete image %s: %w", state.Image, er)
				}

				return nil
			})
		}
	}
	return rollbackTasks.Wait()
}

func (p *gcp) Close() error {
	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
		})
	}

	storageClient, imagesClient := p.clients()

	return p.destroyClients(storageClient, imagesClient)
}

func (*gcp) destroyClients(storageClient *storage.Client, imagesClient *compute.ImagesClient) error {
	if storageClient != nil {
		err := storageClient.Close()
		if err != nil {
			return fmt.Errorf("cannot close storage client: %w", err)
		}
	}

	if imagesClient != nil {
		err := imagesClient.Close()
		if err != nil {
			return fmt.Errorf("cannot close images client: %w", err)
		}
	}

	return nil
}
