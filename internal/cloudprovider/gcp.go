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
	"sync/atomic"
	"time"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"cloud.google.com/go/storage"
	"github.com/googleapis/gax-go/v2"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	transporthttp "google.golang.org/api/transport/http"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/hsh"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("EXPERIMENTAL_GOOGLE_")
	env.Clean("GCE_")
	env.Clean("GOOGLE_")
	env.Clean("GRPC_")
	env.Clean("OTEL_")
	env.Clean("STORAGE_EMULATOR_HOST")

	module.RegisterImpl(PublishingTargetCategory, "GCP", func(b *module.Base) PublishingTarget {
		p := &gcp{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})
}

func (*gcp) Type() string {
	return "GCP"
}

type gcp struct {
	nonFusableTarget

	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource

	pubCfg  gcpPublishingConfig
	retrier guard.Retrier

	clientsMtx sync.RWMutex
	clients    gcpClients
	clientsGen atomic.Uint64
}

type gcpClients struct {
	storage          *storage.Client
	images           *compute.ImagesClient
	globalOperations *compute.GlobalOperationsClient
	accessID         string
}

type gcpPublishingConfig struct {
	Source  string `mapstructure:"source"`
	Config  string `mapstructure:"config"`
	Project string `mapstructure:"project"`
	Bucket  string `mapstructure:"bucket"`
}

func (p *gcp) isConfigured() bool {
	clients := p.getClients()

	return clients.storage != nil && clients.images != nil && clients.globalOperations != nil
}

type gcpOperationState struct {
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

	err = p.destroyClients(p.clients)
	if err != nil {
		return fmt.Errorf("cannot destroy existing clients: %w", err)
	}

	tokenSrc := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: creds.Token,
		Expiry:      time.Unix(creds.Expiry, 0),
	})

	p.clients.storage, err = storage.NewClient(ctx, option.WithTokenSource(tokenSrc))
	if err != nil {
		return fmt.Errorf("cannot create storage client: %w", err)
	}

	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("unexpected default transport type")
	}

	t = t.Clone()
	t.ResponseHeaderTimeout = guard.Timeout
	var transport http.RoundTripper
	transport, err = transporthttp.NewTransport(ctx, t, option.WithTokenSource(tokenSrc))
	if err != nil {
		return fmt.Errorf("cannot create compute transport: %w", err)
	}
	c := &http.Client{
		Transport: transport,
	}

	p.clients.images, err = compute.NewImagesRESTClient(ctx, option.WithHTTPClient(c))
	if err != nil {
		return fmt.Errorf("cannot create images client: %w", err)
	}

	p.clients.globalOperations, err = compute.NewGlobalOperationsRESTClient(ctx, option.WithHTTPClient(c))
	if err != nil {
		return fmt.Errorf("cannot create global operations client: %w", err)
	}

	p.clients.accessID = creds.ServiceAccountEmail
	p.clientsGen.Add(1)

	return nil
}

func (p *gcp) getClients() gcpClients {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.clients
}

func (p *gcp) storageClient() (*storage.Client, string) {
	clients := p.getClients()

	return clients.storage, clients.accessID
}

func (p *gcp) imagesClient() *compute.ImagesClient {
	return p.getClients().images
}

func (p *gcp) globalOperationsClient() *compute.GlobalOperationsClient {
	return p.getClients().globalOperations
}

func (*gcp) ImageSuffix() string {
	return ".gcpimage.tar.gz"
}

func (*gcp) imageName(flavor, version, committish string) string {
	flavor = hsh.Hash(fnv.New64(), flavor)
	version = strings.ReplaceAll(version, ".", "-")
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", flavor, version, committish)
}

func (*gcp) architecture(arch gardenlinux.Architecture) (string, error) {
	switch arch {
	case gardenlinux.ArchitectureAMD64:
		return "X86_64", nil
	case gardenlinux.ArchitectureARM64:
		return "ARM64", nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (p *gcp) CanPublish(manifest *gardenlinux.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return manifest.Platform == "gcp"
}

func (p *gcp) IsPublished(manifest *gardenlinux.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	gcpOutput, err := publishingOutputFromManifest[gcpPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return gcpOutput.Project != "" && gcpOutput.Image != "", nil
}

func (p *gcp) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	pl := platform(flavor)
	if pl != "gcp" {
		return nil, fmt.Errorf("invalid flavor %s for target %s", flavor, p.Type())
	}
	if pl != manifest.Platform {
		return nil, fmt.Errorf("flavor %s does not match platform %s", flavor, manifest.Platform)
	}

	image := p.imageName(flavor, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", flavor, err)
	}
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", p.source.Type(), "sourceRepo", p.source.Repository(),
		"project", p.pubCfg.Project)

	var secureBoot bool
	var pk, kek, db string
	secureBoot, pk, kek, db, err = p.prepareSecureBoot(ctx, p.source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "secureBoot", secureBoot)

	ctx = resilience.BeginOperation(ctx, "publish/"+image, &gcpOperationState{})
	var blob, blobURL string
	blob, blobURL, err = p.uploadBlob(ctx, p.source, imagePath.S3Key, image)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot upload blob for image %s: %w", image, err))
	}

	err = p.insertImage(ctx, blobURL, image, arch, secureBoot, pk, kek, db)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot insert image %s from blob %s: %w", image, blob, err))
	}

	err = p.deleteBlob(ctx, blob, false)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot delete blob %s: %w", blob, err))
	}

	err = p.makePublic(ctx, image)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot make image %s public: %w", image, err))
	}
	resilience.CompleteOperation(ctx)

	return &gcpPublishingOutput{
		Project: p.pubCfg.Project,
		Image:   image,
	}, nil
}

func (*gcp) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gardenlinux.Manifest) (bool, string, string, string,
	error,
) {
	var pk, kek, db string

	if manifest.SecureBoot {
		fetchCertificates := concurrency.NewActivity(ctx)

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

	storageClient, accessID := p.storageClient()

	log.Info(ctx, "Uploading blob")
	bucket := storageClient.Bucket(p.pubCfg.Bucket)
	w := bucket.Object(blob).Retryer(storage.WithMaxAttempts(guard.Retries+1), storage.WithBackoff(gax.Backoff{
		Initial: guard.RetryBaseDelay,
		Max:     guard.RetryMaxDelay,
	})).NewWriter(ctx)
	w.ChunkRetryDeadline = guard.Timeout

	_, err = io.Copy(w, obj)
	if err != nil {
		return "", "", fmt.Errorf("cannot copy blob: %w", err)
	}

	err = w.Close()
	if err != nil {
		return "", "", fmt.Errorf("cannot close object writer: %w", err)
	}
	resilience.UpdateOperation(ctx, func(s *gcpOperationState) *gcpOperationState {
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
		GoogleAccessID: accessID,
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
				Type: new("VIRTIO_SCSI_MULTIQUEUE"),
			},
			{
				Type: new("UEFI_COMPATIBLE"),
			},
			{
				Type: new("GVNIC"),
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
					FileType: new("X509"),
				},
			},
			Keks: []*computepb.FileContentBuffer{
				{
					Content:  &kek,
					FileType: new("X509"),
				},
			},
			Pk: &computepb.FileContentBuffer{
				Content:  &pk,
				FileType: new("X509"),
			},
		}
	}

	log.Info(ctx, "Inserting image")
	var op *compute.Operation
	err := p.retrier.Do(ctx, "insert image", func(ctx context.Context) error {
		var inErr error
		op, inErr = p.imagesClient().Insert(ctx, &computepb.InsertImageRequest{
			ImageResource: imageResource,
			Project:       p.pubCfg.Project,
		}, gax.WithRetry(func() gax.Retryer {
			return &countingRetrier{
				retrier: gax.OnHTTPCodes(gax.Backoff{
					Initial:    guard.RetryBaseDelay,
					Max:        guard.RetryMaxDelay,
					Multiplier: 2,
				}, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
					http.StatusGatewayTimeout),
				retries: guard.Retries,
			}
		}))
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot insert image: %w", err)
	}
	resilience.UpdateOperation(ctx, func(s *gcpOperationState) *gcpOperationState {
		s.Image = image
		return s
	})

	err = p.awaitOperation(ctx, "await image insertion", op.Name())
	if err != nil {
		return fmt.Errorf("cannot insert image: %w", err)
	}
	log.Info(ctx, "Image ready")

	return nil
}

func (p *gcp) deleteBlob(ctx context.Context, blob string, steamroll bool) error {
	log.Info(ctx, "Deleting blob")
	err := p.retrier.Do(ctx, "delete blob", func(ctx context.Context) error {
		storageClient, _ := p.storageClient()
		return storageClient.Bucket(p.pubCfg.Bucket).Object(blob).Retryer(storage.WithMaxAttempts(guard.Retries+1),
			storage.WithBackoff(gax.Backoff{
				Initial: guard.RetryBaseDelay,
				Max:     guard.RetryMaxDelay,
			})).Delete(ctx)
	})
	if err != nil {
		terr, ok := errors.AsType[*googleapi.Error](err)
		if steamroll && ok && terr.Code == http.StatusNotFound {
			log.Debug(ctx, "Blob not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete blob %s: %w", blob, err)
	}
	resilience.UpdateOperation(ctx, func(s *gcpOperationState) *gcpOperationState {
		s.Blob = ""
		return s
	})

	return nil
}

func (p *gcp) makePublic(ctx context.Context, image string) error {
	log.Debug(ctx, "Setting IAM policy")
	err := p.retrier.Do(ctx, "set IAM policy", func(ctx context.Context) error {
		_, inErr := p.imagesClient().SetIamPolicy(ctx, &computepb.SetIamPolicyImageRequest{
			GlobalSetPolicyRequestResource: &computepb.GlobalSetPolicyRequest{
				Policy: &computepb.Policy{
					AuditConfigs: nil,
					Bindings: []*computepb.Binding{
						{
							Members: []string{
								"allAuthenticatedUsers",
							},
							Role: new("roles/compute.imageUser"),
						},
					},
					Version: new(int32(3)),
				},
			},
			Project:  p.pubCfg.Project,
			Resource: image,
		}, gax.WithRetry(func() gax.Retryer {
			return &countingRetrier{
				retrier: gax.OnHTTPCodes(gax.Backoff{
					Initial:    guard.RetryBaseDelay,
					Max:        guard.RetryMaxDelay,
					Multiplier: 2,
				}, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
					http.StatusGatewayTimeout),
				retries: guard.Retries,
			}
		}))
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot set IAM policy: %w", err)
	}

	return nil
}

func (*gcp) CanUnpublish() bool {
	return true
}

func (p *gcp) Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error {
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
	log.Info(ctx, "Deleting image")
	var op *compute.Operation
	err := p.retrier.Do(ctx, "delete image", func(ctx context.Context) error {
		var inErr error
		op, inErr = p.imagesClient().Delete(ctx, &computepb.DeleteImageRequest{
			Image:   image,
			Project: p.pubCfg.Project,
		}, gax.WithRetry(func() gax.Retryer {
			return &countingRetrier{
				retrier: gax.OnHTTPCodes(gax.Backoff{
					Initial:    guard.RetryBaseDelay,
					Max:        guard.RetryMaxDelay,
					Multiplier: 2,
				}, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
					http.StatusGatewayTimeout),
				retries: guard.Retries,
			}
		}))
		return inErr
	})
	if err != nil {
		terr, ok := errors.AsType[*googleapi.Error](err)
		if steamroll && ok && terr.Code == http.StatusNotFound {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete image: %w", err)
	}

	err = p.awaitOperation(ctx, "await image deletion", op.Name())
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}

func (p *gcp) awaitOperation(ctx context.Context, operation, op string) error {
	for {
		var o *computepb.Operation
		err := p.retrier.Do(ctx, operation, func(ctx context.Context) error {
			var inErr error
			o, inErr = p.globalOperationsClient().Get(ctx, &computepb.GetGlobalOperationRequest{
				Operation: op,
				Project:   p.pubCfg.Project,
			})
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot get operation status: %w", err)
		}

		if o.GetStatus() == computepb.Operation_DONE {
			code := o.GetHttpErrorStatusCode()
			if code != 0 && (code < 200 || code > 299) {
				return fmt.Errorf("operation failed with status %d: %s", code, o.GetHttpErrorMessage())
			}

			return nil
		}

		time.Sleep(statusPollInterval)
	}
}

func (p *gcp) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "gcp"
}

func (p *gcp) Rollback(ctx context.Context, operations map[string]resilience.Operation) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := concurrency.NewActivity(ctx)
	for _, op := range operations {
		state, err := resilience.ParseOperationState[*gcpOperationState](op.State)
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

func (p *gcp) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.pubCfg)
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

func (*gcp) Configurables() []module.Configurable {
	return nil
}

func (p *gcp) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.pubCfg.Config,
		Role:   "target",
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	return nil
}

func (p *gcp) Stop() error {
	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
			Role:   "target",
		})
	}

	return p.destroyClients(p.getClients())
}

func (*gcp) destroyClients(clients gcpClients) error {
	if clients.storage != nil {
		err := clients.storage.Close()
		if err != nil {
			return fmt.Errorf("cannot close storage client: %w", err)
		}
	}

	if clients.images != nil {
		err := clients.images.Close()
		if err != nil {
			return fmt.Errorf("cannot close images client: %w", err)
		}
	}

	if clients.globalOperations != nil {
		err := clients.globalOperations.Close()
		if err != nil {
			return fmt.Errorf("cannot close global operations client: %w", err)
		}
	}

	return nil
}

type countingRetrier struct {
	retrier gax.Retryer
	retries int
}

func (r *countingRetrier) Retry(err error) (time.Duration, bool) {
	pause, shouldRetry := r.retrier.Retry(err)
	if !shouldRetry || r.retries <= 0 {
		return 0, false
	}
	r.retries--

	return pause, true
}
