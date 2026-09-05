package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	osscredentials "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/retry"
	"github.com/aliyun/credentials-go/credentials"
	"github.com/aliyun/credentials-go/credentials/providers"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("OSS_")
	env.Clean("ALIBABA_")

	module.RegisterImpl(PublishingTargetCategory, "Aliyun", func(b *module.Base) PublishingTarget {
		p := &aliyun{
			base: b,
		}
		p.world.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.world.credsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})
		p.world.ecsRetrier = guard.NewRetrier(guard.CountingRetryPolicy{}, guard.DelegatingTimeoutPolicy{})
		return p
	})
}

func (*aliyun) Type() string {
	return "Aliyun"
}

type aliyun struct {
	nonFusableTarget
	noReplicationsTarget

	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource

	pubCfg aliyunPublishingConfig

	world aliyunEnvironment
}

type aliyunEnvironment struct {
	credentialsProvider aliyunCredentialsProvider
	credsGen            atomic.Uint64
	retrier             guard.Retrier
	ecsRetrier          guard.Retrier
	ossClient           *oss.Client
	ecsClients          map[string]*client.Client
}

type aliyunPublishingConfig struct {
	Source  string   `mapstructure:"source"`
	Config  string   `mapstructure:"config"`
	Region  string   `mapstructure:"region"`
	Regions []string `mapstructure:"regions,omitempty"`
	Bucket  string   `mapstructure:"bucket"`
}

func (p *aliyun) isConfigured() bool {
	environment := p.environment()

	return environment.ossClient != nil && len(environment.ecsClients) > 0
}

type aliyunOperationState struct {
	Region string `json:"region,omitzero"`
	Blob   string `json:"blob,omitzero"`
	Image  string `json:"image,omitzero"`
	Public bool   `json:"public,omitzero"`
}

type aliyunPublishingOutput struct {
	Images []aliyunPublishedImage `yaml:"published_alicloud_images,omitempty"`
}

type aliyunPublishedImage struct {
	Region string `yaml:"region_id"`
	ID     string `yaml:"image_id"`
	Image  string `yaml:"image_name"`
}

type aliyunCredentials struct {
	AccessKey     string `mapstructure:"access_key"`
	SecretKey     string `mapstructure:"secret_key"`
	SecurityToken string `mapstructure:"security_token"`
}

type aliyunCredentialsProvider struct {
	credentials atomic.Pointer[aliyunCredentials]
}

func (p *aliyunCredentialsProvider) GetCredentials(_ context.Context) (osscredentials.Credentials, error) {
	creds := p.credentials.Load()
	if creds == nil {
		return osscredentials.Credentials{}, errors.New("credentials not set")
	}

	return osscredentials.Credentials{
		AccessKeyID:     creds.AccessKey,
		AccessKeySecret: creds.SecretKey,
		SecurityToken:   creds.SecurityToken,
	}, nil
}

type aliyunECSCredentialsProvider struct {
	provider *aliyunCredentialsProvider
}

func (p aliyunECSCredentialsProvider) GetCredentials() (*providers.Credentials, error) {
	creds, err := p.provider.GetCredentials(context.Background())
	if err != nil {
		return nil, err
	}

	return &providers.Credentials{
		AccessKeyId:     creds.AccessKeyID,
		AccessKeySecret: creds.AccessKeySecret,
		SecurityToken:   creds.SecurityToken,
		ProviderName:    "GL",
	}, nil
}

func (aliyunECSCredentialsProvider) GetProviderName() string {
	return "GL"
}

func (p *aliyun) applyCredentials(ctx context.Context, rawCreds map[string]any) error {
	var creds aliyunCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	environment := p.environment()
	environment.credentialsProvider.credentials.Store(&creds)
	environment.credsGen.Add(1)

	if environment.ossClient != nil && len(environment.ecsClients) > 0 {
		return nil
	}

	ossClient := oss.NewClient(oss.LoadDefaultConfig().WithCredentialsProvider(&environment.credentialsProvider).
		WithRegion(p.pubCfg.Region).WithConnectTimeout(guard.Timeout).WithReadWriteTimeout(guard.Timeout).
		WithRetryer(retry.NewStandard(func(o *retry.RetryOptions) {
			o.MaxAttempts = guard.Retries + 1
			o.MaxBackoff = guard.RetryMaxDelay
			o.BaseDelay = guard.RetryBaseDelay
		})))

	ecsCredential := credentials.FromCredentialsProvider("sts", aliyunECSCredentialsProvider{
		provider: &environment.credentialsProvider,
	})

	var ecsClient *client.Client
	ecsClient, err = client.NewClient(&utils.Config{
		RegionId:   &p.pubCfg.Region,
		Credential: ecsCredential,
	})
	if err != nil {
		return fmt.Errorf("cannot create ecs client: %w", err)
	}

	var regions []string
	regions, err = p.listRegions(ctx, guard.NewRetrier(guard.CountingRetryPolicy{}, guard.DelegatingTimeoutPolicy{}), ecsClient)
	if err != nil {
		return fmt.Errorf("cannot list regions: %w", err)
	}
	if len(p.pubCfg.Regions) > 0 {
		regions = subset(regions, p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return errors.New("no available regions")
	}
	if !slices.Contains(regions, p.pubCfg.Region) {
		return fmt.Errorf("region %s is not available", p.pubCfg.Region)
	}

	ecsClients := make(map[string]*client.Client, len(regions))
	for _, region := range regions {
		if region == p.pubCfg.Region {
			ecsClients[region] = ecsClient
			continue
		}

		ecsClients[region], err = client.NewClient(&utils.Config{
			RegionId:   &region,
			Credential: ecsCredential,
		})
		if err != nil {
			return fmt.Errorf("cannot create client for region %s: %w", region, err)
		}
	}

	environment.ossClient = ossClient
	environment.ecsClients = ecsClients

	return nil
}

func (*aliyun) listRegions(ctx context.Context, retrier guard.Retrier, c *client.Client) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	var r *client.DescribeRegionsResponse
	err := retrier.Do(ctx, "describe regions", func(_ context.Context) error {
		var inErr error
		r, inErr = c.DescribeRegionsWithOptions(&client.DescribeRegionsRequest{}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		return nil, fmt.Errorf("cannot describe regions: %w", err)
	}
	if r.Body == nil {
		return nil, errors.New("cannot describe regions: missing body")
	}
	if r.Body.Regions == nil {
		return nil, errors.New("cannot describe regions: missing regions")
	}

	regions := make([]string, 0, len(r.Body.Regions.Region))
	for _, region := range r.Body.Regions.Region {
		if region == nil {
			return nil, errors.New("cannot describe regions: missing region")
		}
		if region.RegionId == nil {
			return nil, errors.New("cannot describe regions: missing region ID")
		}
		regions = append(regions, *region.RegionId)
	}

	return regions, nil
}

func (p *aliyun) environment() *aliyunEnvironment {
	return &p.world
}

func (*aliyun) ImageSuffix() string {
	return ".qcow2"
}

func (*aliyun) imageName(flavor, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", flavor, version, committish)
}

func (*aliyun) CanPublish(manifest *gardenlinux.Manifest) bool {
	return manifest.Platform == "ali"
}

func (p *aliyun) IsPublished(manifest *gardenlinux.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	aliyunOutput, err := publishingOutputFromManifest[aliyunPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return len(aliyunOutput.Images) > 0, nil
}

func (p *aliyun) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	pl := platform(flavor)
	if pl != "ali" {
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
	region := p.pubCfg.Region
	ctx = log.WithValues(ctx, "image", image, "source", p.pubCfg.Source)

	ctx = resilience.BeginOperation(ctx, "publish/"+image+"/"+region, &aliyunOperationState{
		Region: region,
	})
	var blob string
	blob, err = p.uploadBlob(ctx, p.source, imagePath.S3Key, image)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot upload blob for image %s: %w", image, err))
	}

	var imageID string
	imageID, err = p.importImage(ctx, blob, image)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot import image %s from blob %s: %w", image, blob, err))
	}

	err = p.deleteBlob(ctx, image+p.ImageSuffix(), false)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot delete blob %s: %w", image, err))
	}

	ecsClients := p.environment().ecsClients
	images := make(map[string]string, len(ecsClients))
	publishImages := concurrency.NewActivitySync(ctx)
	for toRegion := range ecsClients {
		publishImages.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			ctx = log.WithValues(ctx, "region", toRegion)
			localID := imageID
			var inErr error

			if toRegion == region {
				ctx = log.WithValues(ctx, "imageID", localID)
			} else {
				ctx = resilience.BeginOperation(ctx, "publish/"+image+"/"+toRegion, &aliyunOperationState{
					Region: toRegion,
				})
				localID, inErr = p.copyImage(ctx, image, imageID, region, toRegion)
				if inErr != nil {
					return nil, resilience.FailOperation(ctx,
						fmt.Errorf("cannot copy image %s from region %s to region %s: %w", image, region, toRegion, inErr))
				}
				ctx = log.WithValues(ctx, "imageID", localID)

				inErr = p.waitForImage(ctx, localID, toRegion)
				if inErr != nil {
					return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", image, toRegion,
						inErr))
				}
			}

			inErr = p.makePublic(ctx, localID, toRegion, true, false)
			if inErr != nil {
				return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot make image %s in region %s public: %w", image, toRegion,
					inErr))
			}
			resilience.CompleteOperation(ctx)

			return func() error {
				images[toRegion] = localID

				return nil
			}, nil
		})
	}
	err = publishImages.Wait()
	if err != nil {
		return nil, err
	}
	log.Info(ctx, "Images ready", "count", len(images))

	outputImages := make([]aliyunPublishedImage, 0, len(images))
	for region, imageID = range images {
		outputImages = append(outputImages, aliyunPublishedImage{
			Region: region,
			ID:     imageID,
			Image:  image,
		})
	}
	return &aliyunPublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *aliyun) uploadBlob(ctx context.Context, source ArtifactSource, key, image string) (string, error) {
	ossKey := image + p.ImageSuffix()
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "key", key, "ossKey", ossKey)

	obj, err := source.GetObject(ctx, key)
	if err != nil {
		return "", fmt.Errorf("cannot get blob: %w", err)
	}
	defer func() {
		_ = obj.Close()
	}()

	log.Info(ctx, "Uploading blob")
	err = p.environment().retrier.Do(ctx, "put object", func(ctx context.Context) error {
		_, inErr := p.environment().ossClient.PutObject(ctx, &oss.PutObjectRequest{
			Bucket: &p.pubCfg.Bucket,
			Key:    &ossKey,
			Body:   obj,
		})
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot put object %s in bucket %s: %w", ossKey, p.pubCfg.Bucket, err)
	}
	resilience.UpdateOperation(ctx, func(s *aliyunOperationState) *aliyunOperationState {
		s.Blob = ossKey
		return s
	})
	log.Debug(ctx, "Blob uploaded")

	err = obj.Close()
	if err != nil {
		return "", fmt.Errorf("cannot close blob: %w", err)
	}

	return ossKey, nil
}

func (p *aliyun) importImage(ctx context.Context, blob, image string) (string, error) {
	ctx = log.WithValues(ctx, "blob", blob, "region", p.pubCfg.Region)

	log.Info(ctx, "Importing image")
	var r *client.ImportImageResponse
	err := p.environment().ecsRetrier.Do(ctx, "import image", func(_ context.Context) error {
		var inErr error
		r, inErr = p.environment().ecsClients[p.pubCfg.Region].ImportImageWithOptions(&client.ImportImageRequest{
			DiskDeviceMapping: []*client.ImportImageRequestDiskDeviceMapping{
				{
					DiskImageSize: new(int32(20)),
					Format:        new("qcow2"),
					OSSBucket:     &p.pubCfg.Bucket,
					OSSObject:     &blob,
				},
			},
			Features: &client.ImportImageRequestFeatures{
				NvmeSupport: new("supported"),
			},
			ImageName: &image,
			RegionId:  &p.pubCfg.Region,
		}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot import image: %w", err)
	}
	if r.Body == nil {
		return "", errors.New("cannot import image: missing body")
	}
	if r.Body.ImageId == nil {
		return "", errors.New("cannot import image: missing image ID")
	}
	imageID := *r.Body.ImageId
	resilience.UpdateOperation(ctx, func(s *aliyunOperationState) *aliyunOperationState {
		s.Image = imageID
		return s
	})
	ctx = log.WithValues(ctx, "imageID", imageID)

	err = p.waitForImage(ctx, imageID, p.pubCfg.Region)
	if err != nil {
		return "", err
	}
	log.Debug(ctx, "Image ready")

	return imageID, nil
}

func (p *aliyun) deleteBlob(ctx context.Context, blob string, _ bool) error {
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "blob", blob)

	log.Info(ctx, "Deleting blob")
	err := p.environment().retrier.Do(ctx, "delete object", func(ctx context.Context) error {
		_, inErr := p.environment().ossClient.DeleteObject(ctx, &oss.DeleteObjectRequest{
			Bucket: &p.pubCfg.Bucket,
			Key:    &blob,
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot delete object %s in bucket %s: %w", blob, p.pubCfg.Bucket, err)
	}
	resilience.UpdateOperation(ctx, func(s *aliyunOperationState) *aliyunOperationState {
		s.Blob = ""
		return s
	})

	return nil
}

func (p *aliyun) copyImage(ctx context.Context, image, imageID, region, toRegion string) (string, error) {
	log.Info(ctx, "Copying image")
	var r *client.CopyImageResponse
	err := p.environment().ecsRetrier.Do(ctx, "copy image", func(_ context.Context) error {
		var inErr error
		r, inErr = p.environment().ecsClients[region].CopyImageWithOptions(&client.CopyImageRequest{
			DestinationImageName: &image,
			DestinationRegionId:  &toRegion,
			ImageId:              &imageID,
			RegionId:             &region,
		}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot copy image: %w", err)
	}
	if r.Body == nil {
		return "", errors.New("cannot copy image: missing body")
	}
	if r.Body.ImageId == nil {
		return "", errors.New("cannot copy image: missing image ID")
	}
	toImageID := *r.Body.ImageId
	resilience.UpdateOperation(ctx, func(s *aliyunOperationState) *aliyunOperationState {
		s.Image = toImageID
		return s
	})

	return toImageID, nil
}

func (p *aliyun) waitForImage(ctx context.Context, imageID, region string) error {
	var status string
	for status != "Available" {
		var r *client.DescribeImagesResponse
		err := p.environment().ecsRetrier.Do(ctx, "describe images", func(_ context.Context) error {
			var inErr error
			r, inErr = p.environment().ecsClients[region].DescribeImagesWithOptions(&client.DescribeImagesRequest{
				ImageId:  &imageID,
				RegionId: &region,
			}, &dara.RuntimeOptions{
				Autoretry:      new(false),
				MaxAttempts:    new(1),
				ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
				ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
			})
			return inErr
		})
		if err != nil {
			return fmt.Errorf("cannot describe image: %w", err)
		}
		if r.Body == nil {
			return errors.New("cannot describe image: missing body")
		}
		if r.Body.Images == nil || len(r.Body.Images.Image) > 1 {
			return errors.New("cannot describe image: missing images")
		}
		if len(r.Body.Images.Image) == 1 {
			if r.Body.Images.Image[0] == nil {
				return errors.New("cannot describe image: missing image")
			}
			if r.Body.Images.Image[0].Status == nil {
				return errors.New("cannot describe image: missing status")
			}
			status = *r.Body.Images.Image[0].Status
		}

		if status != "Available" {
			if status != "" {
				return fmt.Errorf("image has status %s", status)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()

			case <-time.After(statusPollInterval):
			}
		}
	}

	return nil
}

func (p *aliyun) makePublic(ctx context.Context, imageID, region string, public, steamroll bool) error {
	if public {
		log.Debug(ctx, "Adding share permission to image")
	} else {
		log.Debug(ctx, "Removing share permission from image")
	}
	err := p.environment().ecsRetrier.Do(ctx, "modify image share permission", func(_ context.Context) error {
		_, inErr := p.environment().ecsClients[region].ModifyImageSharePermissionWithOptions(&client.ModifyImageSharePermissionRequest{
			ImageId:  &imageID,
			IsPublic: &public,
			RegionId: &region,
		}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		terr, ok := errors.AsType[*tea.SDKError](err)
		if steamroll && ok {
			if terr.StatusCode != nil && *terr.StatusCode == http.StatusNotFound {
				log.Debug(ctx, "Image not found but the steamroller keeps going")
				return nil
			}
			if terr.Code != nil && *terr.Code == "Image.NotPublic" {
				log.Debug(ctx, "Image not public but the steamroller keeps going")
				return nil
			}
		}
		return fmt.Errorf("cannot modify share permission: %w", err)
	}
	resilience.UpdateOperation(ctx, func(s *aliyunOperationState) *aliyunOperationState {
		s.Public = public
		return s
	})

	return nil
}

func (*aliyun) CanUnpublish() bool {
	return true
}

func (p *aliyun) Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if manifest.Platform != "ali" {
		return fmt.Errorf("invalid manifest: invalid platform %s for target %s", manifest.Platform, p.Type())
	}

	pubOut, err := publishingOutputFromManifest[aliyunPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	removeImages := concurrency.NewActivity(ctx)
	for _, img := range pubOut.Images {
		removeImages.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "image", img.ID, "region", img.Region)

			inErr := p.unpublishAndDeleteImage(ctx, img.ID, img.Region, steamroll)
			if inErr != nil {
				return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, inErr)
			}

			return nil
		})
	}
	return removeImages.Wait()
}

func (p *aliyun) unpublishAndDeleteImage(ctx context.Context, imageID, region string, steamroll bool) error {
	log.Debug(ctx, "Getting image status")
	var r *client.DescribeImagesResponse
	err := p.environment().ecsRetrier.Do(ctx, "describe images", func(_ context.Context) error {
		var inErr error
		r, inErr = p.environment().ecsClients[region].DescribeImagesWithOptions(&client.DescribeImagesRequest{
			ImageId:  &imageID,
			RegionId: &region,
		}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot describe image: %w", err)
	}
	if r.Body == nil {
		return errors.New("cannot describe image: missing body")
	}
	if r.Body.Images == nil || r.Body.Images.Image == nil || len(r.Body.Images.Image) > 1 {
		return errors.New("cannot describe image: missing images")
	}
	if len(r.Body.Images.Image) != 1 {
		if steamroll {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return errors.New("cannot describe image: image not found")
	}
	if r.Body.Images.Image[0] == nil {
		return errors.New("cannot describe image: missing image")
	}
	if r.Body.Images.Image[0].IsPublic == nil {
		return errors.New("cannot describe image: missing status")
	}
	isPublic := *r.Body.Images.Image[0].IsPublic

	if isPublic {
		err = p.makePublic(ctx, imageID, region, false, steamroll)
		if err != nil {
			return fmt.Errorf("cannot make image not public: %w", err)
		}
	} else if !steamroll {
		return errors.New("image is not public")
	}

	err = p.deleteImage(ctx, imageID, region, steamroll)
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}

func (p *aliyun) deleteImage(ctx context.Context, imageID, region string, _ bool) error {
	log.Info(ctx, "Deleting image")
	err := p.environment().ecsRetrier.Do(ctx, "delete image", func(_ context.Context) error {
		_, inErr := p.environment().ecsClients[region].DeleteImageWithOptions(&client.DeleteImageRequest{
			ImageId:  &imageID,
			RegionId: &region,
		}, &dara.RuntimeOptions{
			Autoretry:      new(false),
			MaxAttempts:    new(1),
			ConnectTimeout: new(int(guard.Timeout / time.Millisecond)),
			ReadTimeout:    new(int(guard.Timeout / time.Millisecond)),
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}

func (p *aliyun) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "aliyun"
}

func (p *aliyun) Rollback(ctx context.Context, operations map[string]resilience.Operation) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := concurrency.NewActivity(ctx)
	for _, op := range operations {
		state, err := resilience.ParseOperationState[*aliyunOperationState](op.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}

		if state.Blob != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "blob", state.Blob)

				inErr := p.deleteBlob(ctx, state.Blob, true)
				if inErr != nil {
					return fmt.Errorf("cannot delete blob %s: %w", state.Blob, inErr)
				}

				return nil
			})
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "image", state.Image)

				if state.Public {
					inErr := p.makePublic(ctx, state.Image, state.Region, false, true)
					if inErr != nil {
						return fmt.Errorf("cannot make image %s in region %s not public: %w", state.Image, state.Region, inErr)
					}
				}

				inErr := p.deleteImage(ctx, state.Image, state.Region, true)
				if inErr != nil {
					return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, inErr)
				}

				return nil
			})
		}
	}
	return rollbackTasks.Wait()
}

func (p *aliyun) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.pubCfg)
	if err != nil {
		return err
	}

	switch {
	case p.pubCfg.Source == "":
		return errors.New("missing source")
	case p.pubCfg.Config == "":
		return errors.New("missing config")
	case p.pubCfg.Region == "":
		return errors.New("missing region")
	case p.pubCfg.Bucket == "":
		return errors.New("missing bucket")
	}

	if len(p.pubCfg.Regions) > 0 {
		if !slices.Contains(p.pubCfg.Regions, p.pubCfg.Region) {
			return fmt.Errorf("region %s missing from list of regions", p.pubCfg.Region)
		}
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

func (*aliyun) Configurables() []module.Configurable {
	return nil
}

func (p *aliyun) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.pubCfg.Config,
		Role:   "target",
	}, p.applyCredentials)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	return nil
}

func (p *aliyun) Stop(ctx context.Context) error {
	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
			Role:   "target",
		})
	}

	return nil
}
