package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/slc"
	"github.com/gardenlinux/glci/internal/task"
)

func init() {
	env.Clean("OSS_")

	registerPublishingTarget(func() PublishingTarget {
		return &aliyun{}
	})
}

func (*aliyun) Type() string {
	return "Aliyun"
}

func (p *aliyun) SetCredentials(creds map[string]any) error {
	return setCredentials(creds, "alicloud", &p.creds)
}

func (p *aliyun) SetTargetConfig(_ context.Context, cfg map[string]any, sources map[string]ArtifactSource) error {
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

	var creds aliyunCredentials
	creds, ok = p.creds[p.pubCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.pubCfg.Config)
	}

	if len(p.pubCfg.Regions) > 0 {
		if !slices.Contains(p.pubCfg.Regions, creds.Region) {
			return fmt.Errorf("credentials region %s missing from list of regions", creds.Region)
		}
	}

	p.ossClient = oss.NewClient(oss.LoadDefaultConfig().WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID,
		creds.AccessKeySecret)).WithRegion(creds.Region))

	if len(p.pubCfg.Regions) == 0 {
		p.ecsClients = make(map[string]*client.Client)
	} else {
		p.ecsClients = make(map[string]*client.Client, len(p.pubCfg.Regions))
	}
	p.ecsClients[creds.Region], err = client.NewClient(&utils.Config{
		AccessKeyId:     &creds.AccessKeyID,
		AccessKeySecret: &creds.AccessKeySecret,
		RegionId:        &creds.Region,
	})
	if err != nil {
		return fmt.Errorf("cannot create ecs client: %w", err)
	}

	return nil
}

func (*aliyun) Close() error {
	return nil
}

func (*aliyun) ImageSuffix() string {
	return ".qcow2"
}

func (p *aliyun) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return flavor(manifest.Platform) == "ali"
}

func (p *aliyun) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	aliyunOutput, err := publishingOutputFromManifest[aliyunPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return len(aliyunOutput.Images) != 0, nil
}

func (p *aliyun) AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	aliyunOutput, err := publishingOutput[aliyunPublishingOutput](output)
	if err != nil {
		return nil, err
	}
	var ownOutput aliyunPublishingOutput
	ownOutput, err = publishingOutput[aliyunPublishingOutput](own)
	if err != nil {
		return nil, err
	}

	if len(aliyunOutput.Images) != 0 {
		return nil, errors.New("cannot add publishing output to existing publishing output")
	}

	return &ownOutput, nil
}

func (p *aliyun) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	_, err := publishingOutput[aliyunPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *aliyun) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	f := flavor(cname)
	if f != "ali" {
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
	source := sources[p.pubCfg.Source]
	region := p.creds[p.pubCfg.Config].Region
	ctx = log.WithValues(ctx, "image", image, "sourceType", source.Type(), "sourceRepo", source.Repository())

	var regions []string
	regions, err = p.listRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list regions: %w", err)
	}
	if len(p.pubCfg.Regions) > 0 {
		regions = slc.Subset(regions, p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no available regions")
	}

	ctx = task.Begin(ctx, "publish/"+image+"/"+region, &aliyunTaskState{
		Region: region,
	})
	var blob string
	blob, err = p.uploadBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot upload blob for image %s: %w", image, err))
	}

	var imageID string
	imageID, err = p.importImage(ctx, blob, image)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot import image %s from blob %s: %w", image, blob, err))
	}

	err = p.deleteBlob(ctx, image+p.ImageSuffix(), false)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot delete blob %s: %w", image, err))
	}

	images := make(map[string]string, len(regions))
	for _, toRegion := range regions {
		lctx := log.WithValues(ctx, "region", toRegion)
		localID := imageID

		if toRegion == region {
			lctx = log.WithValues(lctx, "imageID", localID)
		} else {
			lctx = task.Begin(lctx, "publish/"+image+"/"+toRegion, &aliyunTaskState{
				Region: toRegion,
			})
			localID, err = p.copyImage(lctx, image, imageID, region, toRegion)
			if err != nil {
				return nil, task.Fail(lctx, fmt.Errorf("cannot copy image %s from region %s to region %s: %w", image, region, toRegion, err))
			}
			lctx = log.WithValues(lctx, "imageID", localID)

			err = p.waitForImage(lctx, localID, toRegion)
			if err != nil {
				return nil, task.Fail(lctx, fmt.Errorf("cannot finalize image %s in region %s: %w", image, toRegion, err))
			}
		}

		err = p.makePublic(lctx, localID, toRegion, true, false)
		if err != nil {
			return nil, task.Fail(lctx, fmt.Errorf("cannot make image %s in region %s public: %w", image, toRegion, err))
		}
		task.Complete(lctx)

		images[toRegion] = localID
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

func (p *aliyun) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if flavor(manifest.Platform) != "ali" {
		return fmt.Errorf("invalid manifest: invalid platform %s for target %s", manifest.Platform, p.Type())
	}

	pubOut, err := publishingOutputFromManifest[aliyunPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	for _, img := range pubOut.Images {
		lctx := log.WithValues(ctx, "image", img.ID, "fromRegion", img.Region)

		err = p.unpublishAndDeleteImage(lctx, img.ID, img.Region, steamroll)
		if err != nil {
			return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, err)
		}
	}

	return nil
}

func (p *aliyun) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "aliyun"
}

func (p *aliyun) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	for _, t := range tasks {
		state, err := task.ParseState[*aliyunTaskState](t.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}
		lctx := log.WithValues(ctx, "region", state.Region)

		if state.Blob != "" {
			lctx = log.WithValues(lctx, "blob", state.Blob)
			err = p.deleteBlob(lctx, state.Blob, true)
			if err != nil {
				return fmt.Errorf("cannot delete blob %s: %w", state.Blob, err)
			}
		}

		if state.Image != "" {
			lctx = log.WithValues(lctx, "image", state.Image)
			if state.Public {
				err = p.makePublic(ctx, state.Image, state.Region, false, true)
				if err != nil {
					return fmt.Errorf("cannot make image %s in region %s not public: %w", state.Image, state.Region, err)
				}
			}

			err = p.deleteImage(lctx, state.Image, state.Region, true)
			if err != nil {
				return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, err)
			}
		}
	}

	return nil
}

type aliyun struct {
	creds         map[string]aliyunCredentials
	pubCfg        aliyunPublishingConfig
	ossClient     *oss.Client
	ecsClients    map[string]*client.Client
	ecsClientsMtx sync.RWMutex
}

type aliyunCredentials struct {
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret"`
}

type aliyunPublishingConfig struct {
	Source  string   `mapstructure:"source"`
	Config  string   `mapstructure:"config"`
	Bucket  string   `mapstructure:"bucket"`
	Regions []string `mapstructure:"regions,omitempty"`
}

type aliyunTaskState struct {
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

func (p *aliyun) isConfigured() bool {
	return p.ossClient != nil && len(p.ecsClients) != 0
}

func (*aliyun) imageName(cname, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", cname, version, committish)
}

func (p *aliyun) listRegions(ctx context.Context) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	c, err := p.ecsClient("")
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("cannot describe regions: %w", err)
	}
	var r *client.DescribeRegionsResponse
	r, err = c.DescribeRegions(&client.DescribeRegionsRequest{})
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
	_, err = p.ossClient.PutObject(ctx, &oss.PutObjectRequest{
		Bucket: &p.pubCfg.Bucket,
		Key:    &ossKey,
		Body:   obj,
	})
	if err != nil {
		return "", fmt.Errorf("cannot put object %s in bucket %s: %w", ossKey, p.pubCfg.Bucket, err)
	}
	task.Update(ctx, func(s *aliyunTaskState) *aliyunTaskState {
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
	region := p.creds[p.pubCfg.Config].Region
	ctx = log.WithValues(ctx, "blob", blob, "region", region)

	log.Info(ctx, "Importing image")
	c, err := p.ecsClient("")
	if err != nil {
		return "", err
	}
	err = ctx.Err()
	if err != nil {
		return "", fmt.Errorf("cannot import image: %w", err)
	}
	var r *client.ImportImageResponse
	r, err = c.ImportImage(&client.ImportImageRequest{
		DiskDeviceMapping: []*client.ImportImageRequestDiskDeviceMapping{
			{
				DiskImageSize: ptr.P(int32(20)),
				Format:        ptr.P("qcow2"),
				OSSBucket:     &p.pubCfg.Bucket,
				OSSObject:     &blob,
			},
		},
		Features: &client.ImportImageRequestFeatures{
			NvmeSupport: ptr.P("supported"),
		},
		ImageName: &image,
		RegionId:  &region,
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
	task.Update(ctx, func(s *aliyunTaskState) *aliyunTaskState {
		s.Image = imageID
		return s
	})
	ctx = log.WithValues(ctx, "imageID", imageID)

	err = p.waitForImage(ctx, imageID, region)
	if err != nil {
		return "", err
	}
	log.Debug(ctx, "Image ready")

	return imageID, nil
}

func (p *aliyun) deleteBlob(ctx context.Context, blob string, _ bool) error {
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "blob", blob)

	log.Info(ctx, "Deleting blob")
	_, err := p.ossClient.DeleteObject(ctx, &oss.DeleteObjectRequest{
		Bucket: &p.pubCfg.Bucket,
		Key:    &blob,
	})
	if err != nil {
		return fmt.Errorf("cannot delete object %s in bucket %s: %w", blob, p.pubCfg.Bucket, err)
	}
	task.Update(ctx, func(s *aliyunTaskState) *aliyunTaskState {
		s.Blob = ""
		return s
	})

	return nil
}

func (p *aliyun) copyImage(ctx context.Context, image, imageID, region, toRegion string) (string, error) {
	log.Info(ctx, "Copying image")
	c, err := p.ecsClient("")
	if err != nil {
		return "", err
	}
	err = ctx.Err()
	if err != nil {
		return "", fmt.Errorf("cannot copy image: %w", err)
	}
	var r *client.CopyImageResponse
	r, err = c.CopyImage(&client.CopyImageRequest{
		DestinationImageName: &image,
		DestinationRegionId:  &toRegion,
		ImageId:              &imageID,
		RegionId:             &region,
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
	task.Update(ctx, func(s *aliyunTaskState) *aliyunTaskState {
		s.Image = toImageID
		return s
	})

	return toImageID, nil
}

func (p *aliyun) waitForImage(ctx context.Context, imageID, region string) error {
	var status string
	c, err := p.ecsClient(region)
	if err != nil {
		return err
	}

	for status != "Available" {
		log.Debug(ctx, "Waiting for image")
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("cannot describe image: %w", err)
		}
		var r *client.DescribeImagesResponse
		r, err = c.DescribeImages(&client.DescribeImagesRequest{
			ImageId:  &imageID,
			RegionId: &region,
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

			time.Sleep(time.Second * 7)
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
	c, err := p.ecsClient(region)
	if err != nil {
		return err
	}
	err = ctx.Err()
	if err != nil {
		return fmt.Errorf("cannot modify share permission: %w", err)
	}
	_, err = c.ModifyImageSharePermission(&client.ModifyImageSharePermissionRequest{
		ImageId:  &imageID,
		IsPublic: &public,
		RegionId: &region,
	})
	if err != nil {
		var terr *tea.SDKError
		if steamroll && errors.As(err, &terr) {
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
	task.Update(ctx, func(s *aliyunTaskState) *aliyunTaskState {
		s.Public = public
		return s
	})

	return nil
}

func (p *aliyun) ecsClient(region string) (*client.Client, error) {
	mainClient := p.ecsClients[p.creds[p.pubCfg.Config].Region]
	if region == "" || region == *mainClient.RegionId {
		return mainClient, nil
	}

	var c *client.Client
	var ok bool
	func() {
		p.ecsClientsMtx.RLock()
		defer p.ecsClientsMtx.RUnlock()
		c, ok = p.ecsClients[region]
	}()
	if !ok {
		p.ecsClientsMtx.Lock()
		defer p.ecsClientsMtx.Unlock()
		c, ok = p.ecsClients[region]
		if ok {
			return c, nil
		}

		var err error
		c, err = client.NewClient(&utils.Config{
			RegionId:   &region,
			Credential: mainClient.Credential,
		})
		if err != nil {
			return nil, fmt.Errorf("cannot create client for region %s: %w", region, err)
		}

		p.ecsClients[region] = c
	}

	return c, nil
}

func (p *aliyun) unpublishAndDeleteImage(ctx context.Context, imageID, region string, steamroll bool) error {
	c, err := p.ecsClient(region)
	if err != nil {
		return err
	}

	log.Debug(ctx, "Getting image status")
	err = ctx.Err()
	if err != nil {
		return fmt.Errorf("cannot describe image: %w", err)
	}
	var r *client.DescribeImagesResponse
	r, err = c.DescribeImages(&client.DescribeImagesRequest{
		ImageId:  &imageID,
		RegionId: &region,
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
	c, err := p.ecsClient(region)
	if err != nil {
		return err
	}

	log.Info(ctx, "Deleting image")
	err = ctx.Err()
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}
	_, err = c.DeleteImage(&client.DeleteImageRequest{
		ImageId:  &imageID,
		RegionId: &region,
	})
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}
