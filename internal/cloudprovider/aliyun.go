package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/ecs-20140526/v7/client"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/slc"
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

	if p.pubCfg.Regions != nil {
		if !slices.Contains(*p.pubCfg.Regions, creds.Region) {
			return fmt.Errorf("credentials region %s missing from list of regions", creds.Region)
		}
	}

	p.ossClient = oss.NewClient(oss.LoadDefaultConfig().WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID,
		creds.AccessKeySecret)).WithRegion(creds.Region))

	if p.pubCfg.Regions == nil {
		p.ecsClients = make(map[string]*client.Client)
	} else {
		p.ecsClients = make(map[string]*client.Client, len(*p.pubCfg.Regions))
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

	return aliyunOutput.Images != nil && len(*aliyunOutput.Images) != 0, nil
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

	if aliyunOutput.Images != nil && len(*aliyunOutput.Images) != 0 {
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
	ctx = log.WithValues(ctx, "image", image, "sourceType", source.Type(), "sourceRepo", source.Repository(), "region", region)

	var regions []string
	regions, err = p.listRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list regions: %w", err)
	}
	if p.pubCfg.Regions != nil {
		regions = slc.Subset(regions, *p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no available regions")
	}

	var blob string
	blob, err = p.uploadBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, fmt.Errorf("cannot upload blob for image %s: %w", image, err)
	}

	var imageID string
	imageID, err = p.importImage(ctx, blob, image)
	if err != nil {
		return nil, fmt.Errorf("cannot import image %s from blob %s: %w", image, blob, err)
	}
	ctx = log.WithValues(ctx, "imageID", imageID)

	err = p.deleteBlob(ctx, image)
	if err != nil {
		return nil, fmt.Errorf("cannot delete blob %s: %w", image, err)
	}

	var images map[string]string
	images, err = p.copyImage(ctx, image, imageID, region, regions)
	if err != nil {
		return nil, fmt.Errorf("cannot copy image %s: %w", image, err)
	}

	err = p.waitForImages(ctx, images)
	if err != nil {
		return nil, fmt.Errorf("cannot finalize images: %w", err)
	}

	err = p.makePublic(ctx, images)
	if err != nil {
		return nil, fmt.Errorf("cannot make images public: %w", err)
	}

	outputImages := make([]aliyunPublishedImage, 0, len(images))
	for region, imageID = range images {
		outputImages = append(outputImages, aliyunPublishedImage{
			Region: region,
			ID:     imageID,
			Image:  image,
		})
	}
	return &aliyunPublishingOutput{
		Images: &outputImages,
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
	if pubOut.Images == nil {
		return errors.New("invalid manifest: missing published images")
	}

	for _, img := range *pubOut.Images {
		lctx := log.WithValues(ctx, "image", img.ID, "fromRegion", img.Region)

		err = p.deleteImage(lctx, img.ID, img.Region, steamroll)
		if err != nil {
			return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, err)
		}
	}

	return nil
}

type aliyun struct {
	creds           map[string]aliyunCredentials
	pubCfg          aliyunPublishingConfig
	ossClient       *oss.Client
	ecsClients      map[string]*client.Client
	ecsClientsMutex sync.RWMutex
}

type aliyunCredentials struct {
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	AccessKeySecret string `mapstructure:"access_key_secret"`
}

type aliyunPublishingConfig struct {
	Source  string    `mapstructure:"source"`
	Config  string    `mapstructure:"config"`
	Bucket  string    `mapstructure:"bucket"`
	Regions *[]string `mapstructure:"regions,omitempty"`
}

type aliyunPublishingOutput struct {
	Images *[]aliyunPublishedImage `yaml:"published_alicloud_images,omitempty"`
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
	log.Debug(ctx, "Blob uploaded")

	err = obj.Close()
	if err != nil {
		return "", fmt.Errorf("cannot close blob: %w", err)
	}

	return ossKey, nil
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

func (p *aliyun) importImage(ctx context.Context, blob, image string) (string, error) {
	region := p.creds[p.pubCfg.Config].Region
	ctx = log.WithValues(ctx, "blob", blob)

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

	err = p.waitForImage(ctx, region, imageID)
	if err != nil {
		return "", err
	}
	log.Debug(ctx, "Image ready")

	return imageID, nil
}

func (p *aliyun) deleteBlob(ctx context.Context, image string) error {
	ossKey := image + p.ImageSuffix()
	ctx = log.WithValues(ctx, "bucket", p.pubCfg.Bucket, "ossKey", ossKey)

	log.Info(ctx, "Deleting blob")
	_, err := p.ossClient.DeleteObject(ctx, &oss.DeleteObjectRequest{
		Bucket: &p.pubCfg.Bucket,
		Key:    &ossKey,
	})
	if err != nil {
		return fmt.Errorf("cannot delete object %s in bucket %s: %w", p.pubCfg.Bucket, ossKey, err)
	}

	return nil
}

func (p *aliyun) waitForImage(ctx context.Context, region, imageID string) error {
	var status string
	c, err := p.ecsClient(region)
	if err != nil {
		return err
	}

	for status != "Available" {
		log.Debug(ctx, "Waiting for image", "toRegion", region, "toImageID", imageID)
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("cannot get status of image %s in region %s: %w", imageID, region, err)
		}
		var r *client.DescribeImagesResponse
		r, err = c.DescribeImages(&client.DescribeImagesRequest{
			ImageId:  &imageID,
			RegionId: &region,
		})
		if err != nil {
			return fmt.Errorf("cannot get status of image %s in region %s: %w", imageID, region, err)
		}
		if r.Body == nil {
			return fmt.Errorf("cannot get status of image %s in region %s: missing body", imageID, region)
		}
		if r.Body.Images == nil || len(r.Body.Images.Image) > 1 {
			return fmt.Errorf("cannot get status of image %s in region %s: missing images", imageID, region)
		}
		if len(r.Body.Images.Image) == 1 {
			if r.Body.Images.Image[0] == nil {
				return fmt.Errorf("cannot get status of image %s in region %s: missing image", imageID, region)
			}
			if r.Body.Images.Image[0].Status == nil {
				return fmt.Errorf("cannot get status of image %s in region %s: missing status", imageID, region)
			}
			status = *r.Body.Images.Image[0].Status
		}

		if status != "Available" {
			if status != "" {
				return fmt.Errorf("image %s in region %s has status %s", imageID, region, status)
			}

			time.Sleep(time.Second * 7)
		}
	}

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
		p.ecsClientsMutex.RLock()
		defer p.ecsClientsMutex.RUnlock()
		c, ok = p.ecsClients[region]
	}()
	if !ok {
		p.ecsClientsMutex.Lock()
		defer p.ecsClientsMutex.Unlock()
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

func (p *aliyun) copyImage(ctx context.Context, image, imageID, fromRegion string, toRegions []string) (map[string]string, error) {
	images := make(map[string]string, len(toRegions))

	for _, region := range toRegions {
		if region == fromRegion {
			images[region] = imageID
			continue
		}

		log.Info(ctx, "Copying image", "toRegion", region)
		c, err := p.ecsClient("")
		if err != nil {
			return nil, err
		}
		err = ctx.Err()
		if err != nil {
			return nil, fmt.Errorf("cannot copy image %s to region %s: %w", imageID, region, err)
		}
		var r *client.CopyImageResponse
		r, err = c.CopyImage(&client.CopyImageRequest{
			DestinationImageName: &image,
			DestinationRegionId:  &region,
			ImageId:              &imageID,
			RegionId:             &fromRegion,
		})
		if err != nil {
			return images, fmt.Errorf("cannot copy image %s to region %s: %w", imageID, region, err)
		}
		if r.Body == nil {
			return nil, fmt.Errorf("cannot copy image %s to region %s: missing body", imageID, region)
		}
		if r.Body.ImageId == nil {
			return nil, fmt.Errorf("cannot copy image %s to region %s: missing image ID", imageID, region)
		}
		images[region] = *r.Body.ImageId
	}

	return images, nil
}

func (p *aliyun) waitForImages(ctx context.Context, images map[string]string) error {
	for region, imageID := range images {
		err := p.waitForImage(ctx, region, imageID)
		if err != nil {
			return err
		}
	}
	log.Info(ctx, "Images ready", "count", len(images))

	return nil
}

func (p *aliyun) makePublic(ctx context.Context, images map[string]string) error {
	for region, imageID := range images {
		log.Debug(ctx, "Adding launch permission to image", "toRegion", region, "toImageID", imageID)
		c, err := p.ecsClient(region)
		if err != nil {
			return err
		}
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("cannot modify share permission of image %s in region %s: %w", imageID, region, err)
		}
		_, err = c.ModifyImageSharePermission(&client.ModifyImageSharePermissionRequest{
			ImageId:  &imageID,
			IsPublic: ptr.P(true),
			RegionId: &region,
		})
		if err != nil {
			return fmt.Errorf("cannot modify share permission of image %s in region %s: %w", imageID, region, err)
		}
	}

	return nil
}

func (p *aliyun) deleteImage(ctx context.Context, imageID, region string, steamroll bool) error {
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
		log.Debug(ctx, "Removing launch permission from image")
		err = ctx.Err()
		if err != nil {
			return fmt.Errorf("cannot modify share permission: %w", err)
		}
		_, err = c.ModifyImageSharePermission(&client.ModifyImageSharePermissionRequest{
			ImageId:  &imageID,
			IsPublic: ptr.P(false),
			RegionId: &region,
		})
		if err != nil {
			return fmt.Errorf("cannot modify share permission: %w", err)
		}
	} else if !steamroll {
		return errors.New("image is not public")
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
