package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/slc"
)

func init() {
	env.Clean("AWS_")
	env.Clean("_X_AMZN_")

	registerArtifactSource(func() ArtifactSource {
		return &aws{}
	})

	registerPublishingTarget(func() PublishingTarget {
		return &aws{}
	})
}

func (*aws) Type() string {
	return "AWS"
}

func (p *aws) SetCredentials(creds map[string]any) error {
	return setCredentials(creds, "aws", &p.creds)
}

func (p *aws) SetSourceConfig(ctx context.Context, cfg map[string]any) error {
	err := setConfig(cfg, &p.srcCfg)
	if err != nil {
		return err
	}

	if p.creds == nil {
		return errors.New("credentials not set")
	}
	creds, ok := p.creds[p.srcCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.srcCfg.Config)
	}

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(creds.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")))
	if err != nil {
		return fmt.Errorf("cannot load default aws config: %w", err)
	}
	p.srcS3Client = s3.NewFromConfig(awsCfg)

	return nil
}

func (p *aws) SetTargetConfig(ctx context.Context, cfg map[string]any, sources map[string]ArtifactSource) error {
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

	var creds awsCredentials
	creds, ok = p.creds[p.pubCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.pubCfg.Config)
	}

	if strings.HasPrefix(creds.Region, "cn-") {
		p.pubCfg.china = true
	}

	if p.pubCfg.Regions != nil {
		if !slices.Contains(*p.pubCfg.Regions, creds.Region) {
			return fmt.Errorf("credentials region %s missing from list of regions", creds.Region)
		}
	}

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(creds.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")))
	if err != nil {
		return fmt.Errorf("cannot load default AWS config: %w", err)
	}
	p.tgtEC2Client = ec2.NewFromConfig(awsCfg)

	return nil
}

func (*aws) Close() error {
	return nil
}

func (p *aws) Repository() string {
	return p.srcCfg.Bucket
}

func (p *aws) GetObjectURL(ctx context.Context, key string) (string, error) {
	srcPresignClient := s3.NewPresignClient(p.srcS3Client, func(o *s3.PresignOptions) {
		o.Expires = time.Hour * 7
	})
	presigned, err := srcPresignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.srcCfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		return "", fmt.Errorf("cannot get presigned URL: %w", err)
	}

	return presigned.URL, nil
}

func (p *aws) GetObjectSize(ctx context.Context, key string) (int64, error) {
	if p.srcS3Client == nil {
		return 0, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Heading object", "bucket", p.srcCfg.Bucket, "key", key)
	r, err := p.srcS3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &p.srcCfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		var noSuchKey *s3types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			err = KeyNotFoundError{
				err: err,
			}
		}

		return 0, fmt.Errorf("cannot head object %s from bucket %s: %w", key, p.srcCfg.Bucket, err)
	}
	if r.ContentLength == nil {
		return 0, fmt.Errorf("cannot head object %s from bucket %s: missing content length", key, p.srcCfg.Bucket)
	}

	return *r.ContentLength, nil
}

func (p *aws) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if p.srcS3Client == nil {
		return nil, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Getting object", "bucket", p.srcCfg.Bucket, "key", key)
	r, err := p.srcS3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.srcCfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		var noSuchKey *s3types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			err = KeyNotFoundError{
				err: err,
			}
		}

		return nil, fmt.Errorf("cannot get object %s from bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return r.Body, nil
}

func (p *aws) PutObject(ctx context.Context, key string, object io.Reader) error {
	if p.srcS3Client == nil {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Putting object", "bucket", p.srcCfg.Bucket, "key", key)
	_, err := p.srcS3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &p.srcCfg.Bucket,
		Key:             &key,
		Body:            object,
		ContentEncoding: ptr.P("utf-8"),
		ContentType:     ptr.P("text/yaml"),
	})
	if err != nil {
		return fmt.Errorf("cannot put object %s to bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return nil
}

func (*aws) ImageSuffix() string {
	return ".raw"
}

func (p *aws) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	awsOutput, err := publishingOutputFromManifest[awsPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	cld := p.cloud()

	if awsOutput.Images == nil {
		return false, nil
	}

	for _, img := range *awsOutput.Images {
		if img.Cloud == cld {
			return true, nil
		}
	}

	return false, nil
}

func (p *aws) AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	awsOutput, err := publishingOutput[awsPublishingOutput](output)
	if err != nil {
		return nil, err
	}
	var ownOutput awsPublishingOutput
	ownOutput, err = publishingOutput[awsPublishingOutput](own)
	if err != nil {
		return nil, err
	}

	cld := p.cloud()

	if ownOutput.Images == nil {
		ownOutput.Images = &[]awsPublishedImage{}
	}
	for _, img := range *ownOutput.Images {
		if img.Cloud != cld {
			return nil, errors.New("new publishing output has extraneous entries")
		}
	}

	if awsOutput.Images == nil {
		return &ownOutput, nil
	}
	for _, img := range *awsOutput.Images {
		if img.Cloud == cld {
			return nil, errors.New("cannot add publishing output to existing publishing output")
		}
	}

	ownOutput.Images = ptr.P(slices.Concat(*awsOutput.Images, *ownOutput.Images))
	return &ownOutput, nil
}

func (p *aws) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	awsOutput, err := publishingOutput[awsPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	cld := p.cloud()

	var otherImages []awsPublishedImage
	if awsOutput.Images != nil {
		for _, img := range *awsOutput.Images {
			if img.Cloud != cld {
				otherImages = append(otherImages, img)
			}
		}
	}
	if len(otherImages) == 0 {
		return nil, nil
	}

	return &awsPublishingOutput{
		Images: &otherImages,
	}, nil
}

func (p *aws) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput, error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "target", p.Type())

	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var arch ec2types.ArchitectureValues
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	region := p.creds[p.pubCfg.Config].Region
	tags := p.prepareTags(manifest)
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", source.Type(), "sourceRepo", source.Repository(),
		"region", region)

	var requireUEFI, secureBoot bool
	var uefiData *string
	requireUEFI, secureBoot, uefiData, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

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

	var snapshot string
	snapshot, err = p.importSnapshot(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, fmt.Errorf("cannot import snapshot for image %s: %w", image, err)
	}
	ctx = log.WithValues(ctx, "snapshot", snapshot)

	err = p.attachTags(ctx, snapshot, tags)
	if err != nil {
		return nil, fmt.Errorf("cannot attach tags to snapshot %s: %w", snapshot, err)
	}

	var imageID string
	imageID, err = p.registerImage(ctx, snapshot, image, arch, requireUEFI, uefiData)
	if err != nil {
		return nil, fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err)
	}
	ctx = log.WithValues(ctx, "imageID", imageID)

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

	outputImages := make([]awsPublishedImage, 0, len(images))
	for region, imageID = range images {
		outputImages = append(outputImages, awsPublishedImage{
			Cloud:  p.cloud(),
			Region: region,
			ID:     imageID,
			Image:  image,
		})
	}

	return &awsPublishingOutput{
		Images: &outputImages,
	}, nil
}

func (p *aws) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "target", p.Type())

	pubOut, err := publishingOutputFromManifest[awsPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if pubOut.Images == nil {
		return errors.New("invalid manifest: missing published images")
	}

	cld := p.cloud()
	ctx = log.WithValues(ctx, "cloud", cld)

	for _, img := range *pubOut.Images {
		if img.Cloud != cld {
			continue
		}
		lctx := log.WithValues(ctx, "region", img.Region, "id", img.ID, "image", img.Image)

		err = p.deregisterImage(lctx, img.ID, img.Region)
		if err != nil {
			return fmt.Errorf("cannot deregister image %s in region %s: %w", img.Image, img.Region, err)
		}
	}

	return nil
}

type aws struct {
	creds        map[string]awsCredentials
	srcCfg       awsSourceConfig
	pubCfg       awsPublishingConfig
	srcS3Client  *s3.Client
	tgtEC2Client *ec2.Client
}

type awsCredentials struct {
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
}

type awsSourceConfig struct {
	Config string `mapstructure:"config"`
	Bucket string `mapstructure:"bucket"`
}

type awsPublishingConfig struct {
	Source    string        `mapstructure:"source"`
	Config    string        `mapstructure:"config"`
	Regions   *[]string     `mapstructure:"regions,omitempty"`
	ImageTags *awsImageTags `mapstructure:"image_tags,omitempty"`
	china     bool
}

type awsImageTags struct {
	IncludeGardenLinuxVersion    *bool              `mapstructure:"include_gardenlinux_version,omitempty"`
	IncludeGardenLinuxCommittish *bool              `mapstructure:"include_gardenlinux_committish,omitempty"`
	StaticTags                   *map[string]string `mapstructure:"static_tags,omitempty"`
}

type awsPublishingOutput struct {
	Images *[]awsPublishedImage `yaml:"published_aws_images,omitempty"`
}

type awsPublishedImage struct {
	Cloud  string `yaml:"cloud"`
	Region string `yaml:"aws_region_id"`
	ID     string `yaml:"ami_id"`
	Image  string `yaml:"image_name"`
}

func (p *aws) isConfigured() bool {
	return p.tgtEC2Client != nil
}

func (p *aws) cloud() string {
	if p.pubCfg.china {
		return "China"
	}

	return "public"
}

func (*aws) imageName(cname, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", cname, version, committish)
}

func (*aws) architecture(arch gl.Architecture) (ec2types.ArchitectureValues, error) {
	switch arch {
	case gl.ArchitectureAMD64:
		return ec2types.ArchitectureValuesX8664, nil
	case gl.ArchitectureARM64:
		return ec2types.ArchitectureValuesArm64, nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (p *aws) prepareTags(manifest *gl.Manifest) []ec2types.Tag {
	var tags []ec2types.Tag

	tagsLen := 2
	if p.pubCfg.ImageTags != nil && p.pubCfg.ImageTags.StaticTags != nil {
		tagsLen += len(*p.pubCfg.ImageTags.StaticTags)
	}

	if p.pubCfg.ImageTags != nil {
		tags = make([]ec2types.Tag, 0, tagsLen)
		if p.pubCfg.ImageTags.StaticTags != nil {
			for k, v := range *p.pubCfg.ImageTags.StaticTags {
				tags = append(tags, ec2types.Tag{
					Key:   &k,
					Value: &v,
				})
			}
		}

		if p.pubCfg.ImageTags.IncludeGardenLinuxVersion != nil && *p.pubCfg.ImageTags.IncludeGardenLinuxVersion {
			tags = append(tags, ec2types.Tag{
				Key:   ptr.P("gardenlinux-version"),
				Value: &manifest.Version,
			})
		}

		if p.pubCfg.ImageTags.IncludeGardenLinuxCommittish != nil && *p.pubCfg.ImageTags.IncludeGardenLinuxCommittish {
			tags = append(tags, ec2types.Tag{
				Key:   ptr.P("gardenlinux-committish"),
				Value: &manifest.BuildCommittish,
			})
		}
	}

	return tags
}

func (*aws) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gl.Manifest) (bool, bool, *string, error) {
	requireUEFI := manifest.RequireUEFI != nil && *manifest.RequireUEFI
	secureBoot := manifest.SecureBoot != nil && *manifest.SecureBoot
	var uefiData *string

	if secureBoot {
		efivarsFile, err := manifest.PathBySuffix(".secureboot.aws-efivars")
		if err != nil {
			return false, false, nil, fmt.Errorf("missing efivars: %w", err)
		}

		var efivars []byte
		efivars, err = getObjectBytes(ctx, source, efivarsFile.S3Key)
		if err != nil {
			return false, false, nil, fmt.Errorf("cannot get efivars: %w", err)
		}

		uefiData = ptr.P(string(efivars))
	}

	return requireUEFI, secureBoot, uefiData, nil
}

func (p *aws) listRegions(ctx context.Context) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	r, err := p.tgtEC2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("cannot describe regions: %w", err)
	}

	regions := make([]string, 0, len(r.Regions))
	for _, region := range r.Regions {
		if region.RegionName == nil {
			return nil, errors.New("cannot describe regions: missing region name")
		}
		regions = append(regions, *region.RegionName)
	}

	return regions, nil
}

func (p *aws) importSnapshot(ctx context.Context, source ArtifactSource, key, image string) (string, error) {
	bucket := source.Repository()
	ctx = log.WithValues(ctx, "key", key)

	log.Info(ctx, "Importing snapshot")
	r, err := p.tgtEC2Client.ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
		DiskContainer: &ec2types.SnapshotDiskContainer{
			Description: &image,
			Format:      ptr.P("raw"),
			UserBucket: &ec2types.UserBucket{
				S3Bucket: &bucket,
				S3Key:    &key,
			},
		},
		Encrypted: ptr.P(false),
	})
	if err != nil {
		return "", fmt.Errorf("cannot import snapshot from %s in bucket %s: %w", key, bucket, err)
	}
	if r.ImportTaskId == nil {
		return "", fmt.Errorf("cannot import snapshot from %s in bucket %s: missing import task ID", key, bucket)
	}
	ctx = log.WithValues(ctx, "taskId", *r.ImportTaskId)

	var snapshot string
	status := "active"
	for status == "active" {
		log.Debug(ctx, "Waiting for snapshot")
		var s *ec2.DescribeImportSnapshotTasksOutput
		s, err = p.tgtEC2Client.DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
			ImportTaskIds: []string{*r.ImportTaskId},
		})
		if err != nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with id %s: %w", *r.ImportTaskId, err)
		}
		if len(s.ImportSnapshotTasks) != 1 || s.NextToken != nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with id %s: missing import snapshot tasks", *r.ImportTaskId)
		}
		task := s.ImportSnapshotTasks[0]
		if task.SnapshotTaskDetail == nil || task.SnapshotTaskDetail.Status == nil || task.SnapshotTaskDetail.SnapshotId == nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with id %s: missing import snapshot task detail", *r.ImportTaskId)
		}
		status = *task.SnapshotTaskDetail.Status
		snapshot = *task.SnapshotTaskDetail.SnapshotId

		if status == "active" {
			time.Sleep(time.Second * 7)
		}
	}
	if status != "completed" {
		return "", fmt.Errorf("unknown import task status %s from %s in bucket %s", status, key, bucket)
	}
	log.Debug(ctx, "Snapshot imported")

	return snapshot, nil
}

func (p *aws) attachTags(ctx context.Context, obj string, tags []ec2types.Tag) error {
	log.Debug(ctx, "Attaching tags", "object", obj)
	_, err := p.tgtEC2Client.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{obj},
		Tags:      tags,
	})
	if err != nil {
		return fmt.Errorf("cannot create tags for %s: %w", obj, err)
	}

	return nil
}

func (p *aws) registerImage(ctx context.Context, snapshot, image string, arch ec2types.ArchitectureValues, requireUEFI bool,
	uefiData *string,
) (string, error) {
	params := ec2.RegisterImageInput{
		Name:         &image,
		Architecture: arch,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			DeviceName: ptr.P("/dev/xvda"),
			Ebs: &ec2types.EbsBlockDevice{
				DeleteOnTermination: ptr.P(true),
				SnapshotId:          &snapshot,
				VolumeType:          ec2types.VolumeTypeGp3,
			},
		}},
		BootMode:           ec2types.BootModeValuesUefiPreferred,
		EnaSupport:         ptr.P(true),
		ImdsSupport:        ec2types.ImdsSupportValuesV20,
		RootDeviceName:     ptr.P("/dev/xvda"),
		VirtualizationType: ptr.P("hvm"),
	}
	if requireUEFI {
		params.BootMode = ec2types.BootModeValuesUefi
	}
	if uefiData != nil {
		params.BootMode = ec2types.BootModeValuesUefi
		params.TpmSupport = ec2types.TpmSupportValuesV20
		params.UefiData = uefiData
	}

	log.Info(ctx, "Registering image")
	r, err := p.tgtEC2Client.RegisterImage(ctx, &params)
	if err != nil {
		return "", fmt.Errorf("cannot register image: %w", err)
	}
	if r.ImageId == nil {
		return "", errors.New("cannot register image: missing image ID")
	}

	return *r.ImageId, nil
}

func (p *aws) copyImage(ctx context.Context, image, imageID, fromRegion string, toRegions []string) (map[string]string, error) {
	images := make(map[string]string, len(toRegions))

	for _, region := range toRegions {
		if region == fromRegion {
			images[region] = imageID
			continue
		}

		log.Info(ctx, "Copying image", "toRegion", region)
		r, err := p.tgtEC2Client.CopyImage(ctx, &ec2.CopyImageInput{
			Name:          &image,
			SourceImageId: &imageID,
			SourceRegion:  &fromRegion,
			CopyImageTags: ptr.P(true),
		}, overrideRegion(region))
		if err != nil {
			return nil, fmt.Errorf("cannot copy image %s to region %s: %w", imageID, region, err)
		}
		if r.ImageId == nil {
			return nil, fmt.Errorf("cannot copy image %s to region %s: missing image ID", imageID, region)
		}
		images[region] = *r.ImageId
	}

	return images, nil
}

func (p *aws) waitForImages(ctx context.Context, images map[string]string) error {
	for region, imageID := range images {
		var state ec2types.ImageState
		for state != ec2types.ImageStateAvailable {
			log.Debug(ctx, "Waiting for image", "toRegion", region, "toImageID", imageID)
			r, err := p.tgtEC2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
				ImageIds: []string{imageID},
			}, overrideRegion(region))
			if err != nil {
				return fmt.Errorf("cannot get status of image %s in region %s: %w", imageID, region, err)
			}
			if len(r.Images) != 1 || r.NextToken != nil {
				return fmt.Errorf("cannot get status of image %s in region %s: missing images", imageID, region)
			}
			state = r.Images[0].State

			if state != ec2types.ImageStateAvailable {
				if state != ec2types.ImageStatePending {
					return fmt.Errorf("image %s in region %s has state %s", imageID, region, state)
				}

				time.Sleep(time.Second * 7)
			}
		}
	}
	log.Info(ctx, "Images ready", "count", len(images))

	return nil
}

func (p *aws) makePublic(ctx context.Context, images map[string]string) error {
	for region, imageID := range images {
		log.Debug(ctx, "Adding launch permission to image", "toRegion", region, "toImageID", imageID)
		_, err := p.tgtEC2Client.ModifyImageAttribute(ctx, &ec2.ModifyImageAttributeInput{
			ImageId:   &imageID,
			Attribute: ptr.P("launchPermission"),
			LaunchPermission: &ec2types.LaunchPermissionModifications{
				Add: []ec2types.LaunchPermission{
					{
						Group: ec2types.PermissionGroupAll,
					},
				},
			},
		}, overrideRegion(region))
		if err != nil {
			return fmt.Errorf("cannot modify attribute of image %s in region %s: %w", imageID, region, err)
		}
	}

	return nil
}

func overrideRegion(region string) func(o *ec2.Options) {
	return func(o *ec2.Options) {
		o.Region = region
	}
}

func (p *aws) deregisterImage(ctx context.Context, imageID, region string) error {
	log.Info(ctx, "Deregistering image")
	r, err := p.tgtEC2Client.DeregisterImage(ctx, &ec2.DeregisterImageInput{
		ImageId:                   &imageID,
		DeleteAssociatedSnapshots: ptr.P(true),
	}, overrideRegion(region))
	if err != nil {
		return fmt.Errorf("cannot deregister image %s: %w", imageID, err)
	}
	if r.Return != nil && !*r.Return {
		return fmt.Errorf("cannot deregister image %s: operation failed", imageID)
	}
	errs := make([]error, 0, len(r.DeleteSnapshotResults))
	for _, result := range r.DeleteSnapshotResults {
		if result.ReturnCode != ec2types.SnapshotReturnCodesSuccess && result.ReturnCode != ec2types.SnapshotReturnCodesWarnSkipped {
			errs = append(errs, fmt.Errorf("snapshot deletion result %s", result.ReturnCode))
		}
	}
	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("cannot deregister image %s: %w", imageID, err)
	}

	return nil
}
