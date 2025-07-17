package cloudprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	aws2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/util"
)

func init() {
	util.CleanEnv("AWS_")
	util.CleanEnv("_X_AMZN_")

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

	var awsCfg aws2.Config
	awsCfg, err = config.LoadDefaultConfig(
		ctx,
		config.WithRegion(creds.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")),
	)
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

	p.tgtEC2Clients = make(map[string]*ec2.Client, len(p.pubCfg.Targets))
	for _, target := range p.pubCfg.Targets {
		_, ok := sources[target.Source]
		if !ok {
			return fmt.Errorf("unknown source %s", target.Source)
		}

		var creds awsCredentials
		creds, ok = p.creds[target.Config]
		if !ok {
			return fmt.Errorf("missing credentials config %s", target.Config)
		}

		var awsCfg aws2.Config
		awsCfg, err = config.LoadDefaultConfig(
			ctx,
			config.WithRegion(creds.Region),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")),
		)
		if err != nil {
			return fmt.Errorf("cannot load default aws config: %w", err)
		}
		p.tgtEC2Clients[target.Config] = ec2.NewFromConfig(awsCfg)
	}

	return nil
}

func (*aws) Close() error {
	return nil
}

func (p *aws) Repository() string {
	return p.srcCfg.Bucket
}

func (p *aws) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
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

func (p *aws) GetObjectBytes(ctx context.Context, key string) ([]byte, error) {
	body, err := p.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = body.Close()
	}()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(body)
	if err != nil {
		return nil, fmt.Errorf("cannot read object: %w", err)
	}

	err = body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object: %w", err)
	}

	return buf.Bytes(), nil
}

func (p *aws) GetManifest(ctx context.Context, key string) (*gl.Manifest, error) {
	body, err := p.GetObject(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("cannot get manifest: %w", err)
	}
	defer func() {
		_ = body.Close()
	}()

	manifest := &gl.Manifest{}
	err = yaml.NewDecoder(body).Decode(manifest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	err = body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object: %w", err)
	}

	return manifest, nil
}

func (p *aws) PutManifest(ctx context.Context, key string, manifest *gl.Manifest) error {
	ctx = log.WithValues(ctx, "source", p.Type())

	var buf bytes.Buffer
	err := yaml.NewEncoder(&buf).Encode(manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	log.Debug(ctx, "Putting object", "bucket", p.srcCfg.Bucket, "key", key)
	_, err = p.srcS3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &p.srcCfg.Bucket,
		Key:             &key,
		Body:            &buf,
		ContentEncoding: util.Ptr("utf-8"),
		ContentType:     util.Ptr("text/yaml"),
	})
	if err != nil {
		return fmt.Errorf("cannot put object %s to bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return nil
}

func (*aws) ImageSuffix() string {
	return ".raw"
}

func (p *aws) Publish(
	ctx context.Context,
	cname string,
	manifest *gl.Manifest,
	sources map[string]ArtifactSource,
) (PublishingOutput, error) {
	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var architecture ec2types.ArchitectureValues
	architecture, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	tags := p.prepareTags(manifest)
	var output awsPublishingOutput
	ctx = log.WithValues(ctx, "target", p.Type(), "image", image, "architecture", architecture)

	for _, target := range p.pubCfg.Targets {
		source := sources[target.Source]
		ec2Client := p.tgtEC2Clients[target.Config]
		region := p.creds[target.Config].Region
		lctx := log.WithValues(ctx, "sourceType", source.Type(), "sourceRepo", source.Repository(), "region", region)

		var requireUEFI, secureBoot bool
		var uefiData *string
		requireUEFI, secureBoot, uefiData, err = p.prepareSecureBoot(lctx, source, manifest)
		if err != nil {
			return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
		}
		lctx = log.WithValues(lctx, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

		var regions []string
		regions, err = p.listRegions(lctx, ec2Client)
		if err != nil {
			return nil, fmt.Errorf("cannot list regions: %w", err)
		}
		if target.Regions != nil {
			regions = util.Subset(regions, *target.Regions)
		}
		if len(regions) == 0 {
			return nil, errors.New("no available regions")
		}

		var snapshot string
		snapshot, err = p.importSnapshot(lctx, ec2Client, source, imagePath.S3Key, image)
		if err != nil {
			return nil, fmt.Errorf("cannot import snapshot for image %s: %w", image, err)
		}
		lctx = log.WithValues(lctx, "snapshot", snapshot)

		err = p.attachTags(lctx, ec2Client, snapshot, tags)
		if err != nil {
			return nil, fmt.Errorf("cannot attach tags to snapshot %s: %w", snapshot, err)
		}

		var imageID string
		imageID, err = p.registerImage(lctx, ec2Client, snapshot, image, architecture, requireUEFI, uefiData)
		if err != nil {
			return nil, fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err)
		}
		lctx = log.WithValues(lctx, "imageID", imageID)

		var images map[string]string
		images, err = p.copyImage(lctx, ec2Client, image, imageID, region, regions)
		if err != nil {
			return nil, fmt.Errorf("cannot copy image %s: %w", image, err)
		}

		err = p.waitForImages(lctx, ec2Client, images)
		if err != nil {
			return nil, fmt.Errorf("cannot finalize images: %w", err)
		}

		err = p.makePublic(lctx, ec2Client, images)
		if err != nil {
			return nil, fmt.Errorf("cannot finalize images: %w", err)
		}

		for region, imageID = range images {
			output = append(output, awsPublishedImage{
				Region: region,
				AMIID:  imageID,
				Name:   image,
			})
		}
	}

	return output, nil
}

func (p *aws) Remove(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) error {
	for _, target := range p.pubCfg.Targets {
		_, ok := sources[target.Source]
		if !ok {
			return fmt.Errorf("unknown source %s", target.Source)
		}
	}

	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	ctx = log.WithValues(ctx, "target", p.Type(), "image", image)

	for _, target := range p.pubCfg.Targets {
		ec2Client := p.tgtEC2Clients[target.Config]
		lctx := ctx

		regions, err := p.listRegions(lctx, ec2Client)
		if err != nil {
			return fmt.Errorf("cannot list regions: %w", err)
		}
		if len(regions) == 0 {
			break
		}

		var images map[string]string
		images, err = p.getImageIDsByRegion(ctx, ec2Client, image, regions)
		if err != nil {
			return fmt.Errorf("cannot get image IDs for image %s: %w", image, err)
		}

		for region, imageID := range images {
			err = p.deregisterImage(ctx, ec2Client, imageID, region)
			if err != nil {
				return fmt.Errorf("cannot deregister image %s: %w", image, err)
			}
		}
	}

	return nil
}

type aws struct {
	creds         map[string]awsCredentials
	srcCfg        awsSourceConfig
	pubCfg        awsPublishingConfig
	srcS3Client   *s3.Client
	tgtEC2Clients map[string]*ec2.Client
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
	Targets   []awsTarget   `mapstructure:"targets"`
	ImageTags *awsImageTags `mapstructure:"image_tags,omitempty"`
}

type awsTarget struct {
	Source  string    `mapstructure:"source"`
	Config  string    `mapstructure:"config"`
	Regions *[]string `mapstructure:"regions,omitempty"`
}

type awsImageTags struct {
	IncludeGardenLinuxVersion    *bool              `mapstructure:"include_gardenlinux_version,omitempty"`
	IncludeGardenLinuxCommittish *bool              `mapstructure:"include_gardenlinux_committish,omitempty"`
	StaticTags                   *map[string]string `mapstructure:"static_tags,omitempty"`
}

type awsPublishingOutput []awsPublishedImage

type awsPublishedImage struct {
	Region string `mapstructure:"region"`
	AMIID  string `mapstructure:"ami_id"`
	Name   string `mapstructure:"name"`
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
				Key:   util.Ptr("gardenlinux-version"),
				Value: &manifest.Version,
			})
		}

		if p.pubCfg.ImageTags.IncludeGardenLinuxCommittish != nil && *p.pubCfg.ImageTags.IncludeGardenLinuxCommittish {
			tags = append(tags, ec2types.Tag{
				Key:   util.Ptr("gardenlinux-committish"),
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
		efivars, err = source.GetObjectBytes(ctx, efivarsFile.S3Key)
		if err != nil {
			return false, false, nil, fmt.Errorf("cannot get efivars: %w", err)
		}

		uefiData = util.Ptr(string(efivars))
	}

	return requireUEFI, secureBoot, uefiData, nil
}

func (*aws) listRegions(ctx context.Context, ec2Client *ec2.Client) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	r, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("cannot desctibe regions: %w", err)
	}

	regions := make([]string, 0, len(r.Regions))
	for _, region := range r.Regions {
		if region.RegionName == nil {
			return nil, errors.New("cannot desctibe regions: missing region name")
		}
		regions = append(regions, *region.RegionName)
	}

	return regions, nil
}

func (*aws) importSnapshot(ctx context.Context, ec2Client *ec2.Client, source ArtifactSource, key, image string) (string, error) {
	bucket := source.Repository()
	ctx = log.WithValues(ctx, "key", key)

	log.Info(ctx, "Importing snapshot")
	r, err := ec2Client.ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
		DiskContainer: &ec2types.SnapshotDiskContainer{
			Description: &image,
			Format:      util.Ptr("raw"),
			UserBucket: &ec2types.UserBucket{
				S3Bucket: &bucket,
				S3Key:    &key,
			},
		},
		Encrypted: util.Ptr(false),
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
		log.Debug(ctx, "Waiting for snapshot import")
		var s *ec2.DescribeImportSnapshotTasksOutput
		s, err = ec2Client.DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
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
	log.Info(ctx, "Snapshot imported")

	return snapshot, nil
}

func (*aws) attachTags(ctx context.Context, ec2Client *ec2.Client, obj string, tags []ec2types.Tag) error {
	log.Debug(ctx, "Attaching tags", "object", obj)
	_, err := ec2Client.CreateTags(ctx, &ec2.CreateTagsInput{
		Resources: []string{obj},
		Tags:      tags,
	})
	if err != nil {
		return fmt.Errorf("cannot create tags for %s: %w", obj, err)
	}

	return nil
}

func (*aws) registerImage(
	ctx context.Context,
	ec2Client *ec2.Client,
	snapshot, image string,
	architecture ec2types.ArchitectureValues,
	requireUEFI bool,
	uefiData *string,
) (string, error) {
	params := ec2.RegisterImageInput{
		Name:         &image,
		Architecture: architecture,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			DeviceName: util.Ptr("/dev/xvda"),
			Ebs: &ec2types.EbsBlockDevice{
				DeleteOnTermination: util.Ptr(true),
				SnapshotId:          &snapshot,
				VolumeType:          ec2types.VolumeTypeGp3,
			},
		}},
		BootMode:           ec2types.BootModeValuesUefiPreferred,
		EnaSupport:         util.Ptr(true),
		ImdsSupport:        ec2types.ImdsSupportValuesV20,
		RootDeviceName:     util.Ptr("/dev/xvda"),
		VirtualizationType: util.Ptr("hvm"),
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
	r, err := ec2Client.RegisterImage(ctx, &params)
	if err != nil {
		return "", fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err)
	}
	if r.ImageId == nil {
		return "", fmt.Errorf("cannot register image %s from snapshot %s: missing image ID", image, snapshot)
	}

	return *r.ImageId, nil
}

func (*aws) copyImage(
	ctx context.Context,
	ec2Client *ec2.Client,
	imageName, imageID, fromRegion string,
	toRegions []string,
) (map[string]string, error) {
	images := make(map[string]string, len(toRegions))

	for _, region := range toRegions {
		if region == fromRegion {
			images[region] = imageID
			continue
		}

		log.Info(ctx, "Copying image", "toRegion", region)
		r, err := ec2Client.CopyImage(ctx, &ec2.CopyImageInput{
			Name:          &imageName,
			SourceImageId: &imageID,
			SourceRegion:  &fromRegion,
			CopyImageTags: util.Ptr(true),
		}, overrideRegion(region))
		if err != nil {
			return images, fmt.Errorf("cannot copy image %s to region %s: %w", imageID, region, err)
		}
		if r.ImageId == nil {
			return images, fmt.Errorf("cannot copy image %s to region %s: missing image ID", imageID, region)
		}
		images[region] = *r.ImageId
	}

	return images, nil
}

func (*aws) waitForImages(ctx context.Context, ec2Client *ec2.Client, images map[string]string) error {
	for region, imageID := range images {
		var state ec2types.ImageState
		for state != ec2types.ImageStateAvailable {
			log.Debug(ctx, "Waiting for image", "toRegion", region, "toImageID", imageID)
			r, err := ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
				ImageIds: []string{imageID},
			}, overrideRegion(region))
			if err != nil {
				return fmt.Errorf("cannot get status of image %s in region %s: %w", imageID, region, err)
			}
			if len(r.Images) != 1 || r.NextToken != nil {
				return fmt.Errorf("cannot get status of image %s in region %s: missing images", imageID, region)
			}
			state = r.Images[0].State

			if state == ec2types.ImageStateInvalid || state == ec2types.ImageStateFailed || state == ec2types.ImageStateError {
				return fmt.Errorf("image %s in region %s is in %s state", imageID, region, state)
			}

			if state != ec2types.ImageStateAvailable {
				time.Sleep(time.Second * 7)
			}
		}
	}
	log.Info(ctx, "Images ready", "count", len(images))

	return nil
}

func (*aws) makePublic(ctx context.Context, ec2Client *ec2.Client, images map[string]string) error {
	for region, imageID := range images {
		log.Debug(ctx, "Adding launch permission to image", "toRegion", region, "toImageID", imageID)
		_, err := ec2Client.ModifyImageAttribute(ctx, &ec2.ModifyImageAttributeInput{
			ImageId:   &imageID,
			Attribute: util.Ptr("launchPermission"),
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

func (*aws) getImageIDsByRegion(ctx context.Context, ec2Client *ec2.Client, image string, regions []string) (map[string]string, error) {
	images := make(map[string]string, len(regions))
	for _, region := range regions {
		log.Debug(ctx, "Getting image ID", "fromRegion", region)
		r, err := ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
			Filters: []ec2types.Filter{
				{
					Name: util.Ptr("name"),
					Values: []string{
						image,
					},
				},
			},
			MaxResults: util.Ptr(int32(5)),
		}, overrideRegion(region))
		if err != nil {
			return nil, fmt.Errorf("cannot get status of image in region %s: %w", region, err)
		}
		if len(r.Images) > 1 {
			return nil, errors.New("too many images with the same name")
		}
		if len(r.Images) < 1 {
			continue
		}
		if r.Images[0].ImageId == nil {
			return nil, fmt.Errorf("missing image ID in region %s", region)
		}

		images[region] = *r.Images[0].ImageId
	}

	return images, nil
}

func (*aws) deregisterImage(ctx context.Context, ec2Client *ec2.Client, imageID, region string) error {
	ctx = log.WithValues(ctx, "fromRegion", region)

	log.Info(ctx, "Deregistering image")
	r, err := ec2Client.DeregisterImage(ctx, &ec2.DeregisterImageInput{
		ImageId:                   &imageID,
		DeleteAssociatedSnapshots: util.Ptr(true),
	}, overrideRegion(region))
	if err != nil {
		return fmt.Errorf("cannot deregister image %s in region %s: %w", imageID, region, err)
	}
	if r.Return != nil && !*r.Return {
		return fmt.Errorf("cannot deregister image %s in region %s: operation failed", imageID, region)
	}
	errs := make([]error, 0, len(r.DeleteSnapshotResults))
	for _, result := range r.DeleteSnapshotResults {
		if result.ReturnCode != ec2types.SnapshotReturnCodesSuccess && result.ReturnCode != ec2types.SnapshotReturnCodesWarnSkipped {
			errs = append(errs, fmt.Errorf("snapshot deletion result %s", result.ReturnCode))
		}
	}
	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("cannot deregister image %s in region %s: %w", imageID, region, err)
	}

	return nil
}
