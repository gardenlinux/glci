package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/slc"
	"github.com/gardenlinux/glci/internal/task"
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

type aws struct {
	srcCfg       awsSourceConfig
	pubCfg       awsPublishingConfig
	credsSource  credsprovider.CredsSource
	clientsMtx   sync.RWMutex
	srcS3Client  *s3.Client
	tgtEC2Client *ec2.Client
	regions      []string
}

type awsSourceConfig struct {
	Config string `mapstructure:"config"`
	Region string `mapstructure:"region"`
	Bucket string `mapstructure:"bucket"`
}

type awsPublishingConfig struct {
	Source    string       `mapstructure:"source"`
	Config    string       `mapstructure:"config"`
	Region    string       `mapstructure:"region"`
	Regions   []string     `mapstructure:"regions,omitempty"`
	ImageTags awsImageTags `mapstructure:"image_tags,omitzero"`
	china     bool
}

type awsImageTags struct {
	IncludeGardenLinuxVersion    bool              `mapstructure:"include_gardenlinux_version,omitzero"`
	IncludeGardenLinuxCommittish bool              `mapstructure:"include_gardenlinux_committish,omitzero"`
	StaticTags                   map[string]string `mapstructure:"static_tags,omitempty"`
}

func (p *aws) isConfigured() bool {
	_, ec2Client := p.clients()

	return ec2Client != nil
}

func (p *aws) SetSourceConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg map[string]any) error {
	p.credsSource = credsSource

	err := parseConfig(cfg, &p.srcCfg)
	if err != nil {
		return err
	}

	switch {
	case p.srcCfg.Config == "":
		return errors.New("missing config")
	case p.srcCfg.Region == "":
		return errors.New("missing region")
	case p.srcCfg.Bucket == "":
		return errors.New("missing bucket")
	}

	credsType := p.Type()
	if strings.HasPrefix(p.srcCfg.Region, "cn-") {
		credsType += "_china"
	}

	err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   credsType,
		Config: p.srcCfg.Config,
	}, p.createSrcClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.srcCfg.Config, err)
	}

	return nil
}

func (p *aws) SetTargetConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg map[string]any,
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
	case p.pubCfg.Region == "":
		return errors.New("missing region")
	}

	_, ok := sources[p.pubCfg.Source]
	if !ok {
		return fmt.Errorf("unknown source %s", p.pubCfg.Source)
	}

	if len(p.pubCfg.Regions) > 0 {
		if !slices.Contains(p.pubCfg.Regions, p.pubCfg.Region) {
			return fmt.Errorf("region %s missing from list of regions", p.pubCfg.Region)
		}
	}

	credsType := p.Type()
	if strings.HasPrefix(p.pubCfg.Region, "cn-") {
		p.pubCfg.china = true
		credsType += "_china"
	}

	err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   credsType,
		Config: p.pubCfg.Config,
	}, p.createTgtClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	return nil
}

type awsTaskState struct {
	Region   string `json:"region,omitzero"`
	Import   string `json:"import,omitzero"`
	Snapshot string `json:"snapshot,omitzero"`
	Image    string `json:"image,omitzero"`
}

type awsPublishingOutput struct {
	Images []awsPublishedImage `yaml:"published_aws_images,omitempty"`
}

type awsPublishedImage struct {
	Cloud  string `yaml:"cloud"`
	Region string `yaml:"aws_region_id"`
	ID     string `yaml:"ami_id"`
	Image  string `yaml:"image_name"`
}

type awsCredentials struct {
	AccessKey    string `mapstructure:"access_key"`
	SecretKey    string `mapstructure:"secret_key"`
	SessionToken string `mapstructure:"session_token"`
}

func (p *aws) createSrcClients(ctx context.Context, rawCreds map[string]any) error {
	var creds awsCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(p.srcCfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, creds.SessionToken)),
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.RateLimiter = ratelimit.None
			})
		}))
	if err != nil {
		return fmt.Errorf("cannot load default config: %w", err)
	}
	p.srcS3Client = s3.NewFromConfig(awsCfg)

	return nil
}

func (p *aws) createTgtClients(ctx context.Context, rawCreds map[string]any) error {
	var creds awsCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(p.pubCfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, creds.SessionToken)),
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.RateLimiter = ratelimit.None
			})
		}))
	if err != nil {
		return fmt.Errorf("cannot load default AWS config: %w", err)
	}
	p.tgtEC2Client = ec2.NewFromConfig(awsCfg)

	p.regions, err = p.listRegions(ctx, p.tgtEC2Client)
	if err != nil {
		return fmt.Errorf("cannot list regions: %w", err)
	}
	if len(p.pubCfg.Regions) > 0 {
		p.regions = slc.Subset(p.regions, p.pubCfg.Regions)
	}
	if len(p.regions) == 0 {
		return errors.New("no available regions")
	}
	if !slices.Contains(p.regions, p.pubCfg.Region) {
		return fmt.Errorf("region %s is not available", p.pubCfg.Region)
	}

	return nil
}

func (*aws) listRegions(ctx context.Context, ec2Client *ec2.Client) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	r, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
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

func overrideRegion(region string) func(o *ec2.Options) {
	return func(o *ec2.Options) {
		o.Region = region
	}
}

func (p *aws) clients() (*s3.Client, *ec2.Client) {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.srcS3Client, p.tgtEC2Client
}

func (p *aws) cloud() string {
	if p.pubCfg.china {
		return "china"
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

func (p *aws) Repository() string {
	return p.srcCfg.Bucket
}

func (p *aws) GetObjectURL(ctx context.Context, key string) (string, error) {
	s3Client, _ := p.clients()

	if s3Client == nil {
		return "", errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Getting presigned URL", "bucket", p.srcCfg.Bucket, "key", key)
	srcPresignClient := s3.NewPresignClient(s3Client, func(o *s3.PresignOptions) {
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
	s3Client, _ := p.clients()

	if s3Client == nil {
		return 0, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Heading object", "bucket", p.srcCfg.Bucket, "key", key)
	r, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &p.srcCfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		if errors.As(err, ptr.P(&s3types.NoSuchKey{})) {
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
	s3Client, _ := p.clients()

	if s3Client == nil {
		return nil, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Getting object", "bucket", p.srcCfg.Bucket, "key", key)
	r, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.srcCfg.Bucket,
		Key:    &key,
	})
	if err != nil {
		if errors.As(err, ptr.P(&s3types.NoSuchKey{})) {
			err = KeyNotFoundError{
				err: err,
			}
		}

		return nil, fmt.Errorf("cannot get object %s from bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return r.Body, nil
}

func (p *aws) PutObject(ctx context.Context, key string, object io.Reader) error {
	s3Client, _ := p.clients()

	if s3Client == nil {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Putting object", "bucket", p.srcCfg.Bucket, "key", key)
	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
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

func (p *aws) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	if manifest.Platform != "aws" {
		return false
	}

	chinaAndSecureBoot := p.pubCfg.china && manifest.SecureBoot
	return !chinaAndSecureBoot
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

	for _, img := range awsOutput.Images {
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

	for _, img := range ownOutput.Images {
		if img.Cloud != cld {
			return nil, errors.New("new publishing output has extraneous entries")
		}
	}

	for _, img := range awsOutput.Images {
		if img.Cloud == cld {
			return nil, errors.New("cannot add publishing output to existing publishing output")
		}
	}

	ownOutput.Images = slices.Concat(awsOutput.Images, ownOutput.Images)
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
	for _, img := range awsOutput.Images {
		if img.Cloud != cld {
			otherImages = append(otherImages, img)
		}
	}
	if len(otherImages) == 0 {
		return nil, nil
	}

	return &awsPublishingOutput{
		Images: otherImages,
	}, nil
}

func (p *aws) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput, error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	pl := platform(cname)
	if pl != "aws" {
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
	var arch ec2types.ArchitectureValues
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	tags := p.prepareTags(manifest)
	cld := p.cloud()
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", source.Type(), "sourceRepo", source.Repository(),
		"region", p.pubCfg.Region, "cloud", cld)

	var requireUEFI, secureBoot bool
	var uefiData *string
	requireUEFI, secureBoot, uefiData, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	ctx = log.WithValues(ctx, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

	ctx = task.Begin(ctx, "publish/"+image+"/"+p.pubCfg.Region, &awsTaskState{
		Region: p.pubCfg.Region,
	})
	var snapshot string
	snapshot, err = p.importSnapshot(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot import snapshot from %s for image %s: %w", imagePath.S3Key, image, err))
	}
	ctx = log.WithValues(ctx, "snapshot", snapshot)

	err = p.attachTags(ctx, snapshot, tags)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot attach tags to snapshot %s: %w", snapshot, err))
	}

	var imageID string
	imageID, err = p.registerImage(ctx, snapshot, image, arch, requireUEFI, uefiData)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err))
	}

	images := make(map[string]string, len(p.regions))
	publishImages := parallel.NewActivitySync(ctx)
	for _, toRegion := range p.regions {
		publishImages.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			ctx = log.WithValues(ctx, "region", toRegion)
			localID := imageID
			var er error

			if toRegion != p.pubCfg.Region {
				ctx = task.Begin(ctx, "publish/"+image+"/"+toRegion, &awsTaskState{
					Region: toRegion,
				})
				localID, er = p.copyImage(ctx, image, imageID, p.pubCfg.Region, toRegion)
				if er != nil {
					return nil, task.Fail(ctx, fmt.Errorf("cannot copy image %s from region %s to region %s: %w", image, p.pubCfg.Region,
						toRegion, er))
				}
			}
			ctx = log.WithValues(ctx, "imageID", localID)

			er = p.waitForImage(ctx, localID, toRegion)
			if er != nil {
				return nil, task.Fail(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", image, toRegion, er))
			}

			er = p.makePublic(ctx, localID, toRegion)
			if er != nil {
				return nil, task.Fail(ctx, fmt.Errorf("cannot make image %s public in region %s: %w", image, toRegion, er))
			}
			task.Complete(ctx)

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

	outputImages := make([]awsPublishedImage, 0, len(images))
	for region, id := range images {
		outputImages = append(outputImages, awsPublishedImage{
			Cloud:  p.cloud(),
			Region: region,
			ID:     id,
			Image:  image,
		})
	}

	return &awsPublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *aws) prepareTags(manifest *gl.Manifest) []ec2types.Tag {
	tags := make([]ec2types.Tag, 0, 2+len(p.pubCfg.ImageTags.StaticTags))

	for k, v := range p.pubCfg.ImageTags.StaticTags {
		tags = append(tags, ec2types.Tag{
			Key:   &k,
			Value: &v,
		})
	}

	if p.pubCfg.ImageTags.IncludeGardenLinuxVersion {
		tags = append(tags, ec2types.Tag{
			Key:   ptr.P("gardenlinux-version"),
			Value: &manifest.Version,
		})
	}

	if p.pubCfg.ImageTags.IncludeGardenLinuxCommittish {
		tags = append(tags, ec2types.Tag{
			Key:   ptr.P("gardenlinux-committish"),
			Value: &manifest.BuildCommittish,
		})
	}

	return tags
}

func (*aws) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gl.Manifest) (bool, bool, *string, error) {
	var uefiData *string

	if manifest.SecureBoot {
		fetchCertificates := parallel.NewActivity(ctx)

		fetchCertificates.Go(func(ctx context.Context) error {
			efivarsFile, er := manifest.PathBySuffix(".secureboot.aws-efivars")
			if er != nil {
				return fmt.Errorf("missing efivars: %w", er)
			}

			var efivars []byte
			efivars, er = getObjectBytes(ctx, source, efivarsFile.S3Key)
			if er != nil {
				return fmt.Errorf("cannot get efivars: %w", er)
			}
			uefiData = ptr.P(string(efivars))

			return nil
		})

		err := fetchCertificates.Wait()
		if err != nil {
			return false, false, nil, err
		}
	}

	return manifest.RequireUEFI, manifest.SecureBoot, uefiData, nil
}

func (p *aws) importSnapshot(ctx context.Context, source ArtifactSource, key, image string) (string, error) {
	bucket := source.Repository()
	ctx = log.WithValues(ctx, "key", key)

	_, ec2Client := p.clients()

	log.Info(ctx, "Importing snapshot")
	r, err := ec2Client.ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
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
		return "", fmt.Errorf("cannot import snapshot in bucket %s: %w", bucket, err)
	}
	if r.ImportTaskId == nil {
		return "", fmt.Errorf("cannot import snapshot in bucket %s: missing import task ID", bucket)
	}
	importTaskID := *r.ImportTaskId
	task.Update(ctx, func(s *awsTaskState) *awsTaskState {
		s.Import = importTaskID
		return s
	})
	ctx = log.WithValues(ctx, "taskId", importTaskID)

	var snapshot string
	status := "active"
	for status == "active" {
		var s *ec2.DescribeImportSnapshotTasksOutput
		s, err = ec2Client.DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
			ImportTaskIds: []string{*r.ImportTaskId},
		})
		if err != nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with ID %s: %w", *r.ImportTaskId, err)
		}
		if len(s.ImportSnapshotTasks) != 1 || s.NextToken != nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with ID %s: missing import snapshot tasks", *r.ImportTaskId)
		}
		importTask := s.ImportSnapshotTasks[0]
		if importTask.SnapshotTaskDetail == nil || importTask.SnapshotTaskDetail.Status == nil {
			return "", fmt.Errorf("cannot describe import snapshot tasks with ID %s: missing import snapshot task detail", *r.ImportTaskId)
		}
		status = *importTask.SnapshotTaskDetail.Status
		if importTask.SnapshotTaskDetail.SnapshotId != nil {
			snapshot = *importTask.SnapshotTaskDetail.SnapshotId
		}

		if status == "active" {
			time.Sleep(time.Second * 7)
		}
	}
	if status != "completed" {
		return "", fmt.Errorf("unknown import task status %s in bucket %s", status, bucket)
	}
	if snapshot == "" {
		return "", fmt.Errorf("cannot describe import snapshot tasks with ID %s: missing snapshot ID", *r.ImportTaskId)
	}
	task.Update(ctx, func(s *awsTaskState) *awsTaskState {
		s.Import = ""
		s.Snapshot = snapshot
		return s
	})
	log.Debug(ctx, "Snapshot imported")

	return snapshot, nil
}

func (p *aws) attachTags(ctx context.Context, obj string, tags []ec2types.Tag) error {
	_, ec2Client := p.clients()

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

	_, ec2Client := p.clients()

	log.Info(ctx, "Registering image")
	r, err := ec2Client.RegisterImage(ctx, &params)
	if err != nil {
		return "", fmt.Errorf("cannot register image: %w", err)
	}
	if r.ImageId == nil {
		return "", errors.New("cannot register image: missing image ID")
	}
	imageID := *r.ImageId
	task.Update(ctx, func(s *awsTaskState) *awsTaskState {
		s.Snapshot = ""
		s.Image = imageID
		return s
	})

	return imageID, nil
}

func (p *aws) copyImage(ctx context.Context, image, imageID, region, toRegion string) (string, error) {
	_, ec2Client := p.clients()

	log.Info(ctx, "Copying image")
	r, err := ec2Client.CopyImage(ctx, &ec2.CopyImageInput{
		Name:          &image,
		SourceImageId: &imageID,
		SourceRegion:  &region,
		CopyImageTags: ptr.P(true),
	}, overrideRegion(toRegion))
	if err != nil {
		return "", fmt.Errorf("cannot copy image: %w", err)
	}
	if r.ImageId == nil {
		return "", errors.New("cannot copy image: missing image ID")
	}
	toImageID := *r.ImageId
	task.Update(ctx, func(s *awsTaskState) *awsTaskState {
		s.Image = toImageID
		return s
	})

	return toImageID, nil
}

func (p *aws) waitForImage(ctx context.Context, imageID, region string) error {
	_, ec2Client := p.clients()

	var state ec2types.ImageState
	for state != ec2types.ImageStateAvailable {
		r, err := ec2Client.DescribeImages(ctx, &ec2.DescribeImagesInput{
			ImageIds: []string{imageID},
		}, overrideRegion(region))
		if err != nil {
			return fmt.Errorf("cannot describe image: %w", err)
		}
		if len(r.Images) != 1 || r.NextToken != nil {
			return errors.New("ccannot describe image: missing images")
		}
		state = r.Images[0].State

		if state != ec2types.ImageStateAvailable {
			if state != ec2types.ImageStatePending {
				return fmt.Errorf("image has state %s", state)
			}

			time.Sleep(time.Second * 7)
		}
	}

	return nil
}

func (p *aws) makePublic(ctx context.Context, imageID, region string) error {
	_, ec2Client := p.clients()

	log.Debug(ctx, "Adding launch permission to image")
	_, err := ec2Client.ModifyImageAttribute(ctx, &ec2.ModifyImageAttributeInput{
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
		return fmt.Errorf("cannot modify attribute: %w", err)
	}

	return nil
}

func (p *aws) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if manifest.Platform != "aws" {
		return fmt.Errorf("invalid manifest: invalid platform %s for target %s", manifest.Platform, p.Type())
	}

	pubOut, err := publishingOutputFromManifest[awsPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	cld := p.cloud()
	ctx = log.WithValues(ctx, "cloud", cld)

	removeImages := parallel.NewActivity(ctx)
	for _, img := range pubOut.Images {
		if img.Cloud != cld {
			continue
		}

		removeImages.Go(func(ctx context.Context) error {
			lctx := log.WithValues(ctx, "region", img.Region, "imageID", img.ID, "image", img.Image)

			er := p.deregisterImage(lctx, img.ID, img.Region, steamroll)
			if er != nil {
				return fmt.Errorf("cannot deregister image %s in region %s: %w", img.ID, img.Region, er)
			}

			return nil
		})
	}
	return removeImages.Wait()
}

func (p *aws) deregisterImage(ctx context.Context, imageID, region string, steamroll bool) error {
	_, ec2Client := p.clients()

	log.Info(ctx, "Deregistering image")
	r, err := ec2Client.DeregisterImage(ctx, &ec2.DeregisterImageInput{
		ImageId:                   &imageID,
		DeleteAssociatedSnapshots: ptr.P(true),
	}, overrideRegion(region))
	if err != nil {
		var terr *smithy.GenericAPIError
		if steamroll && errors.As(err, &terr) && terr.Code == "InvalidAMIID.Unavailable" {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot deregister image: %w", err)
	}
	if r.Return != nil && !*r.Return {
		return errors.New("cannot deregister image: operation failed")
	}
	errs := make([]error, 0, len(r.DeleteSnapshotResults))
	for _, result := range r.DeleteSnapshotResults {
		if result.ReturnCode != ec2types.SnapshotReturnCodesSuccess && result.ReturnCode != ec2types.SnapshotReturnCodesWarnSkipped {
			errs = append(errs, fmt.Errorf("snapshot deletion result %s", result.ReturnCode))
		}
	}
	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("cannot deregister image: %w", err)
	}

	return nil
}

func (p *aws) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "aws/" + strings.ReplaceAll(p.cloud(), " ", "_")
}

func (p *aws) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := parallel.NewActivity(ctx)
	for _, t := range tasks {
		state, err := task.ParseState[*awsTaskState](t.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}

		if state.Import != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "importTask", state.Import)

				er := p.deleteSnapshotFromImportTask(ctx, state.Import, state.Region, true)
				if er != nil {
					return fmt.Errorf("cannot delete snapshot from task ID %s in region %s: %w", state.Import, state.Region, er)
				}

				return nil
			})
		}

		if state.Snapshot != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "snapshot", state.Snapshot)

				er := p.deleteSnapshot(ctx, state.Snapshot, state.Region, true)
				if er != nil {
					return fmt.Errorf("cannot delete snapshot %s in region %s: %w", state.Snapshot, state.Region, er)
				}

				return nil
			})
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "image", state.Image)

				er := p.deregisterImage(ctx, state.Image, state.Region, true)
				if er != nil {
					return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, er)
				}

				return nil
			})
		}
	}
	return rollbackTasks.Wait()
}

func (p *aws) deleteSnapshotFromImportTask(ctx context.Context, importTaskID, region string, steamroll bool) error {
	_, ec2Client := p.clients()

	log.Debug(ctx, "Determining snapshot")
	var snapshot string
	status := "active"
	for status == "active" {
		s, err := ec2Client.DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
			ImportTaskIds: []string{importTaskID},
		}, overrideRegion(region))
		if err != nil {
			return fmt.Errorf("cannot describe import snapshot tasks: %w", err)
		}
		if len(s.ImportSnapshotTasks) == 0 && steamroll {
			log.Debug(ctx, "Import task not found but the steamroller keeps going")
			return nil
		}
		if len(s.ImportSnapshotTasks) != 1 || s.NextToken != nil {
			return errors.New("cannot describe import snapshot tasks: missing import snapshot tasks")
		}
		importTask := s.ImportSnapshotTasks[0]
		if importTask.SnapshotTaskDetail == nil || importTask.SnapshotTaskDetail.Status == nil {
			return errors.New("cannot describe import snapshot tasks: missing import snapshot task detail")
		}
		status = *importTask.SnapshotTaskDetail.Status
		if importTask.SnapshotTaskDetail.SnapshotId != nil {
			snapshot = *importTask.SnapshotTaskDetail.SnapshotId
			if snapshot != "" {
				break
			}
		}

		if status == "active" {
			time.Sleep(time.Second * 7)
		}
	}
	if snapshot == "" {
		if steamroll {
			log.Debug(ctx, "Snapshot not determinable but the steamroller keeps going")
			return nil
		}
		return errors.New("cannot describe import snapshot tasks: missing snapshot ID")
	}
	ctx = log.WithValues(ctx, "snapshot", snapshot)

	return p.deleteSnapshot(ctx, snapshot, region, steamroll)
}

func (p *aws) deleteSnapshot(ctx context.Context, snapshot, region string, steamroll bool) error {
	_, ec2Client := p.clients()

	log.Info(ctx, "Deleting snapshot")
	_, err := ec2Client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: &snapshot,
	}, overrideRegion(region))
	if err != nil {
		var terr *smithy.GenericAPIError
		if steamroll && errors.As(err, &terr) && terr.Code == "InvalidSnapshot.NotFound" {
			log.Debug(ctx, "Snapshot not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete snapshot: %w", err)
	}

	return nil
}

func (p *aws) Close() error {
	if p.srcCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.srcCfg.Config,
		})
	}

	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
		})
	}

	return nil
}
