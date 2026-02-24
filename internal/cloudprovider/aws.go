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
	srcCfg            awsSourceConfig
	pubCfg            awsPublishingConfig
	credsSource       credsprovider.CredsSource
	clientsMtx        sync.RWMutex
	srcS3Client       *s3.Client
	tgtEC2Client      *ec2.Client
	tgtEC2ClientChina *ec2.Client
	regions           []string
	regionsChina      []string
	enableChina       bool
}

type awsSourceConfig struct {
	Config string `mapstructure:"config"`
	Region string `mapstructure:"region"`
	Bucket string `mapstructure:"bucket"`
}

type awsPublishingConfig struct {
	Source       string       `mapstructure:"source"`
	SourceChina  string       `mapstructure:"source_china,omitzero"`
	Config       string       `mapstructure:"config"`
	ConfigChina  string       `mapstructure:"config_china,omitzero"`
	Region       string       `mapstructure:"region"`
	RegionChina  string       `mapstructure:"region_china,omitzero"`
	Regions      []string     `mapstructure:"regions,omitempty"`
	RegionsChina []string     `mapstructure:"regions_china,omitempty"`
	ImageTags    awsImageTags `mapstructure:"image_tags,omitzero"`
}

type awsImageTags struct {
	IncludeGardenLinuxVersion    bool              `mapstructure:"include_gardenlinux_version,omitzero"`
	IncludeGardenLinuxCommittish bool              `mapstructure:"include_gardenlinux_committish,omitzero"`
	StaticTags                   map[string]string `mapstructure:"static_tags,omitempty"`
}

func (p *aws) isConfigured() bool {
	ec2Client := p.tgtClients(false)

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

	credsType := p.Type() + "_src"
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

	if p.pubCfg.ConfigChina != "" {
		if p.pubCfg.RegionChina == "" {
			return errors.New("missing region")
		}

		if p.pubCfg.SourceChina != "" {
			_, ok = sources[p.pubCfg.SourceChina]
			if !ok {
				return fmt.Errorf("unknown source %s", p.pubCfg.SourceChina)
			}
		}

		if len(p.pubCfg.RegionsChina) > 0 {
			if !slices.Contains(p.pubCfg.RegionsChina, p.pubCfg.RegionChina) {
				return fmt.Errorf("region %s missing from list of regions", p.pubCfg.RegionChina)
			}
		}

		p.enableChina = true
	}

	err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.pubCfg.Config,
	}, func(ctx context.Context, creds map[string]any) error {
		return p.createTgtClients(ctx, creds, false)
	})
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	if p.enableChina {
		err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
			Type:   p.Type() + "_china",
			Config: p.pubCfg.ConfigChina,
		}, func(ctx context.Context, creds map[string]any) error {
			return p.createTgtClients(ctx, creds, true)
		})
		if err != nil {
			return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.ConfigChina, err)
		}
	}

	return nil
}

type awsTaskState struct {
	China    bool   `json:"china,omitzero"`
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

func (p *aws) createTgtClients(ctx context.Context, rawCreds map[string]any, china bool) error {
	var creds awsCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	region := p.pubCfg.Region
	if china {
		region = p.pubCfg.RegionChina
	}

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, creds.SessionToken)),
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.RateLimiter = ratelimit.None
			})
		}))
	if err != nil {
		return fmt.Errorf("cannot load default AWS config: %w", err)
	}
	tgtEC2Client := ec2.NewFromConfig(awsCfg)

	var regions []string
	regions, err = p.listRegions(ctx, tgtEC2Client)
	if err != nil {
		return fmt.Errorf("cannot list regions: %w", err)
	}

	if china {
		if len(p.pubCfg.RegionsChina) > 0 {
			regions = slc.Subset(regions, p.pubCfg.RegionsChina)
		}
		if len(regions) == 0 {
			return errors.New("no available regions")
		}
		if !slices.Contains(regions, region) {
			return fmt.Errorf("region %s is not available", region)
		}

		p.tgtEC2ClientChina = tgtEC2Client
		p.regionsChina = regions
	} else {
		if len(p.pubCfg.Regions) > 0 {
			regions = slc.Subset(regions, p.pubCfg.Regions)
		}
		if len(regions) == 0 {
			return errors.New("no available regions")
		}
		if !slices.Contains(regions, region) {
			return fmt.Errorf("region %s is not available", region)
		}

		p.tgtEC2Client = tgtEC2Client
		p.regions = regions
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

func (p *aws) srcClients() *s3.Client {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.srcS3Client
}

func (p *aws) tgtClients(china bool) *ec2.Client {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	if china {
		return p.tgtEC2ClientChina
	}

	return p.tgtEC2Client
}

func (*aws) ImageSuffix() string {
	return ".raw"
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
	s3Client := p.srcClients()

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
	s3Client := p.srcClients()

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
		_, ok := errors.AsType[*s3types.NoSuchKey](err)
		if ok {
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
	s3Client := p.srcClients()

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
		_, ok := errors.AsType[*s3types.NoSuchKey](err)
		if ok {
			err = KeyNotFoundError{
				err: err,
			}
		}

		return nil, fmt.Errorf("cannot get object %s from bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return r.Body, nil
}

func (p *aws) PutObject(ctx context.Context, key string, object io.Reader) error {
	s3Client := p.srcClients()

	if s3Client == nil {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Putting object", "bucket", p.srcCfg.Bucket, "key", key)
	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &p.srcCfg.Bucket,
		Key:             &key,
		Body:            object,
		ContentEncoding: new("utf-8"),
		ContentType:     new("text/yaml"),
	})
	if err != nil {
		return fmt.Errorf("cannot put object %s to bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return nil
}

func (p *aws) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return manifest.Platform == "aws"
}

func (p *aws) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	awsOutput, err := publishingOutputFromManifest[awsPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return len(awsOutput.Images) > 0, nil
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

	source := sources[p.pubCfg.Source]
	ctx = log.WithValues(ctx, "sourceType", source.Type(), "sourceRepo", source.Repository())
	sourceChina := source
	if p.pubCfg.SourceChina != "" {
		sourceChina = sources[p.pubCfg.SourceChina]
		ctx = log.WithValues(ctx, "sourceChinaType", sourceChina.Type(), "sourceChinaRepo", sourceChina.Repository())
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
	tags := p.prepareTags(manifest)

	var requireUEFI, secureBoot bool
	var uefiData *string
	requireUEFI, secureBoot, uefiData, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}

	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

	outputImages := make([]awsPublishedImage, 0, 4)
	publish := parallel.NewActivitySync(ctx)

	publish.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
		ctx = log.WithValues(ctx, "cloud", "public")

		images, er := p.publish(ctx, source, imagePath.S3Key, image, tags, arch, requireUEFI, uefiData, false)
		if er != nil {
			return nil, er
		}
		return func() error {
			outputImages = append(outputImages, images...)

			return nil
		}, nil
	})

	if p.enableChina && !secureBoot {
		publish.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			ctx = log.WithValues(ctx, "cloud", "china")

			images, er := p.publish(ctx, sourceChina, imagePath.S3Key, image, tags, arch, requireUEFI, uefiData, true)
			if er != nil {
				return nil, er
			}
			return func() error {
				outputImages = append(outputImages, images...)

				return nil
			}, nil
		})
	}

	err = publish.Wait()
	if err != nil {
		return nil, err
	}

	return &awsPublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *aws) publish(ctx context.Context, source ArtifactSource, key, image string, tags []ec2types.Tag, arch ec2types.ArchitectureValues,
	requireUEFI bool, uefiData *string, china bool,
) ([]awsPublishedImage, error) {
	cld := "public"
	region := p.pubCfg.Region
	regions := p.regions
	taskImage := image
	if china {
		cld = "china"
		region = p.pubCfg.RegionChina
		regions = p.regionsChina
		taskImage += "/china"
	}

	ctx = task.Begin(ctx, "publish/"+taskImage+"/"+region, &awsTaskState{
		Region: region,
		China:  china,
	})
	snapshot, err := p.importSnapshot(ctx, source, key, image, china)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot import snapshot from %s for image %s: %w", key, image, err))
	}
	ctx = log.WithValues(ctx, "snapshot", snapshot)

	err = p.attachTags(ctx, snapshot, tags, china)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot attach tags to snapshot %s: %w", snapshot, err))
	}

	var imageID string
	imageID, err = p.registerImage(ctx, snapshot, image, arch, requireUEFI, uefiData, china)
	if err != nil {
		return nil, task.Fail(ctx, fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err))
	}

	images := make(map[string]string, len(regions))
	publishImages := parallel.NewLimitedActivitySync(ctx, 12)
	for _, toRegion := range regions {
		publishImages.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			ctx = log.WithValues(ctx, "region", toRegion)
			localID := imageID
			var er error

			if toRegion != region {
				ctx = task.Begin(ctx, "publish/"+taskImage+"/"+toRegion, &awsTaskState{
					Region: toRegion,
					China:  china,
				})
				localID, er = p.copyImage(ctx, image, imageID, region, toRegion, china)
				if er != nil {
					return nil, task.Fail(ctx, fmt.Errorf("cannot copy image %s from region %s to region %s: %w", image, region,
						toRegion, er))
				}
			}
			ctx = log.WithValues(ctx, "imageID", localID)

			er = p.waitForImage(ctx, localID, toRegion, china)
			if er != nil {
				return nil, task.Fail(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", image, toRegion, er))
			}

			er = p.makePublic(ctx, localID, toRegion, china)
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
	for r, id := range images {
		outputImages = append(outputImages, awsPublishedImage{
			Cloud:  cld,
			Region: r,
			ID:     id,
			Image:  image,
		})
	}

	return outputImages, nil
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
			Key:   new("gardenlinux-version"),
			Value: &manifest.Version,
		})
	}

	if p.pubCfg.ImageTags.IncludeGardenLinuxCommittish {
		tags = append(tags, ec2types.Tag{
			Key:   new("gardenlinux-committish"),
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
			uefiData = new(string(efivars))

			return nil
		})

		err := fetchCertificates.Wait()
		if err != nil {
			return false, false, nil, err
		}
	}

	return manifest.RequireUEFI, manifest.SecureBoot, uefiData, nil
}

func (p *aws) importSnapshot(ctx context.Context, source ArtifactSource, key, image string, china bool) (string, error) {
	bucket := source.Repository()
	ctx = log.WithValues(ctx, "key", key)

	ec2Client := p.tgtClients(china)

	log.Info(ctx, "Importing snapshot")
	r, err := ec2Client.ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
		DiskContainer: &ec2types.SnapshotDiskContainer{
			Description: &image,
			Format:      new("raw"),
			UserBucket: &ec2types.UserBucket{
				S3Bucket: &bucket,
				S3Key:    &key,
			},
		},
		Encrypted: new(false),
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

func (p *aws) attachTags(ctx context.Context, obj string, tags []ec2types.Tag, china bool) error {
	ec2Client := p.tgtClients(china)

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
	uefiData *string, china bool,
) (string, error) {
	params := ec2.RegisterImageInput{
		Name:         &image,
		Architecture: arch,
		BlockDeviceMappings: []ec2types.BlockDeviceMapping{{
			DeviceName: new("/dev/xvda"),
			Ebs: &ec2types.EbsBlockDevice{
				DeleteOnTermination: new(true),
				SnapshotId:          &snapshot,
				VolumeType:          ec2types.VolumeTypeGp3,
			},
		}},
		BootMode:           ec2types.BootModeValuesUefiPreferred,
		EnaSupport:         new(true),
		ImdsSupport:        ec2types.ImdsSupportValuesV20,
		RootDeviceName:     new("/dev/xvda"),
		VirtualizationType: new("hvm"),
	}
	if requireUEFI {
		params.BootMode = ec2types.BootModeValuesUefi
	}
	if uefiData != nil {
		params.BootMode = ec2types.BootModeValuesUefi
		params.TpmSupport = ec2types.TpmSupportValuesV20
		params.UefiData = uefiData
	}

	ec2Client := p.tgtClients(china)

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

func (p *aws) copyImage(ctx context.Context, image, imageID, region, toRegion string, china bool) (string, error) {
	ec2Client := p.tgtClients(china)

	log.Info(ctx, "Copying image")
	r, err := ec2Client.CopyImage(ctx, &ec2.CopyImageInput{
		Name:          &image,
		SourceImageId: &imageID,
		SourceRegion:  &region,
		CopyImageTags: new(true),
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

func (p *aws) waitForImage(ctx context.Context, imageID, region string, china bool) error {
	ec2Client := p.tgtClients(china)

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

func (p *aws) makePublic(ctx context.Context, imageID, region string, china bool) error {
	ec2Client := p.tgtClients(china)

	log.Debug(ctx, "Adding launch permission to image")
	_, err := ec2Client.ModifyImageAttribute(ctx, &ec2.ModifyImageAttributeInput{
		ImageId:   &imageID,
		Attribute: new("launchPermission"),
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

	deregisterImages := parallel.NewLimitedActivity(ctx, 3)
	for _, img := range pubOut.Images {
		deregisterImages.Go(func(ctx context.Context) error {
			lctx := log.WithValues(ctx, "cloud", img.Cloud, "region", img.Region, "imageID", img.ID, "image", img.Image)

			china := img.Cloud == "china"

			er := p.deregisterImage(lctx, img.ID, img.Region, steamroll, china)
			if er != nil {
				return fmt.Errorf("cannot deregister image %s in region %s: %w", img.ID, img.Region, er)
			}

			return nil
		})
	}
	return deregisterImages.Wait()
}

func (p *aws) deregisterImage(ctx context.Context, imageID, region string, steamroll, china bool) error {
	ec2Client := p.tgtClients(china)

	log.Info(ctx, "Deregistering image")
	r, err := ec2Client.DeregisterImage(ctx, &ec2.DeregisterImageInput{
		ImageId:                   &imageID,
		DeleteAssociatedSnapshots: new(true),
	}, overrideRegion(region))
	if err != nil {
		terr, ok := errors.AsType[*smithy.GenericAPIError](err)
		if steamroll && ok && terr.Code == "InvalidAMIID.Unavailable" {
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

	return "aws"
}

func (p *aws) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := parallel.NewLimitedActivity(ctx, 3)
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

				er := p.deleteSnapshotFromImportTask(ctx, state.Import, state.Region, true, state.China)
				if er != nil {
					return fmt.Errorf("cannot delete snapshot from task ID %s in region %s: %w", state.Import, state.Region, er)
				}

				return nil
			})
		}

		if state.Snapshot != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "snapshot", state.Snapshot)

				er := p.deleteSnapshot(ctx, state.Snapshot, state.Region, true, state.China)
				if er != nil {
					return fmt.Errorf("cannot delete snapshot %s in region %s: %w", state.Snapshot, state.Region, er)
				}

				return nil
			})
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "image", state.Image)

				er := p.deregisterImage(ctx, state.Image, state.Region, true, state.China)
				if er != nil {
					return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, er)
				}

				return nil
			})
		}
	}
	return rollbackTasks.Wait()
}

func (p *aws) deleteSnapshotFromImportTask(ctx context.Context, importTaskID, region string, steamroll, china bool) error {
	ec2Client := p.tgtClients(china)

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

	return p.deleteSnapshot(ctx, snapshot, region, steamroll, china)
}

func (p *aws) deleteSnapshot(ctx context.Context, snapshot, region string, steamroll, china bool) error {
	ec2Client := p.tgtClients(china)

	log.Info(ctx, "Deleting snapshot")
	_, err := ec2Client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: &snapshot,
	}, overrideRegion(region))
	if err != nil {
		terr, ok := errors.AsType[*smithy.GenericAPIError](err)
		if steamroll && ok && terr.Code == "InvalidSnapshot.NotFound" {
			log.Debug(ctx, "Snapshot not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete snapshot: %w", err)
	}

	return nil
}

func (p *aws) Close() error {
	if p.srcCfg.Config != "" {
		credsType := p.Type() + "_src"
		if strings.HasPrefix(p.srcCfg.Region, "cn-") {
			credsType += "_china"
		}

		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   credsType,
			Config: p.srcCfg.Config,
		})
	}

	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
		})
	}

	if p.pubCfg.ConfigChina != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type() + "_china",
			Config: p.pubCfg.ConfigChina,
		})
	}

	return nil
}
