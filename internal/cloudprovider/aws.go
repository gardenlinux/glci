package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4" // Package is named v4, and someone at Amazon needs to learn Go.
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/errorreport"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("AWS_")
	env.Clean("_X_AMZN_")

	module.RegisterImpl(ArtifactSourceCategory, "AWS", func(b *module.Base) ArtifactSource {
		p := &awsSource{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})

		return p
	})

	module.RegisterImpl(PublishingTargetCategory, "AWS", func(b *module.Base) PublishingTarget {
		p := &awsTarget{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})
		p.retrierChina = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.clientsGenChina.Load()
		}), guard.DelegatingTimeoutPolicy{})
		return p
	})
}

func (*awsSource) Type() string {
	return "AWS"
}

func (*awsTarget) Type() string {
	return "AWS"
}

type awsSource struct {
	base *module.Base

	credsSource credsprovider.CredsSource

	srcCfg  awsSourceConfig
	retrier guard.Retrier

	clientsMtx sync.RWMutex
	clients    awsSourceClients
	clientsGen atomic.Uint64
}

type awsSourceClients struct {
	s3 *s3.Client
}

type awsTarget struct {
	nonFusableTarget

	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource
	sourceChina ArtifactSource

	pubCfg       awsPublishingConfig
	enableChina  bool
	retrier      guard.Retrier
	retrierChina guard.Retrier

	clientsMtx      sync.RWMutex
	clients         awsTargetClients
	clientsGen      atomic.Uint64
	clientsGenChina atomic.Uint64
	regions         []string
	regionsChina    []string
}

type awsTargetClients struct {
	ec2 *ec2.Client

	ec2China *ec2.Client
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

func (p *awsTarget) isConfigured() bool {
	return p.ec2Client(false) != nil
}

type awsOperationState struct {
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

func (p *awsSource) createClients(ctx context.Context, rawCreds map[string]any) error {
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
				o.MaxAttempts = guard.Retries + 1
				o.MaxBackoff = guard.RetryMaxDelay
				o.RateLimiter = ratelimit.None
			})
		}), config.WithHTTPClient(awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
			t.ResponseHeaderTimeout = guard.Timeout
		})))
	if err != nil {
		return fmt.Errorf("cannot load default config: %w", err)
	}
	p.clients.s3 = s3.NewFromConfig(awsCfg)
	p.clientsGen.Add(1)

	return nil
}

func (p *awsTarget) createClients(ctx context.Context, rawCreds map[string]any, china bool) error {
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
				o.MaxAttempts = guard.Retries + 1
				o.MaxBackoff = guard.RetryMaxDelay
				o.RateLimiter = ratelimit.None
			})
		}), config.WithHTTPClient(awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
			t.ResponseHeaderTimeout = guard.Timeout
		})))
	if err != nil {
		return fmt.Errorf("cannot load default AWS config: %w", err)
	}
	ec2Client := ec2.NewFromConfig(awsCfg)

	var regions []string
	regions, err = p.listRegions(ctx, ec2Client)
	if err != nil {
		return fmt.Errorf("cannot list regions: %w", err)
	}

	if china {
		if len(p.pubCfg.RegionsChina) > 0 {
			regions = subset(regions, p.pubCfg.RegionsChina)
		}
		if len(regions) == 0 {
			return errors.New("no available regions")
		}
		if !slices.Contains(regions, region) {
			return fmt.Errorf("region %s is not available", region)
		}

		if len(p.regionsChina) > 0 && !equalSets(regions, p.regionsChina) {
			return errorreport.MarkCritical(errors.New("available regions changed"))
		}

		p.clients.ec2China = ec2Client
		p.regionsChina = regions
		p.clientsGenChina.Add(1)
	} else {
		if len(p.pubCfg.Regions) > 0 {
			regions = subset(regions, p.pubCfg.Regions)
		}
		if len(regions) == 0 {
			return errors.New("no available regions")
		}
		if !slices.Contains(regions, region) {
			return fmt.Errorf("region %s is not available", region)
		}

		if len(p.regions) > 0 && !equalSets(regions, p.regions) {
			return errorreport.MarkCritical(errors.New("available regions changed"))
		}

		p.clients.ec2 = ec2Client
		p.regions = regions
		p.clientsGen.Add(1)
	}

	return nil
}

func (p *awsTarget) listRegions(ctx context.Context, ec2Client *ec2.Client) ([]string, error) {
	log.Debug(ctx, "Listing available regions")
	var r *ec2.DescribeRegionsOutput
	err := p.retrier.Do(ctx, "describe regions", func(ctx context.Context) error {
		var inErr error
		r, inErr = ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
		return inErr
	})
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

func (p *awsSource) getClients() awsSourceClients {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.clients
}

func (p *awsSource) s3Client() *s3.Client {
	return p.getClients().s3
}

func (p *awsTarget) getClients() awsTargetClients {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.clients
}

func (p *awsTarget) ec2Client(china bool) *ec2.Client {
	if china {
		return p.getClients().ec2China
	}

	return p.getClients().ec2
}

func (p *awsTarget) getRegions(china bool) []string {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	if china {
		return p.regionsChina
	}

	return p.regions
}

func (p *awsTarget) getRetrier(china bool) guard.Retrier {
	if china {
		return p.retrierChina
	}

	return p.retrier
}

func (*awsTarget) ImageSuffix() string {
	return ".raw"
}

func (*awsTarget) imageName(flavor, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", flavor, version, committish)
}

func (*awsTarget) architecture(arch gardenlinux.Architecture) (ec2types.ArchitectureValues, error) {
	switch arch {
	case gardenlinux.ArchitectureAMD64:
		return ec2types.ArchitectureValuesX8664, nil
	case gardenlinux.ArchitectureARM64:
		return ec2types.ArchitectureValuesArm64, nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (p *awsSource) Repository() string {
	return p.srcCfg.Bucket
}

func (p *awsSource) GetObjectURL(ctx context.Context, key string) (string, error) {
	if p.s3Client() == nil {
		return "", errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Getting presigned URL", "bucket", p.srcCfg.Bucket, "key", key)
	var presigned *signer.PresignedHTTPRequest
	err := p.retrier.Do(ctx, "presign get object", func(ctx context.Context) error {
		presignClient := s3.NewPresignClient(p.s3Client(), func(o *s3.PresignOptions) {
			o.Expires = time.Hour * 7
		})
		var inErr error
		presigned, inErr = presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: &p.srcCfg.Bucket,
			Key:    &key,
		})
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot get presigned URL: %w", err)
	}

	return presigned.URL, nil
}

func (p *awsSource) GetObjectSize(ctx context.Context, key string) (int64, error) {
	if p.s3Client() == nil {
		return 0, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Heading object", "bucket", p.srcCfg.Bucket, "key", key)
	var r *s3.HeadObjectOutput
	err := p.retrier.Do(ctx, "head object", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.s3Client().HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: &p.srcCfg.Bucket,
			Key:    &key,
		})
		return inErr
	})
	if err != nil {
		_, ok := errors.AsType[*s3types.NoSuchKey](err)
		if ok {
			err = &KeyNotFoundError{
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

func (p *awsSource) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	if p.s3Client() == nil {
		return nil, errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Getting object", "bucket", p.srcCfg.Bucket, "key", key)

	return guard.NewRetryingReader(ctx, guard.NewRetrier(guard.CountingRetryPolicy{}, guard.DelegatingTimeoutPolicy{}), awsContentSource{
		retrier: p.retrier,
		client:  p.s3Client,
		bucket:  p.srcCfg.Bucket,
		key:     key,
	})
}

type awsContentSource struct {
	retrier guard.Retrier
	client  func() *s3.Client
	bucket  string
	key     string
}

func (s awsContentSource) Open(ctx context.Context, offset int64, identity string) (guard.Content, error) {
	input := &s3.GetObjectInput{
		Bucket: &s.bucket,
		Key:    &s.key,
	}
	if offset > 0 {
		input.Range = new(fmt.Sprintf("bytes=%d-", offset))
	}
	if identity != "" {
		input.IfMatch = &identity
	}
	var output *s3.GetObjectOutput
	err := s.retrier.Do(ctx, "get object", func(ctx context.Context) error {
		var inErr error
		output, inErr = s.client().GetObject(ctx, input)
		return inErr
	})
	if err != nil {
		_, ok := errors.AsType[*s3types.NoSuchKey](err)
		if ok {
			err = &KeyNotFoundError{
				err: err,
			}
		}

		return guard.Content{}, err
	}
	if output.Body == nil {
		return guard.Content{}, errors.New("missing body")
	}

	content := guard.Content{
		ReadCloser: output.Body,
		Size:       -1,
		CanResume:  output.AcceptRanges != nil && *output.AcceptRanges == "bytes",
	}
	if output.ETag != nil {
		content.Identity = *output.ETag
	}
	if output.ContentLength != nil {
		content.Size = *output.ContentLength
	}

	return content, nil
}

func (p *awsSource) PutObject(ctx context.Context, key string, object io.Reader) error {
	if p.s3Client() == nil {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "source", p.Type())

	log.Debug(ctx, "Putting object", "bucket", p.srcCfg.Bucket, "key", key)
	err := p.retrier.Do(ctx, "put object", func(ctx context.Context) error {
		_, inErr := p.s3Client().PutObject(ctx, &s3.PutObjectInput{
			Bucket:          &p.srcCfg.Bucket,
			Key:             &key,
			Body:            object,
			ContentEncoding: new("utf-8"),
			ContentType:     new("text/yaml"),
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot put object %s to bucket %s: %w", key, p.srcCfg.Bucket, err)
	}

	return nil
}

func (p *awsTarget) CanPublish(manifest *gardenlinux.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return manifest.Platform == "aws"
}

func (p *awsTarget) IsPublished(manifest *gardenlinux.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	awsOutput, err := publishingOutputFromManifest[awsPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return len(awsOutput.Images) > 0, nil
}

func (p *awsTarget) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	pl := platform(flavor)
	if pl != "aws" {
		return nil, fmt.Errorf("invalid flavor %s for target %s", flavor, p.Type())
	}
	if pl != manifest.Platform {
		return nil, fmt.Errorf("flavor %s does not match platform %s", flavor, manifest.Platform)
	}

	ctx = log.WithValues(ctx, "sourceType", p.source.Type(), "sourceRepo", p.source.Repository())
	if p.pubCfg.SourceChina != "" {
		ctx = log.WithValues(ctx, "sourceChinaType", p.sourceChina.Type(), "sourceChinaRepo", p.sourceChina.Repository())
	}

	image := p.imageName(flavor, manifest.Version, manifest.BuildCommittish)
	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}

	var arch ec2types.ArchitectureValues
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", flavor, err)
	}
	tags := p.prepareTags(manifest)

	var requireUEFI, secureBoot bool
	var uefiData *string
	requireUEFI, secureBoot, uefiData, err = p.prepareSecureBoot(ctx, p.source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}

	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

	outputImages := make([]awsPublishedImage, 0, 4)
	publish := concurrency.NewActivitySync(ctx)

	publish.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
		ctx = log.WithValues(ctx, "cloud", "public")

		images, er := p.publish(ctx, p.source, imagePath.S3Key, image, tags, arch, requireUEFI, uefiData, false)
		if er != nil {
			return nil, er
		}
		return func() error {
			outputImages = append(outputImages, images...)

			return nil
		}, nil
	})

	if p.enableChina && !secureBoot {
		publish.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			ctx = log.WithValues(ctx, "cloud", "china")

			source := p.sourceChina
			if source == nil {
				source = p.source
			}

			images, er := p.publish(ctx, source, imagePath.S3Key, image, tags, arch, requireUEFI, uefiData, true)
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

func (p *awsTarget) publish(ctx context.Context, source ArtifactSource, key, image string, tags []ec2types.Tag,
	arch ec2types.ArchitectureValues, requireUEFI bool, uefiData *string, china bool,
) ([]awsPublishedImage, error) {
	cld := "public"
	region := p.pubCfg.Region
	regions := p.getRegions(china)
	taskImage := image
	if china {
		cld = "china"
		region = p.pubCfg.RegionChina
		taskImage += "/china"
	}

	ctx = resilience.BeginOperation(ctx, "publish/"+taskImage+"/"+region, &awsOperationState{
		China:  china,
		Region: region,
	})
	snapshot, err := p.importSnapshot(ctx, source, key, image, china)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot import snapshot from %s for image %s: %w", key, image, err))
	}
	ctx = log.WithValues(ctx, "snapshot", snapshot)

	err = p.attachTags(ctx, snapshot, tags, china)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot attach tags to snapshot %s: %w", snapshot, err))
	}

	var imageID string
	imageID, err = p.registerImage(ctx, snapshot, image, arch, requireUEFI, uefiData, china)
	if err != nil {
		return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot register image %s from snapshot %s: %w", image, snapshot, err))
	}

	images := make(map[string]string, len(regions))
	publishImages := concurrency.NewActivitySync(ctx)
	for _, toRegion := range regions {
		publishImages.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			ctx = log.WithValues(ctx, "region", toRegion)
			localID := imageID
			var er error

			if toRegion != region {
				ctx = resilience.BeginOperation(ctx, "publish/"+taskImage+"/"+toRegion, &awsOperationState{
					China:  china,
					Region: toRegion,
				})
				localID, er = p.copyImage(ctx, image, imageID, region, toRegion, china)
				if er != nil {
					return nil, resilience.FailOperation(ctx,
						fmt.Errorf("cannot copy image %s from region %s to region %s: %w", image, region, toRegion, er))
				}
			}
			ctx = log.WithValues(ctx, "imageID", localID)

			er = p.waitForImage(ctx, localID, toRegion, china)
			if er != nil {
				return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", image, toRegion, er))
			}

			er = p.makePublic(ctx, localID, toRegion, china)
			if er != nil {
				return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot make image %s public in region %s: %w", image, toRegion, er))
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

func (p *awsTarget) prepareTags(manifest *gardenlinux.Manifest) []ec2types.Tag {
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

func (*awsTarget) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gardenlinux.Manifest) (bool, bool, *string, error,
) {
	var uefiData *string

	if manifest.SecureBoot {
		fetchCertificates := concurrency.NewActivity(ctx)

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

func (p *awsTarget) importSnapshot(ctx context.Context, source ArtifactSource, key, image string, china bool) (string, error) {
	bucket := source.Repository()
	ctx = log.WithValues(ctx, "key", key)

	log.Info(ctx, "Importing snapshot")
	var r *ec2.ImportSnapshotOutput
	err := p.getRetrier(china).Do(ctx, "import snapshot", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.ec2Client(china).ImportSnapshot(ctx, &ec2.ImportSnapshotInput{
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
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot import snapshot in bucket %s: %w", bucket, err)
	}
	if r.ImportTaskId == nil {
		return "", fmt.Errorf("cannot import snapshot in bucket %s: missing import task ID", bucket)
	}
	importTaskID := *r.ImportTaskId
	resilience.UpdateOperation(ctx, func(s *awsOperationState) *awsOperationState {
		s.Import = importTaskID
		return s
	})
	ctx = log.WithValues(ctx, "taskId", importTaskID)

	var snapshot string
	status := "active"
	for status == "active" {
		var s *ec2.DescribeImportSnapshotTasksOutput
		err = p.getRetrier(china).Do(ctx, "describe import snapshot tasks", func(ctx context.Context) error {
			var inErr error
			s, inErr = p.ec2Client(china).DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
				ImportTaskIds: []string{*r.ImportTaskId},
			})
			return inErr
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
			select {
			case <-ctx.Done():
				return "", ctx.Err()

			case <-time.After(statusPollInterval):
			}
		}
	}
	if status != "completed" {
		return "", fmt.Errorf("unknown import task status %s in bucket %s", status, bucket)
	}
	if snapshot == "" {
		return "", fmt.Errorf("cannot describe import snapshot tasks with ID %s: missing snapshot ID", *r.ImportTaskId)
	}
	resilience.UpdateOperation(ctx, func(s *awsOperationState) *awsOperationState {
		s.Import = ""
		s.Snapshot = snapshot
		return s
	})
	log.Debug(ctx, "Snapshot imported")

	return snapshot, nil
}

func (p *awsTarget) attachTags(ctx context.Context, obj string, tags []ec2types.Tag, china bool) error {
	log.Debug(ctx, "Attaching tags", "object", obj)
	err := p.getRetrier(china).Do(ctx, "create tags", func(ctx context.Context) error {
		_, inErr := p.ec2Client(china).CreateTags(ctx, &ec2.CreateTagsInput{
			Resources: []string{obj},
			Tags:      tags,
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot create tags for %s: %w", obj, err)
	}

	return nil
}

func (p *awsTarget) registerImage(ctx context.Context, snapshot, image string, arch ec2types.ArchitectureValues, requireUEFI bool,
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

	log.Info(ctx, "Registering image")
	var r *ec2.RegisterImageOutput
	err := p.getRetrier(china).Do(ctx, "register image", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.ec2Client(china).RegisterImage(ctx, &params)
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot register image: %w", err)
	}
	if r.ImageId == nil {
		return "", errors.New("cannot register image: missing image ID")
	}
	imageID := *r.ImageId
	resilience.UpdateOperation(ctx, func(s *awsOperationState) *awsOperationState {
		s.Snapshot = ""
		s.Image = imageID
		return s
	})

	return imageID, nil
}

func (p *awsTarget) copyImage(ctx context.Context, image, imageID, region, toRegion string, china bool) (string, error) {
	log.Info(ctx, "Copying image")
	var r *ec2.CopyImageOutput
	err := p.getRetrier(china).Do(ctx, "copy image", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.ec2Client(china).CopyImage(ctx, &ec2.CopyImageInput{
			Name:          &image,
			SourceImageId: &imageID,
			SourceRegion:  &region,
			CopyImageTags: new(true),
		}, overrideRegion(toRegion))
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot copy image: %w", err)
	}
	if r.ImageId == nil {
		return "", errors.New("cannot copy image: missing image ID")
	}
	toImageID := *r.ImageId
	resilience.UpdateOperation(ctx, func(s *awsOperationState) *awsOperationState {
		s.Image = toImageID
		return s
	})

	return toImageID, nil
}

func (p *awsTarget) waitForImage(ctx context.Context, imageID, region string, china bool) error {
	var state ec2types.ImageState
	for state != ec2types.ImageStateAvailable {
		var r *ec2.DescribeImagesOutput
		err := p.getRetrier(china).Do(ctx, "describe images", func(ctx context.Context) error {
			var inErr error
			r, inErr = p.ec2Client(china).DescribeImages(ctx, &ec2.DescribeImagesInput{
				ImageIds: []string{imageID},
			}, overrideRegion(region))
			return inErr
		})
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

			select {
			case <-ctx.Done():
				return ctx.Err()

			case <-time.After(statusPollInterval):
			}
		}
	}

	return nil
}

func (p *awsTarget) makePublic(ctx context.Context, imageID, region string, china bool) error {
	log.Debug(ctx, "Adding launch permission to image")
	err := p.getRetrier(china).Do(ctx, "modify image attribute", func(ctx context.Context) error {
		_, inErr := p.ec2Client(china).ModifyImageAttribute(ctx, &ec2.ModifyImageAttributeInput{
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
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot modify attribute: %w", err)
	}

	return nil
}

func (*awsTarget) CanUnpublish() bool {
	return true
}

func (p *awsTarget) Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error {
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

	deregisterImages := concurrency.NewActivity(ctx)
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

func (p *awsTarget) deregisterImage(ctx context.Context, imageID, region string, steamroll, china bool) error {
	log.Info(ctx, "Deregistering image")
	var r *ec2.DeregisterImageOutput
	err := p.getRetrier(china).Do(ctx, "deregister image", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.ec2Client(china).DeregisterImage(ctx, &ec2.DeregisterImageInput{
			ImageId:                   &imageID,
			DeleteAssociatedSnapshots: new(true),
		}, overrideRegion(region))
		return inErr
	})
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

func (p *awsTarget) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "aws"
}

func (p *awsTarget) Rollback(ctx context.Context, operations map[string]resilience.Operation) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := concurrency.NewActivity(ctx)
	for _, op := range operations {
		state, err := resilience.ParseOperationState[*awsOperationState](op.State)
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

func (p *awsTarget) deleteSnapshotFromImportTask(ctx context.Context, importTaskID, region string, steamroll, china bool) error {
	log.Debug(ctx, "Determining snapshot")
	var snapshot string
	status := "active"
	for status == "active" {
		var s *ec2.DescribeImportSnapshotTasksOutput
		err := p.getRetrier(china).Do(ctx, "describe import snapshot tasks", func(ctx context.Context) error {
			var inErr error
			s, inErr = p.ec2Client(china).DescribeImportSnapshotTasks(ctx, &ec2.DescribeImportSnapshotTasksInput{
				ImportTaskIds: []string{importTaskID},
			}, overrideRegion(region))
			return inErr
		})
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
			select {
			case <-ctx.Done():
				return ctx.Err()

			case <-time.After(statusPollInterval):
			}
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

func (p *awsTarget) deleteSnapshot(ctx context.Context, snapshot, region string, steamroll, china bool) error {
	log.Info(ctx, "Deleting snapshot")
	err := p.getRetrier(china).Do(ctx, "delete snapshot", func(ctx context.Context) error {
		_, inErr := p.ec2Client(china).DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
			SnapshotId: &snapshot,
		}, overrideRegion(region))
		return inErr
	})
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

func (p *awsSource) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.srcCfg)
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

	err = module.RegisterTypeRef[credsprovider.CredsSource](p.base, p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	return nil
}

func (*awsSource) Configurables() []module.Configurable {
	return nil
}

func (p *awsSource) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.srcCfg.Config,
		Role:   "source",
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.srcCfg.Config, err)
	}

	return nil
}

func (p *awsSource) Stop() error {
	if p.srcCfg.Config != "" {
		p.credsSource.ReleaseCreds(context.Background(), credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.srcCfg.Config,
			Role:   "source",
		})
	}

	return nil
}

func (p *awsTarget) Configure(rawCfg map[string]any) error {
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

		if len(p.pubCfg.RegionsChina) > 0 {
			if !slices.Contains(p.pubCfg.RegionsChina, p.pubCfg.RegionChina) {
				return fmt.Errorf("region %s missing from list of regions", p.pubCfg.RegionChina)
			}
		}

		p.enableChina = true
	}

	err = module.RegisterTypeRef[credsprovider.CredsSource](p.base, p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	err = module.RegisterRef[ArtifactSource](p.base, p, &p.source, p.pubCfg.Source)
	if err != nil {
		return fmt.Errorf("cannot register source: %w", err)
	}

	if p.pubCfg.SourceChina != "" {
		err = module.RegisterRef[ArtifactSource](p.base, p, &p.sourceChina, p.pubCfg.SourceChina)
		if err != nil {
			return fmt.Errorf("cannot register source: %w", err)
		}
	}

	return nil
}

func (*awsTarget) Configurables() []module.Configurable {
	return nil
}

func (p *awsTarget) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.pubCfg.Config,
		Role:   "target",
	}, func(ctx context.Context, creds map[string]any) error {
		return p.createClients(ctx, creds, false)
	})
	if err != nil {
		return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.Config, err)
	}

	if p.enableChina {
		err = p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.ConfigChina,
			Role:   "target",
		}, func(ctx context.Context, creds map[string]any) error {
			return p.createClients(ctx, creds, true)
		})
		if err != nil {
			return fmt.Errorf("cannot acquire credentials for config %s: %w", p.pubCfg.ConfigChina, err)
		}
	}

	return nil
}

func (p *awsTarget) Stop() error {
	if p.pubCfg.Config != "" {
		p.credsSource.ReleaseCreds(context.Background(), credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.Config,
			Role:   "target",
		})
	}

	if p.pubCfg.ConfigChina != "" {
		p.credsSource.ReleaseCreds(context.Background(), credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.pubCfg.ConfigChina,
			Role:   "target",
		})
	}

	return nil
}
