package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	openstacksdk "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imageimport"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"

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
	env.Clean("OS_")

	module.RegisterImpl(PublishingTargetCategory, "OpenStack", func(b *module.Base) PublishingTarget {
		return &openstack{
			base: b,
		}
	})
}

func (*openstack) Type() string {
	return "OpenStack"
}

type openstack struct {
	nonFusableTarget

	base *module.Base

	credsSource credsprovider.CredsSource
	source      ArtifactSource
	sourceChina ArtifactSource

	pubCfg openstackPublishingConfig

	environments map[string]*openstackEnvironment
}

type openstackPublishingConfig struct {
	Source      string                            `mapstructure:"source"`
	SourceChina string                            `mapstructure:"source_china,omitzero"`
	Configs     []openstackPublishingConfigConfig `mapstructure:"configs"`
	Test        bool                              `mapstructure:"test,omitzero"`
}

type openstackPublishingConfigConfig struct {
	Config   string   `mapstructure:"config"`
	Endpoint string   `mapstructure:"endpoint"`
	Domain   string   `mapstructure:"domain"`
	Project  string   `mapstructure:"project"`
	Regions  []string `mapstructure:"regions"`
}

type openstackVariant string

const (
	openstackVariantVMware openstackVariant = "vmware"
	openstackVariantMetal  openstackVariant = "metal"
)

func (p *openstack) isConfigured() bool {
	if len(p.environments) == 0 {
		return false
	}

	for _, environment := range p.environments {
		if environment.imagesClient == nil {
			return false
		}
	}

	return true
}

type openstackOperationState struct {
	Region string `json:"region,omitzero"`
	Image  string `json:"image,omitzero"`
}

type openstackPublishingOutput struct {
	Images []openstackPublishedImage `yaml:"published_openstack_images,omitempty"`
}

type openstackPublishedImage struct {
	Region  string `yaml:"region_name"`
	ID      string `yaml:"image_id"`
	Image   string `yaml:"image_name"`
	Variant string `yaml:"variant"`
}

type openstackCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type openstackEnvironment struct {
	credentials  atomic.Pointer[openstackCredentials]
	retrier      guard.Retrier
	imageRetrier guard.Retrier
	imagesClient *gophercloud.ServiceClient
}

func (p *openstack) applyCredentials(ctx context.Context, config openstackPublishingConfigConfig, rawCreds map[string]any) error {
	var creds openstackCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	initClients := concurrency.NewActivitySync(ctx)
	for _, region := range config.Regions {
		environment := p.environment(region)
		environment.credentials.Store(&creds)

		if environment.imagesClient != nil {
			continue
		}

		initClients.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			var providerClient *gophercloud.ProviderClient
			inErr := environment.retrier.Do(ctx, "authenticate", func(ctx context.Context) error {
				var inErr error
				providerClient, inErr = openstacksdk.AuthenticatedClient(ctx, openstackAuthOptions(&creds, config, region))
				return inErr
			})
			if inErr != nil {
				return nil, fmt.Errorf("cannot create provider client for region %s: %w", region, inErr)
			}

			providerClient.ReauthFunc = func(ctx context.Context) error {
				currentCreds := environment.credentials.Load()
				if currentCreds == nil {
					return errors.New("credentials not set")
				}

				return openstacksdk.Authenticate(ctx, providerClient, openstackAuthOptions(currentCreds, config, region))
			}

			var imagesClient *gophercloud.ServiceClient
			imagesClient, inErr = openstacksdk.NewImageV2(providerClient, gophercloud.EndpointOpts{
				Region: region,
			})
			if inErr != nil {
				return nil, fmt.Errorf("cannot create images client for region %s: %w", region, inErr)
			}

			return func() error {
				environment.imagesClient = imagesClient

				return nil
			}, nil
		})
	}

	return initClients.Wait()
}

func openstackAuthOptions(creds *openstackCredentials, config openstackPublishingConfigConfig, region string) gophercloud.AuthOptions { // fixme what is this
	return gophercloud.AuthOptions{
		IdentityEndpoint: strings.Replace(config.Endpoint, "{region}", region, 1),
		Username:         creds.Username,
		Password:         creds.Password,
		DomainName:       config.Domain,
		Scope: &gophercloud.AuthScope{
			ProjectName: config.Project,
			DomainName:  config.Domain,
		},
	}
}

func (p *openstack) environment(region string) *openstackEnvironment {
	return p.environments[region]
}

func (*openstack) ImageSuffix() string {
	return ".vmdk"
}

func (p *openstack) RequiredReplications(manifest *gardenlinux.Manifest) ([]Replication, error) {
	if p.sourceChina == nil || p.sourceChina == p.source {
		return nil, nil
	}

	if !slices.ContainsFunc(p.pubCfg.Configs, func(config openstackPublishingConfigConfig) bool {
		return slices.ContainsFunc(config.Regions, func(region string) bool {
			return strings.HasPrefix(region, "ap-cn-")
		})
	}) {
		return nil, nil
	}

	imagePath, err := manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, err
	}

	return []Replication{{
		Origin:        p.source,
		OriginID:      p.pubCfg.Source,
		Destination:   p.sourceChina,
		DestinationID: p.pubCfg.SourceChina,
		Key:           imagePath.S3Key,
		SHA256:        imagePath.SHA256Sum,
	}}, nil
}

func (p *openstack) imageName(flavor, version, committish string) string {
	if p.pubCfg.Test {
		flavor += "-test"
	}
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", flavor, version, committish)
}

func (*openstack) variant(platform, variant string) (openstackVariant, error) {
	if variant == "" {
		switch platform {
		case "openstack":
			return openstackVariantVMware, nil
		case "openstackbaremetal":
			return openstackVariantMetal, nil
		default:
		}
	}

	switch variant {
	case string(openstackVariantVMware):
		return openstackVariantVMware, nil
	case string(openstackVariantMetal):
		return openstackVariantMetal, nil
	default:
		return "", fmt.Errorf("invalid variant %s", variant)
	}
}

func (*openstack) architecture(arch gardenlinux.Architecture) (string, error) {
	switch arch {
	case gardenlinux.ArchitectureAMD64:
		return "AMD64", nil
	case gardenlinux.ArchitectureARM64:
		return "ARM64", nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (p *openstack) CanPublish(manifest *gardenlinux.Manifest) bool {
	if manifest.Platform != "openstack" && manifest.Platform != "openstackbaremetal" {
		return false
	}

	_, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	return err == nil
}

func (p *openstack) IsPublished(manifest *gardenlinux.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	_, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	if err != nil {
		return false, fmt.Errorf("invalid manifest: %w", err)
	}

	var openstackOutput openstackPublishingOutput
	openstackOutput, err = publishingOutputFromManifest[openstackPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	return len(openstackOutput.Images) > 0, nil
}

func (p *openstack) Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}
	if platform(flavor) != manifest.Platform {
		return nil, fmt.Errorf("flavor %s does not match platform %s", flavor, manifest.Platform)
	}
	variant, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	image := p.imageName(flavor, manifest.Version, manifest.BuildCommittish)
	var imagePath gardenlinux.S3ReleaseFile
	imagePath, err = manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", flavor, err)
	}
	ctx = log.WithValues(ctx, "image", image, "variant", variant, "architecture", arch, "source", p.pubCfg.Source)

	if p.pubCfg.SourceChina != "" {
		ctx = log.WithValues(ctx, "sourceChina", p.pubCfg.SourceChina)
	}

	outImages := make(map[string]string, len(p.environments))
	publishImages := concurrency.NewActivitySync(ctx)
	for _, config := range p.pubCfg.Configs {
		for _, region := range config.Regions {
			source := p.source
			if strings.HasPrefix(region, "ap-cn-") && p.sourceChina != nil {
				source = p.sourceChina
			}

			publishImages.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
				ctx = log.WithValues(ctx, "region", region)

				ctx = resilience.BeginOperation(ctx, "publish/"+image+"/"+region, &openstackOperationState{
					Region: region,
				})
				imageID, inErr := p.createImage(ctx, region, source, imagePath.S3Key, image, variant)
				if inErr != nil {
					return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot create image for region %s: %w", region, inErr))
				}
				ctx = log.WithValues(ctx, "region", region)

				inErr = p.waitForImage(ctx, imageID, region)
				if inErr != nil {
					return nil, resilience.FailOperation(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", imageID, region,
						inErr))
				}
				resilience.CompleteOperation(ctx)

				return func() error {
					outImages[region] = imageID

					return nil
				}, nil
			})
		}
	}
	err = publishImages.Wait()
	if err != nil {
		return nil, err
	}
	log.Info(ctx, "Images ready", "count", len(outImages))

	outputImages := make([]openstackPublishedImage, 0, len(outImages))
	for region, imageID := range outImages {
		outputImages = append(outputImages, openstackPublishedImage{
			Region:  region,
			ID:      imageID,
			Image:   image,
			Variant: string(variant),
		})
	}
	return &openstackPublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *openstack) createImage(ctx context.Context, region string, source ArtifactSource, key, image string,
	variant openstackVariant,
) (string, error) {
	var properties map[string]string
	visibility := images.ImageVisibilityCommunity
	switch variant {
	case openstackVariantVMware:
		properties = map[string]string{
			"hw_firmware_type":          "uefi",
			"hw_supported_disk_buses":   "scsi,virtio",
			"hw_supported_scsi_models":  "virtio-scsi,vmpvscsi",
			"hw_supported_vif_models":   "virtio,vmxnet3",
			"hw_video_ram":              "16",
			"hw_vif_multiqueue_enabled": "true",
			"hw_vm_mode":                "hvm",
			"vmware:hv_enabled":         "true",
			"vmware_disktype":           "streamOptimized",
			"vmware_ostype":             "debian10_64Guest",
		}
		visibility = images.ImageVisibilityPublic
	case openstackVariantMetal:
		properties = map[string]string{
			"hypervisor_type":  "baremetal",
			"os_distro":        "debian10_64Guest",
			"img_config_drive": "mandatory",
		}
	default:
		return "", fmt.Errorf("unsupported variant %s", variant)
	}
	url, err := source.GetObjectURL(ctx, key)
	if err != nil {
		return "", fmt.Errorf("cannot get image URL for %s: %w", key, err)
	}
	ctx = log.WithValues(ctx, "key", key)

	environment := p.environment(region)

	log.Info(ctx, "Creating image")
	var img *images.Image
	err = environment.retrier.Do(ctx, "create image", func(ctx context.Context) error {
		var inErr error
		img, inErr = images.Create(ctx, environment.imagesClient, images.CreateOpts{
			Name:            image,
			Visibility:      &visibility,
			ContainerFormat: "bare",
			DiskFormat:      "vmdk",
			Properties:      properties,
		}).Extract()
		return inErr
	})
	if err != nil {
		return "", fmt.Errorf("cannot create image: %w", err)
	}
	resilience.UpdateOperation(ctx, func(s *openstackOperationState) *openstackOperationState {
		s.Image = img.ID
		return s
	})
	ctx = log.WithValues(ctx, "imageID", img.ID)

	log.Debug(ctx, "Importing image")
	err = environment.retrier.Do(ctx, "import image", func(ctx context.Context) error {
		return imageimport.Create(ctx, environment.imagesClient, img.ID, imageimport.CreateOpts{
			Name: imageimport.WebDownloadMethod,
			URI:  url,
		}).ExtractErr()
	})
	if err != nil {
		return "", fmt.Errorf("cannot import image: %w", err)
	}

	return img.ID, nil
}

func (p *openstack) waitForImage(ctx context.Context, imageID, region string) error {
	environment := p.environment(region)

	return environment.imageRetrier.Do(ctx, "wait for image", func(ctx context.Context) error {
		var status images.ImageStatus
		for status != images.ImageStatusActive {
			var img *images.Image
			inErr := environment.retrier.Do(ctx, "get image", func(ctx context.Context) error {
				var inErr error
				img, inErr = images.Get(ctx, environment.imagesClient, imageID).Extract()
				return inErr
			})
			if inErr != nil {
				return fmt.Errorf("cannot get image %s in region %s: %w", imageID, region, inErr)
			}
			status = img.Status

			if status != images.ImageStatusActive {
				if status != images.ImageStatusQueued && status != images.ImageStatusSaving && status != images.ImageStatusImporting {
					return fmt.Errorf("image %s in region %s has status %s", imageID, region, status)
				}

				select {
				case <-ctx.Done():
					return ctx.Err()

				case <-time.After(statusPollInterval):
				}
			}
		}

		return nil
	})
}

func (*openstack) CanUnpublish() bool {
	return true
}

func (p *openstack) Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	variant, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	var pubOut *openstackPublishingOutput
	pubOut, err = publishingOutputFromManifest[*openstackPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if pubOut == nil || len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	ctx = log.WithValues(ctx, "variant", variant)

	removeImages := concurrency.NewActivity(ctx)
	for _, img := range pubOut.Images {
		if p.environment(img.Region) == nil {
			return fmt.Errorf("image %s is in unknown region %s", img.ID, img.Region)
		}

		removeImages.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "region", img.Region, "imageID", img.ID)

			inErr := p.deleteImage(ctx, img.ID, img.Region, steamroll)
			if err != nil {
				return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, inErr)
			}

			return nil
		})
	}
	return removeImages.Wait()
}

func (p *openstack) deleteImage(ctx context.Context, id, region string, steamroll bool) error {
	environment := p.environment(region)
	if environment == nil {
		return fmt.Errorf("unknown region %s", region)
	}

	log.Info(ctx, "Deleting image")
	err := environment.retrier.Do(ctx, "delete image", func(ctx context.Context) error {
		return images.Delete(ctx, environment.imagesClient, id).ExtractErr()
	})
	if err != nil {
		terr, ok := errors.AsType[gophercloud.ErrUnexpectedResponseCode](err)
		if steamroll && ok && terr.Actual == http.StatusNotFound {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}

func (p *openstack) RollbackDomain() string {
	if !p.isConfigured() {
		return ""
	}

	return "openstack"
}

func (p *openstack) Rollback(ctx context.Context, operations map[string]resilience.Operation) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := concurrency.NewActivity(ctx)
	for _, op := range operations {
		state, err := resilience.ParseOperationState[*openstackOperationState](op.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "image", state.Image)

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

func (p *openstack) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.pubCfg)
	if err != nil {
		return err
	}

	switch {
	case p.pubCfg.Source == "":
		return errors.New("missing source")
	case len(p.pubCfg.Configs) == 0:
		return errors.New("missing configs")
	}

	cs := make(map[string]struct{}, len(p.pubCfg.Configs))
	rs := make(map[string]struct{})
	for _, config := range p.pubCfg.Configs {
		_, ok := cs[config.Config]
		switch {
		case config.Config == "":
			return errors.New("invalid config")
		case ok:
			return fmt.Errorf("duplicate config %s", config.Config)
		case config.Endpoint == "":
			return fmt.Errorf("missing endpoint for config %s", config.Config)
		case strings.Count(config.Endpoint, "{region}") != 1:
			return fmt.Errorf("invalid endpoint for config %s", config.Config)
		case config.Domain == "":
			return fmt.Errorf("missing domain for config %s", config.Config)
		case config.Project == "":
			return fmt.Errorf("missing project for config %s", config.Config)
		case len(config.Regions) == 0:
			return fmt.Errorf("missing regions for config %s", config.Config)
		}

		cs[config.Config] = struct{}{}
		for _, r := range config.Regions {
			_, ok = rs[r]
			if ok {
				return fmt.Errorf("duplicate region %s", r)
			}
			rs[r] = struct{}{}
		}
	}

	p.environments = make(map[string]*openstackEnvironment, len(rs))
	for _, config := range p.pubCfg.Configs {
		for _, region := range config.Regions {
			p.environments[region] = &openstackEnvironment{
				retrier:      guard.NewRetrier(guard.CountingRetryPolicy{}, guard.BoundedTimeoutPolicy{}),
				imageRetrier: guard.NewRetrier(guard.DelegatingRetryPolicy{}, guard.NewCustomTimeoutPolicy(time.Minute*7)),
			}
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

	if p.pubCfg.SourceChina != "" {
		err = module.RegisterRef[ArtifactSource](p.base, p, &p.sourceChina, p.pubCfg.SourceChina)
		if err != nil {
			return fmt.Errorf("cannot register source: %w", err)
		}
	}

	return nil
}

func (*openstack) Configurables() []module.Configurable {
	return nil
}

func (p *openstack) Start(ctx context.Context) error {
	for _, config := range p.pubCfg.Configs {
		err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: config.Config,
			Role:   "target",
		}, func(ctx context.Context, creds map[string]any) error {
			return p.applyCredentials(ctx, config, creds)
		})
		if err != nil {
			return fmt.Errorf("cannot acquire credentials for config %s: %w", config.Config, err)
		}
	}

	return nil
}

func (p *openstack) Stop(ctx context.Context) error {
	for _, config := range p.pubCfg.Configs {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: config.Config,
			Role:   "target",
		})
	}

	return nil
}
