package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	openstacksdk "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imageimport"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/task"
)

func init() {
	env.Clean("OS_")

	registerPublishingTarget(func() PublishingTarget {
		return &openstack{}
	})
}

func (*openstack) Type() string {
	return "OpenStack"
}

type openstack struct {
	pubCfg        openstackPublishingConfig
	credsSource   credsprovider.CredsSource
	clientsMtx    sync.RWMutex
	imagesClients map[string]*gophercloud.ServiceClient
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
	imagesClients := p.clients()

	return len(imagesClients) > 0
}

func (p *openstack) SetTargetConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg map[string]any,
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
	case len(p.pubCfg.Configs) == 0:
		return errors.New("missing configs")
	}

	_, ok := sources[p.pubCfg.Source]
	if !ok {
		return fmt.Errorf("unknown source %s", p.pubCfg.Source)
	}
	if p.pubCfg.SourceChina != "" {
		_, ok = sources[p.pubCfg.SourceChina]
		if !ok {
			return fmt.Errorf("unknown source %s", p.pubCfg.Source)
		}
	}

	cs := make(map[string]struct{}, len(p.pubCfg.Configs))
	rs := make(map[string]struct{})
	for _, config := range p.pubCfg.Configs {
		_, ok = cs[config.Config]
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

	func() {
		p.clientsMtx.Lock()
		defer p.clientsMtx.Unlock()

		p.imagesClients = make(map[string]*gophercloud.ServiceClient, len(rs))
	}()

	for _, config := range p.pubCfg.Configs {
		err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: config.Config,
		}, func(ctx context.Context, creds map[string]any) error {
			return p.createClients(ctx, config, creds)
		})
		if err != nil {
			return fmt.Errorf("cannot acquire credentials for config %s: %w", config.Config, err)
		}
	}

	return nil
}

type openstackTaskState struct {
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

func (p *openstack) createClients(ctx context.Context, config openstackPublishingConfigConfig, rawCreds map[string]any) error {
	var creds openstackCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	initClients := parallel.NewLimitedActivitySync(ctx, 7)
	for _, region := range config.Regions {
		initClients.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			providerClient, er := openstacksdk.AuthenticatedClient(ctx, gophercloud.AuthOptions{
				IdentityEndpoint: strings.Replace(config.Endpoint, "{region}", region, 1),
				Username:         creds.Username,
				Password:         creds.Password,
				DomainName:       config.Domain,
				Scope: &gophercloud.AuthScope{
					ProjectName: config.Project,
					DomainName:  config.Domain,
				},
			})
			if er != nil {
				return nil, fmt.Errorf("cannot create provider client for region %s: %w", region, er)
			}

			var client *gophercloud.ServiceClient
			client, er = openstacksdk.NewImageV2(providerClient, gophercloud.EndpointOpts{
				Region: region,
			})
			if er != nil {
				return nil, fmt.Errorf("cannot create image client for region %s: %w", region, er)
			}

			return func() error {
				p.imagesClients[region] = client

				return nil
			}, nil
		})
	}

	return initClients.Wait()
}

func (p *openstack) clients() map[string]*gophercloud.ServiceClient {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.imagesClients
}

func (*openstack) imageName(cname, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", cname, version, committish)
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

func (*openstack) architecture(arch gl.Architecture) (string, error) {
	switch arch {
	case gl.ArchitectureAMD64:
		return "AMD64", nil
	case gl.ArchitectureARM64:
		return "ARM64", nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (*openstack) ImageSuffix() string {
	return ".vmdk"
}

func (p *openstack) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	_, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	return err == nil
}

func (p *openstack) IsPublished(manifest *gl.Manifest) (bool, error) {
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

func (p *openstack) AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	openstackOutput, err := publishingOutput[openstackPublishingOutput](output)
	if err != nil {
		return nil, err
	}
	var ownOutput openstackPublishingOutput
	ownOutput, err = publishingOutput[openstackPublishingOutput](own)
	if err != nil {
		return nil, err
	}

	if len(openstackOutput.Images) > 0 {
		return nil, errors.New("cannot add publishing output to existing publishing output")
	}

	return &ownOutput, nil
}

func (p *openstack) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	_, err := publishingOutput[openstackPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (p *openstack) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}
	if manifest.Platform == "metal,openstackbaremetal" { // A terrible workaround, please remove a soon as possible.
		manifest.Platform = "openstackbaremetal"
	}
	if platform(cname) != manifest.Platform {
		return nil, fmt.Errorf("cname %s does not match platform %s", cname, manifest.Platform)
	}
	variant, err := p.variant(manifest.Platform, manifest.PlatformVariant)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	image := p.imageName(cname, manifest.Version, manifest.BuildCommittish)
	var imagePath gl.S3ReleaseFile
	imagePath, err = manifest.PathBySuffix(p.ImageSuffix())
	if err != nil {
		return nil, fmt.Errorf("missing image: %w", err)
	}
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	ctx = log.WithValues(ctx, "image", image, "variant", variant, "architecture", arch, "sourceType", source.Type(),
		"sourceRepo", source.Repository())

	sourceChina := source
	if p.pubCfg.SourceChina != "" {
		sourceChina = sources[p.pubCfg.SourceChina]
	}

	imagesClients := p.clients()
	outImages := make(map[string]string, len(imagesClients))
	publishImages := parallel.NewActivitySync(ctx)
	for _, config := range p.pubCfg.Configs {
		for _, region := range config.Regions {
			imageClient := imagesClients[region]
			src := source
			if strings.HasPrefix(region, "ap-cn-") {
				src = sourceChina
			}

			publishImages.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
				ctx = log.WithValues(ctx, "region", region)

				ctx = task.Begin(ctx, "publish/"+image+"/"+region, &openstackTaskState{
					Region: region,
				})
				imageID, er := p.createImage(ctx, imageClient, src, imagePath.S3Key, image, variant)
				if er != nil {
					return nil, task.Fail(ctx, fmt.Errorf("cannot create image for region %s: %w", region, er))
				}
				ctx = log.WithValues(ctx, "region", region)

				er = p.waitForImage(ctx, imageID, region)
				if er != nil {
					return nil, task.Fail(ctx, fmt.Errorf("cannot finalize image %s in region %s: %w", imageID, region, er))
				}
				task.Complete(ctx)

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

func (*openstack) createImage(ctx context.Context, imageClient *gophercloud.ServiceClient, source ArtifactSource, key, image string,
	variant openstackVariant,
) (string, error) {
	var properties map[string]string
	visibility := images.ImageVisibilityCommunity
	switch variant {
	case openstackVariantVMware:
		properties = map[string]string{
			"hypervisor_type":    "vmware",
			"hw_disk_bus":        "scsi",
			"hw_firmware_type":   "uefi",
			"hw_vif_model":       "vmxnet3",
			"vmware_adaptertype": "paraVirtual",
			"vmware_disktype":    "streamOptimized",
			"vmware_ostype":      "debian10_64Guest",
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

	log.Info(ctx, "Creating image")
	var img *images.Image
	img, err = images.Create(ctx, imageClient, images.CreateOpts{
		Name:            image,
		Visibility:      &visibility,
		ContainerFormat: "bare",
		DiskFormat:      "vmdk",
		Properties:      properties,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("cannot create image: %w", err)
	}
	task.Update(ctx, func(s *openstackTaskState) *openstackTaskState {
		s.Image = img.ID
		return s
	})
	ctx = log.WithValues(ctx, "imageID", img.ID)

	log.Debug(ctx, "Importing image")
	err = imageimport.Create(ctx, imageClient, img.ID, imageimport.CreateOpts{
		Name: imageimport.WebDownloadMethod,
		URI:  url,
	}).ExtractErr()
	if err != nil {
		return "", fmt.Errorf("cannot import image: %w", err)
	}

	return img.ID, nil
}

func (p *openstack) waitForImage(ctx context.Context, imageID, region string) error {
	imagesClients := p.clients()

	var status images.ImageStatus
	for status != images.ImageStatusActive {
		img, err := images.Get(ctx, imagesClients[region], imageID).Extract()
		if err != nil {
			return fmt.Errorf("cannot get image %s in region %s: %w", imageID, region, err)
		}
		status = img.Status

		if status != images.ImageStatusActive {
			if status != images.ImageStatusQueued && status != images.ImageStatusSaving && status != images.ImageStatusImporting {
				return fmt.Errorf("image %s in region %s has status %s", imageID, region, status)
			}

			time.Sleep(time.Second * 7)
		}
	}

	return nil
}

func (p *openstack) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
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

	imagesClients := p.clients()

	removeImages := parallel.NewLimitedActivity(ctx, 3)
	for _, img := range pubOut.Images {
		_, ok := imagesClients[img.Region]
		if !ok {
			return fmt.Errorf("image %s is in unknown region %s", img.ID, img.Region)
		}

		removeImages.Go(func(ctx context.Context) error {
			ctx = log.WithValues(ctx, "region", img.Region, "imageID", img.ID)

			er := p.deleteImage(ctx, img.ID, img.Region, steamroll)
			if err != nil {
				return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, er)
			}

			return nil
		})
	}
	return removeImages.Wait()
}

func (p *openstack) deleteImage(ctx context.Context, id, region string, steamroll bool) error {
	imagesClients := p.clients()

	log.Info(ctx, "Deleting image")
	err := images.Delete(ctx, imagesClients[region], id).ExtractErr()
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

func (p *openstack) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "openstack"
}

func (p *openstack) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	rollbackTasks := parallel.NewLimitedActivity(ctx, 3)
	for _, t := range tasks {
		state, err := task.ParseState[*openstackTaskState](t.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}

		if state.Image != "" {
			rollbackTasks.Go(func(ctx context.Context) error {
				ctx = log.WithValues(ctx, "region", state.Region, "image", state.Image)

				er := p.deleteImage(ctx, state.Image, state.Region, true)
				if er != nil {
					return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, er)
				}

				return nil
			})
		}
	}
	return rollbackTasks.Wait()
}

func (p *openstack) Close() error {
	for _, config := range p.pubCfg.Configs {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: config.Config,
		})
	}

	return nil
}
