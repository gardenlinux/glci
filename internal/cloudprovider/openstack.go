package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	openstacksdk "github.com/gophercloud/gophercloud/v2/openstack"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/imageimport"
	"github.com/gophercloud/gophercloud/v2/openstack/image/v2/images"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/slc"
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

func (p *openstack) SetCredentials(creds map[string]any) error {
	err := setCredentials(creds, "ccee", &p.creds)
	if err != nil {
		return err
	}

	return nil
}

func (p *openstack) SetTargetConfig(ctx context.Context, cfg map[string]any, sources map[string]ArtifactSource) error {
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

	var creds openstackCredentials
	creds, ok = p.creds[p.pubCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.pubCfg.Config)
	}

	if p.pubCfg.SourceChina != nil {
		_, ok = sources[*p.pubCfg.SourceChina]
		if !ok {
			return fmt.Errorf("unknown source %s", p.pubCfg.Source)
		}
	}

	switch p.pubCfg.Hypervisor {
	case openstackHypervisorBareMetal:
	case openstackHypervisorVMware:
	default:
		return fmt.Errorf("unknown hypervisor %s", p.pubCfg.Hypervisor)
	}

	p.imagesClients = make(map[string]*gophercloud.ServiceClient, len(creds.Projects))
	for _, proj := range creds.Projects {
		if !slices.Contains(*p.pubCfg.Regions, proj.Region) {
			continue
		}

		var providerClient *gophercloud.ProviderClient
		providerClient, err = openstacksdk.AuthenticatedClient(ctx, gophercloud.AuthOptions{
			IdentityEndpoint: proj.AuthURL,
			Username:         creds.Credentials.Username,
			Password:         creds.Credentials.Password,
			DomainName:       proj.Domain,
			Scope: &gophercloud.AuthScope{
				ProjectName: proj.Project,
				DomainName:  proj.Domain,
			},
		})
		if err != nil {
			return fmt.Errorf("cannot create provider client for region %s: %w", proj.Region, err)
		}

		p.imagesClients[proj.Region], err = openstacksdk.NewImageV2(providerClient, gophercloud.EndpointOpts{
			Region: proj.Region,
		})
		if err != nil {
			return fmt.Errorf("cannot create image client for region %s: %w", proj.Region, err)
		}
	}
	if len(p.imagesClients) == 0 {
		return errors.New("no available regions")
	}

	return nil
}

func (*openstack) Close() error {
	return nil
}

func (*openstack) ImageSuffix() string {
	return ".vmdk"
}

func (p *openstack) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	openstackOutput, err := publishingOutputFromManifest[openstackPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	for _, img := range openstackOutput {
		if img.Hypervisor == string(p.pubCfg.Hypervisor) {
			return true, nil
		}
	}

	return false, nil
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

	for _, img := range openstackOutput {
		if img.Hypervisor == string(p.pubCfg.Hypervisor) {
			return nil, errors.New("cannot add publishing output to existing publishing output")
		}
	}

	for _, img := range ownOutput {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			return nil, errors.New("new publishing output has extraneous entries")
		}
	}

	return slices.Concat(openstackOutput, ownOutput), nil
}

func (p *openstack) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	openstackOutput, err := publishingOutput[openstackPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	var filteredOutput openstackPublishingOutput

	for _, img := range openstackOutput {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			filteredOutput = append(filteredOutput, img)
		}
	}

	return filteredOutput, nil
}

func (p *openstack) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
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
	var arch string
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	ctx = log.WithValues(ctx, "image", image, "hypervisor", p.pubCfg.Hypervisor, "architecture", arch, "sourceType", source.Type(),
		"sourceRepo", source.Repository())

	regions := p.listRegions()
	if p.pubCfg.Regions != nil {
		regions = slc.Subset(regions, *p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no available regions")
	}

	sourceChina := source
	if p.pubCfg.SourceChina != nil {
		sourceChina = sources[*p.pubCfg.SourceChina]
	}

	imgs := make(map[string]string, len(regions))
	for _, region := range regions {
		imageClient := p.imagesClients[region]
		src := source
		if strings.HasPrefix(region, "ap-cn-") {
			src = sourceChina
		}
		lctx := log.WithValues(ctx, "region", region)

		var imageID string
		imageID, err = p.createImage(lctx, imageClient, src, imagePath.S3Key, image)
		if err != nil {
			return nil, fmt.Errorf("cannot create image for region %s: %w", region, err)
		}

		imgs[region] = imageID
	}

	err = p.waitForImages(ctx, imgs)
	if err != nil {
		return nil, fmt.Errorf("cannot finalize images: %w", err)
	}

	output := make(openstackPublishingOutput, 0, len(imgs))
	for region, imageID := range imgs {
		output = append(output, openstackPublishedImage{
			Region:     region,
			ID:         imageID,
			Image:      image,
			Hypervisor: string(p.pubCfg.Hypervisor),
		})
	}

	return output, nil
}

func (p *openstack) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}
	ctx = log.WithValues(ctx, "target", p.Type())

	pubOut, err := publishingOutputFromManifest[openstackPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	ctx = log.WithValues(ctx, "hypervisor", p.pubCfg.Hypervisor)

	for _, img := range pubOut {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			continue
		}
		lctx := log.WithValues(ctx, "region", img.Region, "imageID", img.ID)

		log.Info(lctx, "Deleting image")
		err = images.Delete(lctx, p.imagesClients[img.Region], img.ID).ExtractErr()
		if err != nil {
			return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, err)
		}
	}

	return nil
}

type openstack struct {
	creds         map[string]openstackCredentials
	pubCfg        openstackPublishingConfig
	imagesClients map[string]*gophercloud.ServiceClient
}

type openstackCredentials struct {
	Credentials openstackCredentialsCredentials `mapstructure:"credentials"`
	Projects    []openstackProject              `mapstructure:"projects"`
}

type openstackCredentialsCredentials struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type openstackProject struct {
	Project string `mapstructure:"name"`
	Domain  string `mapstructure:"domain"`
	Region  string `mapstructure:"region"`
	AuthURL string `mapstructure:"auth_url"`
}

type openstackPublishingConfig struct {
	Source      string              `mapstructure:"source"`
	Config      string              `mapstructure:"config"`
	SourceChina *string             `mapstructure:"source_china,omitempty"`
	Test        *bool               `mapstructure:"test,omitempty"`
	Hypervisor  openstackHypervisor `mapstructure:"hypervisor"`
	Regions     *[]string           `mapstructure:"regions,omitempty"`
}

type openstackHypervisor string

const (
	openstackHypervisorBareMetal openstackHypervisor = "Base Metal"
	openstackHypervisorVMware    openstackHypervisor = "VMware"
)

type openstackPublishingOutput []openstackPublishedImage

type openstackPublishedImage struct {
	Region     string `yaml:"region"`
	ID         string `yaml:"id"`
	Image      string `yaml:"image"`
	Hypervisor string `yaml:"hypervisor"`
}

func (p *openstack) isConfigured() bool {
	return len(p.imagesClients) != 0
}

func (p *openstack) imageName(cname, version, committish string) string {
	var hypervisor string
	switch p.pubCfg.Hypervisor {
	case openstackHypervisorBareMetal:
		hypervisor = "baremetal"
	case openstackHypervisorVMware:
		hypervisor = "vmware"
	default:
	}
	if p.pubCfg.Test != nil && *p.pubCfg.Test {
		hypervisor += "-test"
	}

	return fmt.Sprintf("gardenlinux-%s-%s-%s-%.8s", cname, hypervisor, version, committish)
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

func (p *openstack) listRegions() []string {
	projects := p.creds[p.pubCfg.Config].Projects

	regions := make([]string, 0, len(projects))
	for _, proj := range projects {
		regions = append(regions, proj.Region)
	}
	return regions
}

func (p *openstack) createImage(ctx context.Context, imageClient *gophercloud.ServiceClient, source ArtifactSource, key, image string,
) (string, error) {
	var properties map[string]string
	visibility := images.ImageVisibilityCommunity
	switch p.pubCfg.Hypervisor {
	case openstackHypervisorBareMetal:
		properties = map[string]string{
			"hypervisor_type":  "baremetal",
			"os_distro":        "debian10_64Guest",
			"img_config_drive": "mandatory",
		}
		visibility = images.ImageVisibilityPublic
	case openstackHypervisorVMware:
		properties = map[string]string{
			"hypervisor_type":    "vmware",
			"hw_disk_bus":        "scsi",
			"hw_firmware_type":   "uefi",
			"hw_vif_model":       "vmxnet3",
			"vmware_adaptertype": "paraVirtual",
			"vmware_disktype":    "streamOptimized",
			"vmware_ostype":      "debian10_64Guest",
		}
	default:
	}
	ctx = log.WithValues(ctx, "key", key)

	log.Info(ctx, "Creating image")
	img, err := images.Create(ctx, imageClient, images.CreateOpts{
		Name:            image,
		Visibility:      &visibility,
		ContainerFormat: "bare",
		DiskFormat:      "vmdk",
		Properties:      properties,
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("cannot create image: %w", err)
	}

	log.Debug(ctx, "Importing image")
	err = imageimport.Create(ctx, imageClient, img.ID, imageimport.CreateOpts{
		Name: imageimport.WebDownloadMethod,
		URI:  source.GetObjectURL(key),
	}).ExtractErr()
	if err != nil {
		return "", fmt.Errorf("cannot import image: %w", err)
	}

	return img.ID, nil
}

func (p *openstack) waitForImages(ctx context.Context, imgs map[string]string) error {
	for region, imageID := range imgs {
		imagesClient := p.imagesClients[region]
		var status images.ImageStatus
		for status != images.ImageStatusActive {
			log.Debug(ctx, "Waiting for image", "region", region, "imageID", imageID)
			img, err := images.Get(ctx, imagesClient, imageID).Extract()
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
	}
	log.Info(ctx, "Images ready", "count", len(imgs))

	return nil
}
