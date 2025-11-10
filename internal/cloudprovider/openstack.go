package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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
	"github.com/gardenlinux/glci/internal/parallel"
	"github.com/gardenlinux/glci/internal/slc"
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

	if p.pubCfg.SourceChina != "" {
		_, ok = sources[p.pubCfg.SourceChina]
		if !ok {
			return fmt.Errorf("unknown source %s", p.pubCfg.Source)
		}
	}

	switch p.pubCfg.Hypervisor {
	case openstackHypervisorBareMetal, openstackHypervisorVMware:
	default:
		return fmt.Errorf("unknown hypervisor %s", p.pubCfg.Hypervisor)
	}

	p.imagesClients = make(map[string]*gophercloud.ServiceClient, len(creds.Projects))
	initClients := parallel.NewActivity(ctx)
	for _, proj := range creds.Projects {
		if len(p.pubCfg.Regions) > 0 && !slices.Contains(p.pubCfg.Regions, proj.Region) {
			continue
		}

		initClients.Go(func(ctx context.Context) (parallel.ResultFunc, error) {
			providerClient, er := openstacksdk.AuthenticatedClient(ctx, gophercloud.AuthOptions{
				IdentityEndpoint: proj.AuthURL,
				Username:         creds.Credentials.Username,
				Password:         creds.Credentials.Password,
				DomainName:       proj.Domain,
				Scope: &gophercloud.AuthScope{
					ProjectName: proj.Project,
					DomainName:  proj.Domain,
				},
			})
			if er != nil {
				return nil, fmt.Errorf("cannot create provider client for region %s: %w", proj.Region, er)
			}

			var client *gophercloud.ServiceClient
			client, er = openstacksdk.NewImageV2(providerClient, gophercloud.EndpointOpts{
				Region: proj.Region,
			})
			if er != nil {
				return nil, fmt.Errorf("cannot create image client for region %s: %w", proj.Region, er)
			}

			return func() error {
				p.imagesClients[proj.Region] = client

				return nil
			}, nil
		})
	}
	err = initClients.Wait()
	if err != nil {
		return err
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

func (p *openstack) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	hypervisor, err := p.hypervisor(manifest.Platform)
	if err != nil {
		return false
	}

	return hypervisor == p.pubCfg.Hypervisor
}

func (p *openstack) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	_, err := p.hypervisor(manifest.Platform)
	if err != nil {
		return false, fmt.Errorf("invalid manifest: %w", err)
	}

	var openstackOutput openstackPublishingOutput
	openstackOutput, err = publishingOutputFromManifest[openstackPublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	for _, img := range openstackOutput.Images {
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

	for _, img := range ownOutput.Images {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			return nil, errors.New("new publishing output has extraneous entries")
		}
	}

	for _, img := range openstackOutput.Images {
		if img.Hypervisor == string(p.pubCfg.Hypervisor) {
			return nil, errors.New("cannot add publishing output to existing publishing output")
		}
	}

	ownOutput.Images = slices.Concat(openstackOutput.Images, ownOutput.Images)
	return &ownOutput, nil
}

func (p *openstack) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	openstackOutput, err := publishingOutput[openstackPublishingOutput](output)
	if err != nil {
		return nil, err
	}

	var otherImages []openstackPublishedImage
	for _, img := range openstackOutput.Images {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			otherImages = append(otherImages, img)
		}
	}
	if len(otherImages) == 0 {
		return nil, nil
	}

	return &openstackPublishingOutput{
		Images: otherImages,
	}, nil
}

func (p *openstack) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	f := flavor(cname)
	hypervisor, err := p.hypervisor(f)
	if err != nil {
		return nil, fmt.Errorf("invalid cname: %w", err)
	}
	if hypervisor != p.pubCfg.Hypervisor {
		return nil, nil
	}
	if f != manifest.Platform {
		return nil, fmt.Errorf("cname %s does not match platform %s", cname, manifest.Platform)
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
	ctx = log.WithValues(ctx, "image", image, "hypervisor", p.pubCfg.Hypervisor, "architecture", arch, "sourceType", source.Type(),
		"sourceRepo", source.Repository())

	regions := p.listRegions()
	if len(p.pubCfg.Regions) > 0 {
		regions = slc.Subset(regions, p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no available regions")
	}

	sourceChina := source
	if p.pubCfg.SourceChina != "" {
		sourceChina = sources[p.pubCfg.SourceChina]
	}

	outImages := make(map[string]string, len(regions))
	for _, region := range regions {
		imageClient := p.imagesClients[region]
		src := source
		if strings.HasPrefix(region, "ap-cn-") {
			src = sourceChina
		}
		lctx := log.WithValues(ctx, "region", region)

		lctx = task.Begin(lctx, "publish/"+image+"/"+region, &openstackTaskState{
			Region: region,
		})
		var imageID string
		imageID, err = p.createImage(lctx, imageClient, src, imagePath.S3Key, image)
		if err != nil {
			return nil, task.Fail(lctx, fmt.Errorf("cannot create image for region %s: %w", region, err))
		}
		lctx = log.WithValues(lctx, "region", region)

		err = p.waitForImage(lctx, imageID, region)
		if err != nil {
			return nil, task.Fail(lctx, fmt.Errorf("cannot finalize image %s in region %s: %w", imageID, region, err))
		}
		task.Complete(lctx)

		outImages[region] = imageID
	}
	log.Info(ctx, "Images ready", "count", len(outImages))

	outputImages := make([]openstackPublishedImage, 0, len(outImages))
	for region, imageID := range outImages {
		outputImages = append(outputImages, openstackPublishedImage{
			Region:     region,
			ID:         imageID,
			Image:      image,
			Hypervisor: string(p.pubCfg.Hypervisor),
		})
	}
	return &openstackPublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *openstack) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	hypervisor, err := p.hypervisor(manifest.Platform)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if hypervisor != p.pubCfg.Hypervisor {
		return nil
	}

	var pubOut *openstackPublishingOutput
	pubOut, err = publishingOutputFromManifest[*openstackPublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if pubOut == nil || len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	ctx = log.WithValues(ctx, "hypervisor", p.pubCfg.Hypervisor)

	regions := p.listRegions()
	if len(p.pubCfg.Regions) > 0 {
		regions = slc.Subset(regions, p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return errors.New("no available regions")
	}

	for _, img := range pubOut.Images {
		if img.Hypervisor != string(p.pubCfg.Hypervisor) {
			continue
		}
		lctx := log.WithValues(ctx, "region", img.Region, "imageID", img.ID)

		if !slices.Contains(regions, img.Region) {
			return fmt.Errorf("image %s is in unknown region %s", img.ID, img.Region)
		}

		err = p.deleteImage(lctx, img.ID, img.Region, steamroll)
		if err != nil {
			return fmt.Errorf("cannot delete image %s in region %s: %w", img.ID, img.Region, err)
		}
	}

	return nil
}

func (p *openstack) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "openstack/" + strings.ReplaceAll(string(p.pubCfg.Hypervisor), " ", "_")
}

func (p *openstack) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	for _, t := range tasks {
		state, err := task.ParseState[*openstackTaskState](t.State)
		if err != nil {
			return err
		}

		if state.Region == "" {
			continue
		}
		lctx := log.WithValues(ctx, "region", state.Region)

		if state.Image != "" {
			lctx = log.WithValues(lctx, "image", state.Image)
			err = p.deleteImage(lctx, state.Image, state.Region, true)
			if err != nil {
				return fmt.Errorf("cannot delete image %s in region %s: %w", state.Image, state.Region, err)
			}
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
	SourceChina string              `mapstructure:"source_china,omitzero"`
	Test        bool                `mapstructure:"test,omitzero"`
	Hypervisor  openstackHypervisor `mapstructure:"hypervisor"`
	Regions     []string            `mapstructure:"regions,omitempty"`
}

type openstackHypervisor string

const (
	openstackHypervisorBareMetal openstackHypervisor = "Bare Metal"
	openstackHypervisorVMware    openstackHypervisor = "VMware"
)

type openstackTaskState struct {
	Region string `json:"region,omitzero"`
	Image  string `json:"image,omitzero"`
}

type openstackPublishingOutput struct {
	Images []openstackPublishedImage `yaml:"published_openstack_images,omitempty"`
}

type openstackPublishedImage struct {
	Region     string `yaml:"region_name"`
	ID         string `yaml:"image_id"`
	Image      string `yaml:"image_name"`
	Hypervisor string `yaml:"hypervisor"`
}

func (p *openstack) isConfigured() bool {
	return len(p.imagesClients) != 0
}

func (p *openstack) hypervisor(platform string) (openstackHypervisor, error) {
	h, ok := strings.CutPrefix(platform, "openstack")
	if !ok {
		return "", fmt.Errorf("invalid platform %s for target %s", platform, p.Type())
	}

	switch h {
	case "baremetal":
		return openstackHypervisorBareMetal, nil
	case "vmware", "":
		return openstackHypervisorVMware, nil
	default:
		return "", fmt.Errorf("invalid hypervisor %s", h)
	}
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
	if p.pubCfg.Test {
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
	imagesClient := p.imagesClients[region]
	var status images.ImageStatus
	for status != images.ImageStatusActive {
		log.Debug(ctx, "Waiting for image")
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

	return nil
}

func (p *openstack) deleteImage(ctx context.Context, id, region string, steamroll bool) error {
	log.Info(ctx, "Deleting image")
	err := images.Delete(ctx, p.imagesClients[region], id).ExtractErr()
	if err != nil {
		var terr gophercloud.ErrUnexpectedResponseCode
		if steamroll && errors.As(err, &terr) && terr.Actual == http.StatusNotFound {
			log.Debug(ctx, "Image not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}
