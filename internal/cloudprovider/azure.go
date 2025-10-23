package cloudprovider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Masterminds/semver/v3"

	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ptr"
	"github.com/gardenlinux/glci/internal/slc"
	"github.com/gardenlinux/glci/internal/task"
)

func init() {
	env.Clean("AZURE_")

	registerPublishingTarget(func() PublishingTarget {
		return &azure{}
	})
}

func (*azure) Type() string {
	return "Azure"
}

func (p *azure) SetCredentials(creds map[string]any) error {
	err := setCredentials(creds, "azure_storage_account", &p.storageAccountCreds)
	if err != nil {
		return err
	}
	for cfg, c := range p.storageAccountCreds {
		c.cred, err = azblob.NewSharedKeyCredential(c.Account, c.AccountKey)
		if err != nil {
			return fmt.Errorf("cannot create shared key credential: %w", err)
		}
		p.storageAccountCreds[cfg] = c
	}

	err = setCredentials(creds, "azure_service_principal", &p.servicePrincipalCreds)
	if err != nil {
		return err
	}

	for cfg, c := range p.servicePrincipalCreds {
		var opts *azidentity.ClientSecretCredentialOptions
		if strings.HasSuffix(cfg, "-cn") {
			opts = &azidentity.ClientSecretCredentialOptions{
				ClientOptions: azcore.ClientOptions{
					Cloud: cloud.AzureChina,
				},
			}
		}
		c.cred, err = azidentity.NewClientSecretCredential(c.TenantID, c.ClientID, c.ClientSecret, opts)
		if err != nil {
			return fmt.Errorf("cannot create client secret credential: %w", err)
		}
		p.servicePrincipalCreds[cfg] = c
	}

	err = setCredentials(creds, "azure_shared_gallery", &p.galleryCreds)
	if err != nil {
		return err
	}

	return nil
}

func (p *azure) SetTargetConfig(_ context.Context, cfg map[string]any, sources map[string]ArtifactSource) error {
	err := setConfig(cfg, &p.pubCfg)
	if err != nil {
		return err
	}

	if p.storageAccountCreds == nil || p.servicePrincipalCreds == nil || p.galleryCreds == nil {
		return errors.New("credentials not set")
	}

	_, ok := sources[p.pubCfg.Source]
	if !ok {
		return fmt.Errorf("unknown source %s", p.pubCfg.Source)
	}

	var sacreds azureStorageAccountCredentials
	sacreds, ok = p.storageAccountCreds[p.pubCfg.StorageAccountConfig]
	if !ok {
		return fmt.Errorf("missing storage account credentials config %s", p.pubCfg.StorageAccountConfig)
	}

	var spcreds azureServicePrincipalCredentials
	spcreds, ok = p.servicePrincipalCreds[p.pubCfg.ServicePrincipalConfig]
	if !ok {
		return fmt.Errorf("missing service principal credentials config %s", p.pubCfg.ServicePrincipalConfig)
	}

	var gcreds azureGalleryCredentials
	gcreds, ok = p.galleryCreds[p.pubCfg.GalleryConfig]
	if !ok {
		return fmt.Errorf("missing gallery credentials config %s", p.pubCfg.GalleryConfig)
	}

	if strings.HasPrefix(gcreds.Region, "china") {
		p.pubCfg.china = true
	}

	apiEndpoint := "core.windows.net"
	var bopts *azblob.ClientOptions
	if p.pubCfg.china {
		apiEndpoint = "core.chinacloudapi.cn"
		bopts = &azblob.ClientOptions{
			ClientOptions: azcore.ClientOptions{
				Cloud: cloud.AzureChina,
			},
		}
	}
	url := fmt.Sprintf("https://%s.blob.%s/", sacreds.Account, apiEndpoint)
	p.storageClient, err = azblob.NewClientWithSharedKeyCredential(url, sacreds.cred, bopts)
	if err != nil {
		return fmt.Errorf("cannot create blob client: %w", err)
	}

	var aopts *arm.ClientOptions
	if p.pubCfg.china {
		aopts = &arm.ClientOptions{
			ClientOptions: policy.ClientOptions{
				Cloud: cloud.AzureChina,
			},
		}
	}

	var sf *armsubscriptions.ClientFactory
	sf, err = armsubscriptions.NewClientFactory(spcreds.cred, aopts)
	if err != nil {
		return fmt.Errorf("cannot create subscriptions client: %w", err)
	}
	p.subscriptionsClient = sf.NewClient()

	var cf *armcompute.ClientFactory
	cf, err = armcompute.NewClientFactory(spcreds.SubscriptionID, spcreds.cred, aopts)
	if err != nil {
		return fmt.Errorf("cannot create compute client: %w", err)
	}
	p.imagesClient = cf.NewImagesClient()
	p.galleryImagesClient = cf.NewGalleryImagesClient()
	p.galleryImageVersionsClient = cf.NewGalleryImageVersionsClient()
	p.galleriesClient = cf.NewGalleriesClient()
	p.communityGalleryImageVersionsClient = cf.NewCommunityGalleryImageVersionsClient()

	return nil
}

func (*azure) Close() error {
	return nil
}

func (*azure) ImageSuffix() string {
	return ".vhd"
}

func (p *azure) CanPublish(manifest *gl.Manifest) bool {
	if !p.isConfigured() {
		return false
	}

	return flavor(manifest.Platform) == "azure"
}

func (p *azure) IsPublished(manifest *gl.Manifest) (bool, error) {
	if !p.isConfigured() {
		return false, errors.New("config not set")
	}

	azureOutput, err := publishingOutputFromManifest[azurePublishingOutput](manifest)
	if err != nil {
		return false, err
	}

	cld := p.cloud()

	for _, img := range azureOutput.Images {
		if img.Cloud == cld {
			return true, nil
		}
	}

	return false, nil
}

func (p *azure) AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	azureOutput, err := publishingOutput[azurePublishingOutput](output)
	if err != nil {
		return nil, err
	}
	var ownOutput azurePublishingOutput
	ownOutput, err = publishingOutput[azurePublishingOutput](own)
	if err != nil {
		return nil, err
	}

	cld := p.cloud()

	for _, img := range ownOutput.Images {
		if img.Cloud != cld {
			return nil, errors.New("new publishing output has extraneous entries")
		}
	}

	for _, img := range azureOutput.Images {
		if img.Cloud == cld {
			return nil, errors.New("cannot add publishing output to existing publishing output")
		}
	}

	ownOutput.Images = slices.Concat(azureOutput.Images, ownOutput.Images)
	return &ownOutput, nil
}

func (p *azure) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	azureOutput, err := publishingOutput[azurePublishingOutput](output)
	if err != nil {
		return nil, err
	}

	cld := p.cloud()

	var otherImages []azurePublishedImage
	for _, img := range azureOutput.Images {
		if img.Cloud != cld {
			otherImages = append(otherImages, img)
		}
	}
	if len(otherImages) == 0 {
		return nil, nil
	}

	return &azurePublishingOutput{
		Images: otherImages,
	}, nil
}

func (p *azure) Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput,
	error,
) {
	if !p.isConfigured() {
		return nil, errors.New("config not set")
	}

	f := flavor(cname)
	if f != "azure" {
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
	var imageVersion string
	imageVersion, err = p.version(manifest.Version)
	if err != nil {
		return nil, fmt.Errorf("invalid version %s: %w", manifest.Version, err)
	}
	var arch armcompute.Architecture
	arch, err = p.architecture(manifest.Architecture)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", cname, err)
	}
	source := sources[p.pubCfg.Source]
	gallery := p.galleryCreds[p.pubCfg.GalleryConfig]
	cld := p.cloud()
	ctx = log.WithValues(ctx, "image", image, "architecture", arch, "sourceType", source.Type(), "sourceRepo", source.Repository(), "cloud",
		cld)

	var requireUEFI, secureBoot bool
	var pk, kek, db string
	requireUEFI, secureBoot, pk, kek, db, err = p.prepareSecureBoot(ctx, source, manifest)
	if err != nil {
		return nil, fmt.Errorf("cannot prepare secureboot: %w", err)
	}
	bios := arch == armcompute.ArchitectureX64 && !requireUEFI && !secureBoot
	ctx = log.WithValues(ctx, "requireUEFI", requireUEFI, "secureBoot", secureBoot)

	var regions []string
	regions, err = p.listRegions(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot list regions: %w", err)
	}
	if len(p.pubCfg.Regions) > 0 {
		regions = slc.Subset(regions, p.pubCfg.Regions)
	}
	if len(regions) == 0 {
		return nil, errors.New("no available regions")
	}

	imageDefinition := p.sku(gallery.Image, cname, false)
	var imageDefinitionBIOS, imageID, publicID string

	bctx := ctx
	if bios {
		imageDefinitionBIOS = p.sku(gallery.Image, cname, true)

		bctx = task.Begin(ctx, "publish/"+image+"/bios", &azureTaskState{})
		err = p.createImageDefinition(bctx, &gallery, imageDefinitionBIOS, cname, arch, true, false)
		if err != nil {
			return nil, fmt.Errorf("cannot create image definition %s for image %s: %w", imageDefinitionBIOS, image, err)
		}
	}

	ctx = task.Begin(ctx, "publish/"+image, &azureTaskState{})
	err = p.createImageDefinition(ctx, &gallery, imageDefinition, cname, arch, false, secureBoot)
	if err != nil {
		return nil, fmt.Errorf("cannot create image definition %s for image %s: %w", imageDefinition, image, err)
	}

	var blob, blobURL string
	blob, blobURL, err = p.importBlob(ctx, source, imagePath.S3Key, image)
	if err != nil {
		return nil, fmt.Errorf("cannot upload blob for image %s: %w", image, err)
	}

	outputImages := make([]azurePublishedImage, 0, 2)
	if bios {
		imageID, err = p.createImage(bctx, &gallery, blobURL, image, true)
		if err != nil {
			return nil, fmt.Errorf("cannot create image: %w", err)
		}

		err = p.createImageVersion(bctx, &gallery, imageDefinitionBIOS, imageVersion, imageID, regions, false, "", "", "")
		if err != nil {
			return nil, fmt.Errorf("cannot create image version %s for image %s: %w", imageVersion, image, err)
		}

		publicID, err = p.getPublicID(bctx, &gallery, imageDefinitionBIOS, imageVersion)
		if err != nil {
			return nil, fmt.Errorf("cannot get public ID of %s for image %s: %w", imageVersion, image, err)
		}
		task.Complete(bctx)

		outputImages = append(outputImages, azurePublishedImage{
			Cloud: p.cloud(),
			ID:    publicID,
			Gen:   "V1",
		})
	}

	imageID, err = p.createImage(ctx, &gallery, blobURL, image, false)
	if err != nil {
		return nil, fmt.Errorf("cannot create image %s: %w", image, err)
	}

	err = p.deleteBlob(ctx, blob, false)
	if err != nil {
		return nil, fmt.Errorf("cannot delete blob %s for image %s: %w", blob, image, err)
	}

	err = p.createImageVersion(ctx, &gallery, imageDefinition, imageVersion, imageID, regions, secureBoot, pk, kek, db)
	if err != nil {
		return nil, fmt.Errorf("cannot create image version %s for image %s: %w", imageVersion, image, err)
	}

	publicID, err = p.getPublicID(ctx, &gallery, imageDefinition, imageVersion)
	if err != nil {
		return nil, fmt.Errorf("cannot get public ID of %s for image %s: %w", imageVersion, image, err)
	}
	task.Complete(ctx)

	outputImages = append(outputImages, azurePublishedImage{
		Cloud: p.cloud(),
		ID:    publicID,
		Gen:   "V2",
	})

	log.Info(ctx, "Image ready")

	return &azurePublishingOutput{
		Images: outputImages,
	}, nil
}

func (p *azure) Remove(ctx context.Context, manifest *gl.Manifest, _ map[string]ArtifactSource, steamroll bool) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}

	if flavor(manifest.Platform) != "azure" {
		return fmt.Errorf("invalid manifest: invalid platform %s for target %s", manifest.Platform, p.Type())
	}

	pubOut, err := publishingOutputFromManifest[azurePublishingOutput](manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	if len(pubOut.Images) == 0 {
		return errors.New("invalid manifest: missing published images")
	}

	gallery := p.galleryCreds[p.pubCfg.GalleryConfig]
	cld := p.cloud()
	ctx = log.WithValues(ctx, "cloud", cld)

	for _, img := range pubOut.Images {
		if img.Cloud != cld {
			continue
		}
		lctx := log.WithValues(ctx, "imageID", img.ID)

		var imageDefinition, image, imageVersion string
		imageDefinition, image, imageVersion, err = p.getMetadata(lctx, &gallery, img.ID)
		if err != nil {
			var errr *azcore.ResponseError
			if steamroll && errors.As(err, &errr) && errr.StatusCode == http.StatusNotFound {
				log.Debug(ctx, "Image not found but the steamroller keeps going")
				continue
			}
			return fmt.Errorf("cannot get metadata: %w", err)
		}
		lctx = log.WithValues(lctx, "imageDefinition", imageDefinition, "imageVersion", imageVersion, "image", image)

		err = p.deleteImageVersion(lctx, &gallery, imageDefinition, imageVersion, steamroll)
		if err != nil {
			return fmt.Errorf("cannot delete image version %s for image definition %s: %w", imageVersion, imageDefinition, err)
		}

		err = p.deleteImage(lctx, gallery.ResourceGroup, image, steamroll)
		if err != nil {
			return fmt.Errorf("cannot delete image %s: %w", image, err)
		}

		err = p.deleteEmptyImageDefinition(ctx, &gallery, imageDefinition)
		if err != nil {
			return fmt.Errorf("cannot delete image definition %s: %w", imageDefinition, err)
		}
	}

	return nil
}

func (p *azure) CanRollback() string {
	if !p.isConfigured() {
		return ""
	}

	return "azure/" + strings.ReplaceAll(p.cloud(), " ", "_")
}

func (p *azure) Rollback(ctx context.Context, tasks map[string]task.Task) error {
	if !p.isConfigured() {
		return errors.New("config not set")
	}
	gallery := p.galleryCreds[p.pubCfg.GalleryConfig]

	for _, t := range tasks {
		state, err := task.ParseState[*azureTaskState](t.State)
		if err != nil {
			return err
		}

		lctx := ctx

		if state.Blob != "" {
			lctx = log.WithValues(lctx, "blob", state.Blob)
			err = p.deleteBlob(lctx, state.Blob, true)
			if err != nil {
				return fmt.Errorf("cannot delete blob %s: %w", state.Blob, err)
			}
		}

		if state.Image != "" {
			lctx = log.WithValues(lctx, "image", state.Image)
			err = p.deleteImage(lctx, gallery.ResourceGroup, state.Image, true)
			if err != nil {
				return fmt.Errorf("cannot delete image %s: %w", state.Image, err)
			}
		}

		if state.Version.Version != "" {
			lctx = log.WithValues(lctx, "imageDefinition", state.Version.Definition, "imageVersion", state.Version.Version)
			err = p.deleteImageVersion(lctx, &gallery, state.Version.Definition, state.Version.Version, true)
			if err != nil {
				return fmt.Errorf("cannot delete image version %s for image definition %s: %w", state.Version,
					state.Version.Definition, err)
			}
		}
	}

	return nil
}

type azure struct {
	storageAccountCreds                 map[string]azureStorageAccountCredentials
	servicePrincipalCreds               map[string]azureServicePrincipalCredentials
	galleryCreds                        map[string]azureGalleryCredentials
	pubCfg                              azurePublishingConfig
	storageClient                       *azblob.Client
	subscriptionsClient                 *armsubscriptions.Client
	imagesClient                        *armcompute.ImagesClient
	galleryImagesClient                 *armcompute.GalleryImagesClient
	galleryImageVersionsClient          *armcompute.GalleryImageVersionsClient
	galleriesClient                     *armcompute.GalleriesClient
	communityGalleryImageVersionsClient *armcompute.CommunityGalleryImageVersionsClient
}

type azureStorageAccountCredentials struct {
	AccountKey   string `mapstructure:"access_key"`
	Account      string `mapstructure:"storage_account_name"`
	Container    string `mapstructure:"container_name"`
	ContainerSig string `mapstructure:"container_name_sig"`
	cred         *azblob.SharedKeyCredential
}

type azureServicePrincipalCredentials struct {
	ClientID       string `mapstructure:"client_id"`
	ClientSecret   string `mapstructure:"client_secret"`
	ObjectID       string `mapstructure:"object_id"`
	SubscriptionID string `mapstructure:"subscription_id"`
	TenantID       string `mapstructure:"tenant_id"`
	cred           *azidentity.ClientSecretCredential
}

type azureGalleryCredentials struct {
	ResourceGroup  string `mapstructure:"resource_group_name"`
	Gallery        string `mapstructure:"gallery_name"`
	Image          string `mapstructure:"published_name"`
	Region         string `mapstructure:"location"`
	Description    string `mapstructure:"description"`
	EULA           string `mapstructure:"eula"`
	ReleaseNoteURI string `mapstructure:"release_note_uri"`
	Publisher      string `mapstructure:"identifier_publisher"`
	Offer          string `mapstructure:"identifier_offer"`
	SKU            string `mapstructure:"identifier_sku"`
}

type azurePublishingConfig struct {
	Source                 string   `mapstructure:"source"`
	StorageAccountConfig   string   `mapstructure:"storage_account_config"`
	ServicePrincipalConfig string   `mapstructure:"service_principal_config"`
	GalleryConfig          string   `mapstructure:"gallery_config"`
	Regions                []string `mapstructure:"regions,omitempty"`
	china                  bool
}

type azureTaskState struct {
	Blob    string                `json:"blob,omitzero"`
	Image   string                `json:"image,omitzero"`
	Version azureTaskStateVersion `json:"version,omitzero"`
}

type azureTaskStateVersion struct {
	Version    string `json:"version,omitzero"`
	Definition string `json:"definition,omitzero"`
}

type azurePublishingOutput struct {
	Images []azurePublishedImage `yaml:"published_gallery_images,omitempty"`
}

type azurePublishedImage struct {
	Cloud string `yaml:"azure_cloud"`
	ID    string `yaml:"community_gallery_image_id"`
	Gen   string `yaml:"hyper_v_generation"`
}

func (p *azure) isConfigured() bool {
	return p.storageClient != nil && p.subscriptionsClient != nil && p.imagesClient != nil && p.galleryImagesClient != nil &&
		p.galleryImageVersionsClient != nil && p.galleriesClient != nil && p.communityGalleryImageVersionsClient != nil
}

func (p *azure) cloud() string {
	if p.pubCfg.china {
		return "china"
	}

	return "public"
}

func (*azure) imageName(cname, version, committish string) string {
	return fmt.Sprintf("gardenlinux-%s-%s-%.8s", cname, version, committish)
}

func (*azure) version(version string) (string, error) {
	ver, err := semver.NewVersion(version)
	if err != nil {
		return "", fmt.Errorf("invalid version %s: %w", version, err)
	}
	return ver.String(), nil
}

func (*azure) architecture(arch gl.Architecture) (armcompute.Architecture, error) {
	switch arch {
	case gl.ArchitectureAMD64:
		return armcompute.ArchitectureX64, nil
	case gl.ArchitectureARM64:
		return armcompute.ArchitectureArm64, nil
	default:
		return "", fmt.Errorf("unknown architecture %s", arch)
	}
}

func (*azure) prepareSecureBoot(ctx context.Context, source ArtifactSource, manifest *gl.Manifest) (bool, bool, string, string, string,
	error,
) {
	var pk, kek, db string

	if manifest.SecureBoot {
		pkFile, err := manifest.PathBySuffix(".secureboot.pk.der")
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("missing secureboot PK: %w", err)
		}

		var rawPK []byte
		rawPK, err = getObjectBytes(ctx, source, pkFile.S3Key)
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("cannot get PK: %w", err)
		}
		pk = base64.StdEncoding.EncodeToString(rawPK)

		var kekFile gl.S3ReleaseFile
		kekFile, err = manifest.PathBySuffix(".secureboot.kek.der")
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("missing KEK: %w", err)
		}

		var rawKEK []byte
		rawKEK, err = getObjectBytes(ctx, source, kekFile.S3Key)
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("cannot get KEK: %w", err)
		}
		kek = base64.StdEncoding.EncodeToString(rawKEK)

		var dbFile gl.S3ReleaseFile
		dbFile, err = manifest.PathBySuffix(".secureboot.db.der")
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("missing DB: %w", err)
		}

		var rawDB []byte
		rawDB, err = getObjectBytes(ctx, source, dbFile.S3Key)
		if err != nil {
			return false, false, "", "", "", fmt.Errorf("cannot get DB: %w", err)
		}
		db = base64.StdEncoding.EncodeToString(rawDB)
	}

	return manifest.RequireUEFI, manifest.SecureBoot, pk, kek, db, nil
}

func (p *azure) listRegions(ctx context.Context) ([]string, error) {
	unusableRegions := []string{
		"brazilus",
		"jioindiacentral",
	}
	spcreds := p.servicePrincipalCreds[p.pubCfg.ServicePrincipalConfig]

	log.Debug(ctx, "Listing available locations")
	pager := p.subscriptionsClient.NewListLocationsPager(spcreds.SubscriptionID, nil)

	regions := make([]string, 0)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cannot list locations: %w", err)
		}

		for _, location := range page.Value {
			if location == nil {
				return nil, errors.New("cannot list locations: missing location")
			}
			if location.Name == nil {
				return nil, errors.New("cannot list locations: missing location name")
			}
			if location.Metadata == nil || location.Metadata.RegionType == nil {
				return nil, errors.New("cannot list locations: missing region type")
			}
			if *location.Metadata.RegionType == armsubscriptions.RegionTypeLogical {
				continue
			}
			if slices.Contains(unusableRegions, *location.Name) {
				continue
			}
			if strings.HasSuffix(*location.Name, "euap") || strings.HasSuffix(*location.Name, "usstg") {
				continue
			}

			regions = append(regions, *location.Name)
		}
	}

	return regions, nil
}

func (*azure) sku(base, cname string, bios bool) string {
	cname = strings.TrimPrefix(cname, "azure-")
	if bios {
		cname += "-bios"
	}
	return fmt.Sprintf("%s-%s", base, cname)
}

func (p *azure) createImageDefinition(ctx context.Context, gallery *azureGalleryCredentials, imageDefinition, cname string,
	arch armcompute.Architecture, bios, secureBoot bool,
) error {
	gen := armcompute.HyperVGenerationV2
	features := []*armcompute.GalleryImageFeature{
		{
			Name:  ptr.P("IsAcceleratedNetworkSupported"),
			Value: ptr.P("True"),
		},
		{
			Name:  ptr.P("DiskControllerTypes"),
			Value: ptr.P("NVMe, SCSI"),
		},
	}
	if bios {
		gen = armcompute.HyperVGenerationV1
	}
	if secureBoot {
		features = append(features, &armcompute.GalleryImageFeature{
			Name:  ptr.P("SecurityType"),
			Value: ptr.P("TrustedLaunchSupported"),
		})
	}
	ctx = log.WithValues(ctx, "imageDefinition", imageDefinition)

	log.Debug(ctx, "Getting image definition")
	exists := true
	_, err := p.galleryImagesClient.Get(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition, nil)
	if err != nil {
		var rerr *azcore.ResponseError
		if !errors.As(err, &rerr) || rerr.StatusCode != http.StatusNotFound {
			return fmt.Errorf("cannot get image definition %s: %w", imageDefinition, err)
		}
		exists = false
	}
	if exists {
		return nil
	}

	log.Info(ctx, "Creating image definition")
	var poller *runtime.Poller[armcompute.GalleryImagesClientCreateOrUpdateResponse]
	poller, err = p.galleryImagesClient.BeginCreateOrUpdate(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition,
		armcompute.GalleryImage{
			Location: &gallery.Region,
			Properties: &armcompute.GalleryImageProperties{
				Identifier: &armcompute.GalleryImageIdentifier{
					Offer:     &gallery.Offer,
					Publisher: &gallery.Publisher,
					SKU:       ptr.P(p.sku(gallery.SKU, cname, bios)),
				},
				OSState:          ptr.P(armcompute.OperatingSystemStateTypesGeneralized),
				OSType:           ptr.P(armcompute.OperatingSystemTypesLinux),
				Architecture:     &arch,
				Description:      &gallery.Description,
				Eula:             &gallery.EULA,
				Features:         features,
				HyperVGeneration: &gen,
				ReleaseNoteURI:   &gallery.ReleaseNoteURI,
			},
		}, nil)
	if err != nil {
		return fmt.Errorf("cannot create or update image definition %s: %w", imageDefinition, err)
	}

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: time.Second * 7,
	})
	if err != nil {
		return fmt.Errorf("cannot create or update image definition %s: %w", imageDefinition, err)
	}

	return nil
}

func (p *azure) importBlob(ctx context.Context, source ArtifactSource, key, image string) (string, string, error) {
	container := p.storageAccountCreds[p.pubCfg.StorageAccountConfig].Container
	blob := image + p.ImageSuffix()
	size, err := source.GetObjectSize(ctx, key)
	if err != nil {
		return "", "", fmt.Errorf("cannot get object size: %w", err)
	}
	ctx = log.WithValues(ctx, "key", key, "container", container, "blob", blob, "size", size)

	log.Info(ctx, "Uploading blob")
	var url string
	url, err = source.GetObjectURL(ctx, key)
	if err != nil {
		return "", "", fmt.Errorf("cannot get image URL for %s: %w", key, err)
	}

	blobClient := p.storageClient.ServiceClient().NewContainerClient(container).NewPageBlobClient(blob)
	_, err = blobClient.Create(ctx, size, nil)
	if err != nil {
		return "", "", fmt.Errorf("cannot create blob: %w", err)
	}
	task.Update(ctx, func(s *azureTaskState) *azureTaskState {
		s.Blob = blob
		return s
	})
	var offset int64
	for offset < size {
		block := min(size-offset, 4*1024*1024)
		_, err = blobClient.UploadPagesFromURL(ctx, url, offset, offset, block, nil)
		if err != nil {
			return "", "", fmt.Errorf("cannot upload to blob %s in container %s: %w", blob, container, err)
		}
		offset += block
	}
	log.Debug(ctx, "Blob uploaded")

	return blob, blobClient.URL(), nil
}

func (p *azure) createImage(ctx context.Context, gallery *azureGalleryCredentials, blobURL, image string, bios bool) (string, error) {
	imageName := image
	gen := armcompute.HyperVGenerationTypesV2
	if bios {
		imageName += "-bios"
		gen = armcompute.HyperVGenerationTypesV1
	}
	imageName += p.ImageSuffix()
	ctx = log.WithValues(ctx, "imageName", imageName)

	log.Info(ctx, "Creating image")
	poller, err := p.imagesClient.BeginCreateOrUpdate(ctx, gallery.ResourceGroup, imageName, armcompute.Image{
		Location: &gallery.Region,
		Properties: &armcompute.ImageProperties{
			HyperVGeneration: &gen,
			StorageProfile: &armcompute.ImageStorageProfile{
				OSDisk: &armcompute.ImageOSDisk{
					OSState: ptr.P(armcompute.OperatingSystemStateTypesGeneralized),
					OSType:  ptr.P(armcompute.OperatingSystemTypesLinux),
					BlobURI: &blobURL,
					Caching: ptr.P(armcompute.CachingTypesReadWrite),
				},
			},
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create or update image %s: %w", imageName, err)
	}
	task.Update(ctx, func(s *azureTaskState) *azureTaskState {
		s.Image = imageName
		return s
	})

	var r armcompute.ImagesClientCreateOrUpdateResponse
	r, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: time.Second * 7,
	})
	if err != nil {
		return "", fmt.Errorf("cannot create or update image %s: %w", imageName, err)
	}
	if r.ID == nil {
		return "", fmt.Errorf("cannot create or update image %s: missing ID", imageName)
	}

	return *r.ID, nil
}

func (p *azure) createImageVersion(ctx context.Context, gallery *azureGalleryCredentials, imageDefinition, imageVersion, imageID string,
	regions []string, secureBoot bool, _, kek, db string,
) error {
	var security *armcompute.ImageVersionSecurityProfile
	if secureBoot {
		security = &armcompute.ImageVersionSecurityProfile{
			UefiSettings: &armcompute.GalleryImageVersionUefiSettings{
				AdditionalSignatures: &armcompute.UefiKeySignatures{
					Db: []*armcompute.UefiKey{
						{
							Type: ptr.P(armcompute.UefiKeyTypeX509),
							Value: []*string{
								&db,
							},
						},
					},
					Kek: []*armcompute.UefiKey{
						{
							Type: ptr.P(armcompute.UefiKeyTypeX509),
							Value: []*string{
								&kek,
							},
						},
					},
					// Currently supplying a PK and using UefiSignatureTemplateNameNoSignatureTemplate does not work.
					// Pk: &armcompute.UefiKey{
					// 	Type: ptr.P(armcompute.UefiKeyTypeX509),
					// 	Value: []*string{
					// 		&pk,
					// 	},
					// },
				},
				SignatureTemplateNames: []*armcompute.UefiSignatureTemplateName{
					ptr.P(armcompute.UefiSignatureTemplateNameMicrosoftUefiCertificateAuthorityTemplate),
				},
			},
		}
	}
	targetRegions := make([]*armcompute.TargetRegion, 0, len(regions))
	for _, region := range regions {
		targetRegions = append(targetRegions, &armcompute.TargetRegion{
			Name: &region,
		})
	}
	ctx = log.WithValues(ctx, "imageDefinition", imageDefinition, "imageVersion", imageVersion)

	log.Info(ctx, "Creating image version")
	poller, err := p.galleryImageVersionsClient.BeginCreateOrUpdate(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition,
		imageVersion, armcompute.GalleryImageVersion{
			Location: &gallery.Region,
			Properties: &armcompute.GalleryImageVersionProperties{
				StorageProfile: &armcompute.GalleryImageVersionStorageProfile{
					Source: &armcompute.GalleryArtifactVersionFullSource{
						ID: &imageID,
					},
				},
				PublishingProfile: &armcompute.GalleryImageVersionPublishingProfile{
					ReplicaCount:       ptr.P(int32(1)),
					StorageAccountType: ptr.P(armcompute.StorageAccountTypeStandardLRS),
					TargetRegions:      targetRegions,
				},
				SecurityProfile: security,
			},
			Tags: map[string]*string{
				"component": ptr.P("gardenlinux"),
			},
		}, nil)
	if err != nil {
		return fmt.Errorf("cannot create or update image version: %w", err)
	}
	task.Update(ctx, func(s *azureTaskState) *azureTaskState {
		s.Version.Version = imageVersion
		s.Version.Definition = imageDefinition
		return s
	})

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: time.Second * 7,
	})
	if err != nil {
		return fmt.Errorf("cannot create or update image version: %w", err)
	}

	return nil
}

func (p *azure) getPublicID(ctx context.Context, gallery *azureGalleryCredentials, imageDefinition, imageVersion string) (string, error) {
	log.Debug(ctx, "Getting gallery")
	gr, err := p.galleriesClient.Get(ctx, gallery.ResourceGroup, gallery.Gallery, nil)
	if err != nil {
		return "", fmt.Errorf("cannot get gallery: %w", err)
	}
	if gr.Properties == nil || gr.Properties.SharingProfile == nil || gr.Properties.SharingProfile.CommunityGalleryInfo == nil ||
		len(gr.Properties.SharingProfile.CommunityGalleryInfo.PublicNames) != 1 ||
		gr.Properties.SharingProfile.CommunityGalleryInfo.PublicNames[0] == nil {
		return "", errors.New("cannot get gallery: missing public name")
	}
	publicName := *gr.Properties.SharingProfile.CommunityGalleryInfo.PublicNames[0]

	log.Debug(ctx, "Getting image version")
	var givr armcompute.CommunityGalleryImageVersionsClientGetResponse
	givr, err = p.communityGalleryImageVersionsClient.Get(ctx, gallery.Region, publicName, imageDefinition, imageVersion, nil)
	if err != nil {
		return "", fmt.Errorf("cannot get community gallery image version: %w", err)
	}
	if givr.Identifier == nil || givr.Identifier.UniqueID == nil {
		return "", errors.New("cannot get community gallery image version: missing unique ID")
	}

	return *givr.Identifier.UniqueID, nil
}

func (p *azure) deleteBlob(ctx context.Context, blob string, steamroll bool) error {
	container := p.storageAccountCreds[p.pubCfg.StorageAccountConfig].Container
	ctx = log.WithValues(ctx, "container", container, "blob", blob)

	log.Info(ctx, "Deleting blob")
	blobClient := p.storageClient.ServiceClient().NewContainerClient(container).NewPageBlobClient(blob)
	_, err := blobClient.Delete(ctx, &azblob.DeleteBlobOptions{
		DeleteSnapshots: ptr.P(azblob.DeleteSnapshotsOptionTypeInclude),
	})
	if err != nil {
		var errr *azcore.ResponseError
		if steamroll && errors.As(err, &errr) && errr.StatusCode == http.StatusNotFound {
			log.Debug(ctx, "Blob not found but the steamroller keeps going")
			return nil
		}
		return fmt.Errorf("cannot delete blob: %w", err)
	}
	task.Update(ctx, func(s *azureTaskState) *azureTaskState {
		s.Blob = ""
		return s
	})

	return nil
}

func (p *azure) getMetadata(ctx context.Context, gallery *azureGalleryCredentials, imageID string) (string, string, string, error) {
	parts := strings.Split(imageID, "/")
	if len(parts) != 7 {
		return "", "", "", fmt.Errorf("invalid image ID %s", imageID)
	}
	imageGallery := parts[2]
	imageDefinition := parts[4]
	imageVersion := parts[6]

	log.Debug(ctx, "Getting gallery")
	gr, err := p.galleriesClient.Get(ctx, gallery.ResourceGroup, gallery.Gallery, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot get gallery %s: %w", gallery.Gallery, err)
	}
	if gr.Properties == nil || gr.Properties.SharingProfile == nil || gr.Properties.SharingProfile.CommunityGalleryInfo == nil {
		return "", "", "", fmt.Errorf("cannot get gallery %s: missing public names", gallery.Gallery)
	}
	found := false
	for _, name := range gr.Properties.SharingProfile.CommunityGalleryInfo.PublicNames {
		if name == nil {
			return "", "", "", fmt.Errorf("cannot get gallery%s : missing public name", gallery.Gallery)
		}
		if *name == imageGallery {
			found = true
			break
		}
	}
	if !found {
		return "", "", "", fmt.Errorf("cannot get gallery %s: no public name matches gallery %s", gallery.Gallery, imageGallery)
	}

	log.Debug(ctx, "Getting gallery image version")
	var givr armcompute.GalleryImageVersionsClientGetResponse
	givr, err = p.galleryImageVersionsClient.Get(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition, imageVersion, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot get gallery image version: %w", err)
	}
	if givr.Properties == nil || givr.Properties.StorageProfile == nil || givr.Properties.StorageProfile.Source == nil ||
		givr.Properties.StorageProfile.Source.ID == nil {
		return "", "", "", errors.New("cannot get gallery image version: missing source ID")
	}
	parts = strings.Split(*givr.Properties.StorageProfile.Source.ID, "/")
	if len(parts) != 9 {
		return "", "", "", fmt.Errorf("cannot get gallery image version: invalid source %s", *givr.Properties.StorageProfile.Source.ID)
	}
	image := parts[8]

	return imageDefinition, image, imageVersion, nil
}

func (p *azure) deleteImageVersion(ctx context.Context, gallery *azureGalleryCredentials, imageDefinition, imageVersion string, _ bool,
) error {
	log.Info(ctx, "Deleting image version")
	poller, err := p.galleryImageVersionsClient.BeginDelete(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition, imageVersion, nil)
	if err != nil {
		return fmt.Errorf("cannot delete gallery image version: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: time.Second * 7,
	})
	if err != nil {
		return fmt.Errorf("cannot delete gallery image version: %w", err)
	}

	return nil
}

func (p *azure) deleteImage(ctx context.Context, imageResourceGroup, image string, _ bool) error {
	log.Info(ctx, "Deleting image")
	poller, err := p.imagesClient.BeginDelete(ctx, imageResourceGroup, image, nil)
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
		Frequency: time.Second * 7,
	})
	if err != nil {
		return fmt.Errorf("cannot delete image: %w", err)
	}

	return nil
}

func (p *azure) deleteEmptyImageDefinition(ctx context.Context, gallery *azureGalleryCredentials, imageDefinition string) error {
	log.Debug(ctx, "Listing image versions")
	pager := p.galleryImageVersionsClient.NewListByGalleryImagePager(gallery.ResourceGroup, gallery.Gallery, imageDefinition, nil)
	if pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("cannot list gallery image versions: %w", err)
		}
		if len(page.Value) == 0 {
			log.Info(ctx, "Deleting image definition")
			var poller *runtime.Poller[armcompute.GalleryImagesClientDeleteResponse]
			poller, err = p.galleryImagesClient.BeginDelete(ctx, gallery.ResourceGroup, gallery.Gallery, imageDefinition, nil)
			if err != nil {
				return fmt.Errorf("cannot delete gallery image definition: %w", err)
			}

			_, err = poller.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{
				Frequency: time.Second * 7,
			})
			if err != nil {
				return fmt.Errorf("cannot delete gallery image definition: %w", err)
			}
		}
	}

	return nil
}
