package nspcpfl

import (
	"fmt"
	"os"
	"slices"
	"strings"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/goccy/go-yaml"
	"github.com/mitchellh/mapstructure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/gardenlinux/glci/internal/cloudprovider"
)

// ---- AWS ----

type awsCloudProfileConfig struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	MachineImages []awsMachineImage `json:"machineImages"`
}

type awsMachineImage struct {
	Name     string                   `json:"name"`
	Versions []awsMachineImageVersion `json:"versions"`
}

type awsMachineImageVersion struct {
	Version string      `json:"version"`
	Regions []awsRegion `json:"regions"`
}

type awsRegion struct {
	Name         string `json:"name"`
	AMI          string `json:"ami"`
	Architecture string `json:"architecture"`
}

type awsPublishedImage struct {
	Region    string `yaml:"aws_region_id"`
	ID        string `yaml:"ami_id"`
	ImageName string `yaml:"image_name"`
}

type awsPublishedMetadata struct {
	Images []awsPublishedImage `yaml:"published_aws_images"`
}

// ---- Alicloud ----

type alicloudCloudProfileConfig struct {
	APIVersion    string                 `json:"apiVersion"`
	Kind          string                 `json:"kind"`
	MachineImages []alicloudMachineImage `json:"machineImages"`
}

type alicloudMachineImage struct {
	Name     string                        `json:"name"`
	Versions []alicloudMachineImageVersion `json:"versions"`
}

type alicloudMachineImageVersion struct {
	Version string           `json:"version"`
	Regions []alicloudRegion `json:"regions"`
}

type alicloudRegion struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type alicloudPublishedImage struct {
	Region    string `yaml:"region_id"`
	ID        string `yaml:"image_id"`
	ImageName string `yaml:"image_name"`
}

type alicloudPublishedMetadata struct {
	Images []alicloudPublishedImage `yaml:"published_alicloud_images"`
}

// ---- GCP ----

type gcpCloudProfileConfig struct {
	APIVersion    string            `json:"apiVersion"`
	Kind          string            `json:"kind"`
	MachineImages []gcpMachineImage `json:"machineImages"`
}

type gcpMachineImage struct {
	Name     string                   `json:"name"`
	Versions []gcpMachineImageVersion `json:"versions"`
}

type gcpMachineImageVersion struct {
	Version      string `json:"version"`
	Image        string `json:"image"`
	Architecture string `json:"architecture,omitempty"`
}

type gcpPublishedMetadata struct {
	Project string `yaml:"gcp_project_name"`
	Image   string `yaml:"gcp_image_name"`
}

// ---- OpenStack ----

type openstackCloudProfileConfig struct {
	APIVersion    string                  `json:"apiVersion"`
	Kind          string                  `json:"kind"`
	MachineImages []openstackMachineImage `json:"machineImages"`
}

type openstackMachineImage struct {
	Name     string                         `json:"name"`
	Versions []openstackMachineImageVersion `json:"versions"`
}

type openstackMachineImageVersion struct {
	Version string            `json:"version"`
	Regions []openstackRegion `json:"regions,omitempty"`
	Image   string            `json:"image,omitempty"`
}

type openstackRegion struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type openstackPublishedImage struct {
	Region    string `yaml:"region_name"`
	ID        string `yaml:"image_id"`
	ImageName string `yaml:"image_name"`
}

type openstackPublishedMetadata struct {
	Images []openstackPublishedImage `yaml:"published_openstack_images"`
}

// ---- Azure ----

type azureCloudProfileConfig struct {
	APIVersion    string              `json:"apiVersion"`
	Kind          string              `json:"kind"`
	MachineImages []azureMachineImage `json:"machineImages"`
}

type azureMachineImage struct {
	Name     string                     `json:"name"`
	Versions []azureMachineImageVersion `json:"versions"`
}

type azureMachineImageVersion struct {
	Version                 string  `json:"version"`
	CommunityGalleryImageID *string `json:"communityGalleryImageID,omitempty"`
	Architecture            *string `json:"architecture,omitempty"`
}

type azurePublishedImage struct {
	Cloud string `yaml:"azure_cloud"`
	ID    string `yaml:"community_gallery_image_id"`
	Gen   string `yaml:"hyper_v_generation"`
}

type azurePublishedMetadata struct {
	Images []azurePublishedImage `yaml:"published_gallery_images"`
}

// ToYAML marshals a NamespacedCloudProfile to YAML via a JSON round-trip so that
// runtime.RawExtension.Raw is rendered correctly (direct YAML marshaling outputs {}).
func ToYAML(d *gardencorev1beta1.NamespacedCloudProfile) ([]byte, error) {
	jsonBytes, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal to JSON: %w", err)
	}
	var intermediate any
	if err := json.Unmarshal(jsonBytes, &intermediate); err != nil {
		return nil, fmt.Errorf("cannot unmarshal JSON: %w", err)
	}
	return yaml.Marshal(intermediate)
}

// BuildNSCloudProfiles builds one Gardener NamespacedCloudProfile per cloud provider
// found in the given publications. Returns one profile each for AWS, Alicloud, GCP,
// and OpenStack — only for providers that have at least one publication.
func BuildNSCloudProfiles(version string, publications []cloudprovider.Publication) ([]*gardencorev1beta1.NamespacedCloudProfile, error) {
	byProvider := make(map[string][]cloudprovider.Publication)
	for _, pub := range publications {
		t := pub.Target.Type()
		byProvider[t] = append(byProvider[t], pub)
	}

	var profiles []*gardencorev1beta1.NamespacedCloudProfile

	builders := []struct {
		targetType string
		build      func(string, []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error)
	}{
		{"AWS", buildAWSProfile},
		{"Aliyun", buildAlicloudProfile},
		{"GCP", buildGCPProfile},
		{"OpenStack", buildOpenStackProfile},
		{"Azure", buildAzureProfile},
	}

	for _, b := range builders {
		pubs, ok := byProvider[b.targetType]
		if !ok {
			continue
		}
		profile, err := b.build(version, pubs)
		if err != nil {
			return nil, fmt.Errorf("cannot build %s profile: %w", b.targetType, err)
		}

		_, err = BuildShootSpecYAML(version, profile)
		if err != nil {
			return nil, fmt.Errorf("cannot build shoot spec: %w", err)
		}

		profileYAML, err := ToYAML(profile)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal %s profile: %w", b.targetType, err)
		}

		filename := strings.ToLower(b.targetType) + ".yaml"
		if err := os.WriteFile(filename, profileYAML, 0644); err != nil {
			return nil, fmt.Errorf("cannot write %s profile: %w", b.targetType, err)
		}
		profiles = append(profiles, profile)
	}

	return profiles, nil
}

func majorVersion(version string) string {
	return strings.Split(version, ".")[0]
}

func newProfile(version, provider string, rawConfig *runtime.RawExtension, architecture []string) *gardencorev1beta1.NamespacedCloudProfile {
	major := majorVersion(version)
	name := fmt.Sprintf("gardenlinux-%s-%s", major, strings.ToLower(provider))
	return &gardencorev1beta1.NamespacedCloudProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core.gardener.cloud/v1beta1",
			Kind:       "NamespacedCloudProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: fmt.Sprintf("gardenlinux-%s", major),
		},
		Spec: gardencorev1beta1.NamespacedCloudProfileSpec{
			Parent: gardencorev1beta1.CloudProfileReference{
				Kind: "CloudProfile",
				Name: provider,
			},
			MachineImages: []gardencorev1beta1.MachineImage{
				{
					Name: "gardenlinux",
					Versions: []gardencorev1beta1.MachineImageVersion{
						{
							ExpirableVersion: gardencorev1beta1.ExpirableVersion{
								Version: version,
							},
							Architectures: architecture,
							CRI: []gardencorev1beta1.CRI{
								{Name: gardencorev1beta1.CRINameContainerD},
							},
						},
					},
				},
			},
			ProviderConfig: rawConfig,
		},
	}
}

func decodePublishedMetadata[T any](pub cloudprovider.Publication) (T, error) {
	var meta T
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &meta,
		TagName: "yaml",
	})
	if err != nil {
		return meta, fmt.Errorf("cannot create decoder: %w", err)
	}
	if err := decoder.Decode(pub.Manifest.PublishedImageMetadata); err != nil {
		return meta, fmt.Errorf("cannot decode published image metadata: %w", err)
	}
	return meta, nil
}

func marshalRaw(cfg any) (*runtime.RawExtension, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal provider config: %w", err)
	}
	return &runtime.RawExtension{Raw: raw}, nil
}

func buildAWSProfile(version string, publications []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error) {
	regions := make([]awsRegion, 0, len(publications))
	architectures := make([]string, 0, len(publications))
	for _, pub := range publications {
		meta, err := decodePublishedMetadata[awsPublishedMetadata](pub)
		if err != nil {
			return nil, err
		}
		arch := string(pub.Manifest.Architecture)
		for _, img := range meta.Images {
			if strings.Contains(img.ImageName, fmt.Sprintf("gardenlinux-aws-gardener_prod-%s", arch)) {
				if !slices.Contains(architectures, arch) {
					architectures = append(architectures, arch)
				}
				regions = append(regions, awsRegion{
					Name:         img.Region,
					AMI:          img.ID,
					Architecture: arch,
				})
			}
		}
	}

	raw, err := marshalRaw(awsCloudProfileConfig{
		APIVersion: "aws.provider.extensions.gardener.cloud/v1alpha1",
		Kind:       "CloudProfileConfig",
		MachineImages: []awsMachineImage{{
			Name: "gardenlinux",
			Versions: []awsMachineImageVersion{{
				Version: version,
				Regions: regions,
			}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return newProfile(version, "aws", raw, architectures), nil
}

func buildAlicloudProfile(version string, publications []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error) {
	regions := make([]alicloudRegion, 0, len(publications))
	architectures := make([]string, 0, len(publications))
	for _, pub := range publications {
		meta, err := decodePublishedMetadata[alicloudPublishedMetadata](pub)
		if err != nil {
			return nil, err
		}
		arch := string(pub.Manifest.Architecture)
		for _, img := range meta.Images {
			if strings.Contains(img.ImageName, fmt.Sprintf("gardenlinux-ali-gardener_prod-%s", arch)) {
				if !slices.Contains(architectures, arch) {
					architectures = append(architectures, arch)
				}
				regions = append(regions, alicloudRegion{
					Name: img.Region,
					ID:   img.ID,
				})
			}
		}
	}

	raw, err := marshalRaw(alicloudCloudProfileConfig{
		APIVersion: "alicloud.provider.extensions.gardener.cloud/v1alpha1",
		Kind:       "CloudProfileConfig",
		MachineImages: []alicloudMachineImage{{
			Name: "gardenlinux",
			Versions: []alicloudMachineImageVersion{{
				Version: version,
				Regions: regions,
			}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return newProfile(version, "alicloud", raw, architectures), nil
}

func buildGCPProfile(version string, publications []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error) {
	versions := make([]gcpMachineImageVersion, 0, len(publications))
	architectures := make([]string, 0, len(publications))
	for _, pub := range publications {
		arch := string(pub.Manifest.Architecture)
		imagePath, err := pub.Manifest.PathBySuffix(".gcpimage.tar.gz")
		if err != nil {
			return nil, fmt.Errorf("cannot find GCP image path: %w", err)
		}
		if !strings.Contains(imagePath.S3Key, fmt.Sprintf("gcp-gardener_prod-%s", arch)) {
			continue
		}
		meta, err := decodePublishedMetadata[gcpPublishedMetadata](pub)
		if err != nil {
			return nil, err
		}
		// GCP image reference is "projects/<project>/global/images/<image>"
		image := fmt.Sprintf("projects/%s/global/images/%s", meta.Project, meta.Image)
		if !slices.Contains(architectures, arch) {
			architectures = append(architectures, arch)
		}
		versions = append(versions, gcpMachineImageVersion{
			Version:      version,
			Image:        image,
			Architecture: arch,
		})
	}

	raw, err := marshalRaw(gcpCloudProfileConfig{
		APIVersion: "gcp.provider.extensions.gardener.cloud/v1alpha1",
		Kind:       "CloudProfileConfig",
		MachineImages: []gcpMachineImage{{
			Name:     "gardenlinux",
			Versions: versions,
		}},
	})
	if err != nil {
		return nil, err
	}
	return newProfile(version, "gcp", raw, architectures), nil
}

func buildOpenStackProfile(version string, publications []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error) {
	regions := make([]openstackRegion, 0, len(publications))
	architectures := make([]string, 0, len(publications))
	for _, pub := range publications {
		meta, err := decodePublishedMetadata[openstackPublishedMetadata](pub)
		if err != nil {
			return nil, err
		}
		arch := string(pub.Manifest.Architecture)
		for _, img := range meta.Images {
			if strings.Contains(img.ImageName, fmt.Sprintf("gardenlinux-openstack-openstack-prod-%s", arch)) {
				if !slices.Contains(architectures, arch) {
					architectures = append(architectures, arch)
				}
				regions = append(regions, openstackRegion{
					Name: img.Region,
					ID:   img.ID,
				})
			}
		}
	}

	raw, err := marshalRaw(openstackCloudProfileConfig{
		APIVersion: "openstack.provider.extensions.gardener.cloud/v1alpha1",
		Kind:       "CloudProfileConfig",
		MachineImages: []openstackMachineImage{{
			Name: "gardenlinux",
			Versions: []openstackMachineImageVersion{{
				Version: version,
				Regions: regions,
			}},
		}},
	})
	if err != nil {
		return nil, err
	}
	return newProfile(version, "converged-cloud", raw, architectures), nil
}

func buildAzureProfile(version string, publications []cloudprovider.Publication) (*gardencorev1beta1.NamespacedCloudProfile, error) {
	versions := make([]azureMachineImageVersion, 0, len(publications))
	architectures := make([]string, 0, len(publications))
	for _, pub := range publications {
		meta, err := decodePublishedMetadata[azurePublishedMetadata](pub)
		if err != nil {
			return nil, err
		}
		arch := string(pub.Manifest.Architecture)
		for _, img := range meta.Images {
			id := img.ID
			archCopy := arch
			if strings.Contains(id, fmt.Sprintf("gardenlinux-gardener_prod-%s/Versions/", archCopy)) {
				versions = append(versions, azureMachineImageVersion{
					Version:                 version,
					CommunityGalleryImageID: &id,
					Architecture:            &archCopy,
				})
				if !slices.Contains(architectures, arch) {
					architectures = append(architectures, arch)
				}
			}
		}
	}

	raw, err := marshalRaw(azureCloudProfileConfig{
		APIVersion: "azure.provider.extensions.gardener.cloud/v1alpha1",
		Kind:       "CloudProfileConfig",
		MachineImages: []azureMachineImage{{
			Name:     "gardenlinux",
			Versions: versions,
		}},
	})
	if err != nil {
		return nil, err
	}
	return newProfile(version, "az", raw, architectures), nil
}
