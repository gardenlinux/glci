package nspcpfl

import (
	"errors"
	"fmt"
	"strings"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/goccy/go-yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func buildShootSpec(version string, profile *gardencorev1beta1.NamespacedCloudProfile) (*gardencorev1beta1.Shoot, []byte, error) {
	major, _, _ := strings.Cut(version, ".")
	platform := profile.Spec.Parent.Name

	var workers []gardencorev1beta1.Worker
	var infraConfig *runtime.RawExtension
	var providerCfg map[string]any

	if profile.Spec.ProviderConfig == nil || len(profile.Spec.ProviderConfig.Raw) == 0 {
		return nil, nil, errors.New("providerConfig is empty")
	}
	var err error
	err = json.Unmarshal(profile.Spec.ProviderConfig.Raw, &providerCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal providerConfig: %w", err)
	}

	machineImages, ok := providerCfg["machineImages"].([]any)
	if !ok {
		return nil, nil, errors.New("providerConfig: machineImages is missing or not an array")
	}
	versions, ok := machineImages[0].(map[string]any)["versions"].([]any)
	if !ok {
		return nil, nil, errors.New("providerConfig: versions is missing or not an array")
	}

	var region string
	switch platform {
	case "gcp":
		region = "europe-west1"
	case "converged-cloud":
		region = "eu-de-1"
	case "az":
		region = "northeurope"
	default:
		regionListRaw, ok := versions[0].(map[string]any)["regions"].([]any)
		if !ok {
			return nil, nil, errors.New("providerConfig: regions is missing or not an array")
		}
		regionName, ok := regionListRaw[0].(map[string]any)["name"].(string)
		if !ok {
			return nil, nil, errors.New("providerConfig: region name is missing or not a string")
		}
		region = regionName
	}

	if platform != "gcp" && platform != "converged-cloud" && platform != "az" {
		infraConfig, err = marshalRaw(map[string]any{
			"apiVersion": platform + ".provider.extensions.gardener.cloud/v1alpha1",
			"kind":       "InfrastructureConfig",
			"networks": map[string]any{
				"vpc": map[string]any{"cidr": "10.180.0.0/16"},
				"zones": []map[string]any{
					{
						"name":     region + "a",
						"workers":  "10.180.0.0/19",
						"public":   "10.180.32.0/20",
						"internal": "10.180.48.0/20",
					},
				},
			},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("cannot build infraConfig: %w", err)
		}
	}
	if platform == "converged-cloud" {
		infraConfig, err = marshalRaw(map[string]any{
			"apiVersion":           platform + ".provider.extensions.gardener.cloud/v1alpha1",
			"kind":                 "InfrastructureConfig",
			"loadbalancerProvider": "f5",
			"floatingPoolName":     "FloatingIP-external-cp-gardener",
		})
		if err != nil {
			return nil, nil, fmt.Errorf("cannot build infraConfig: %w", err)
		}
	}

	for _, mi := range profile.Spec.MachineImages {
		for _, v := range mi.Versions {
			for _, arch := range v.Architectures {
				architecture := arch
				var machineType string
				var volumeType string
				switch platform {
				case "aws":
					machineType = "a1.2xlarge"
					if architecture == "amd64" {
						machineType = "m5.large"
					}
					volumeType = "gp2"
				case "alicloud":
					machineType = "ecs.t6-c1m2.large"
					volumeType = "cloud_efficiency"
				case "gcp":
					machineType = "n1-standard-2"
					if architecture == "arm64" {
						machineType = "t2a-standard-2"
					}
					volumeType = "pd-standard"
				case "converged-cloud":
					machineType = "m1.xsmall"
				case "az":
					machineType = "Standard_DS2_v2"
					volumeType = "Standard_LRS"
				}

				zoneName := region + "a"
				if platform == "gcp" {
					zoneName = region + "-b"
				}
				if platform == "az" {
					zoneName = "1"
				}

				worker := gardencorev1beta1.Worker{
					Name: fmt.Sprintf("gl-%s-%s", major, architecture),
					Machine: gardencorev1beta1.Machine{
						Type: machineType,
						Image: &gardencorev1beta1.ShootMachineImage{
							Name:    "gardenlinux",
							Version: &version,
						},
						Architecture: &architecture,
					},
					Zones:   []string{zoneName},
					Maximum: 2,
					Minimum: 2,
				}
				if platform != "converged-cloud" {
					worker.Volume = &gardencorev1beta1.Volume{
						Type:       &volumeType,
						VolumeSize: "50Gi",
					}
				}
				workers = append(workers, worker)
			}
		}
	}

	networkType := "calico"
	cidr := "10.180.0.0/16"
	credentialBindingName := "aws"
	shoot := &gardencorev1beta1.Shoot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core.gardener.cloud/v1beta1",
			Kind:       "Shoot",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("gl-%s-%s", major, strings.ToLower(platform)),
			Namespace: "garden-gl-it",
		},
		Spec: gardencorev1beta1.ShootSpec{
			Provider: gardencorev1beta1.Provider{
				Type:                 platform,
				InfrastructureConfig: infraConfig,
				Workers:              workers,
			},
			Kubernetes: gardencorev1beta1.Kubernetes{
				Version: "1.35.5",
			},
			CloudProfile: &gardencorev1beta1.CloudProfileReference{
				Name: fmt.Sprintf("gardenlinux-%s-%s", major, strings.ToLower(platform)),
				Kind: "NamespacedCloudProfile",
			},
			Networking: &gardencorev1beta1.Networking{
				Type:  &networkType,
				Nodes: &cidr,
			},
			Region:                 region,
			CredentialsBindingName: &credentialBindingName,
		},
	}

	jsonBytes, err := json.Marshal(shoot)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal shoot to JSON: %w", err)
	}
	var intermediate map[string]any
	err = json.Unmarshal(jsonBytes, &intermediate)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal shoot JSON: %w", err)
	}
	if meta, ok := intermediate["metadata"].(map[string]any); ok {
		delete(meta, "creationTimestamp")
	}
	delete(intermediate, "status")

	shootYAML, err := yaml.Marshal(intermediate)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal shoot to YAML: %w", err)
	}

	return shoot, shootYAML, nil
}

// BuildShootSpecYAML returns the YAML-encoded Shoot spec derived from the given NamespacedCloudProfile.
func BuildShootSpecYAML(version string, profile *gardencorev1beta1.NamespacedCloudProfile) ([]byte, error) {
	_, shootYAML, err := buildShootSpec(version, profile)
	return shootYAML, err
}
