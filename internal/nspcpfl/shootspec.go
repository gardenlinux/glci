package nspcpfl

import (
	"fmt"
	"strings"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-jose/go-jose/v4/json"
	"github.com/goccy/go-yaml"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func buildShootSpec(version string, profile *gardencorev1beta1.NamespacedCloudProfile) (*gardencorev1beta1.Shoot, []byte, error) {
	major := strings.Split(version, ".")[0]
	platform := profile.Spec.Parent.Name

	var workers []gardencorev1beta1.Worker
	var infraConfig *runtime.RawExtension
	var providerCfg map[string]any

	if profile.Spec.ProviderConfig == nil || len(profile.Spec.ProviderConfig.Raw) == 0 {
		return nil, nil, fmt.Errorf("providerConfig is empty")
	}
	if err := json.Unmarshal(profile.Spec.ProviderConfig.Raw, &providerCfg); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal providerConfig: %w", err)
	}

	machineImages := providerCfg["machineImages"].([]any)
	versions := machineImages[0].(map[string]any)["versions"].([]any)

	var region string
	switch platform {
	case "gcp":
		region = "europe-west1"
	case "converged-cloud":
		region = "eu-de-1"
	case "az":
		region = "northeurope"
	default:
		regionList := versions[0].(map[string]any)["regions"].([]any)
		region = regionList[0].(map[string]any)["name"].(string)
	}
	var err error
	if platform != "gcp" && platform != "converged-cloud" && platform != "az" {
		infraConfig, err = marshalRaw(map[string]any{
			"apiVersion": fmt.Sprintf("%s.provider.extensions.gardener.cloud/v1alpha1", platform),
			"kind":       "InfrastructureConfig",
			"networks": map[string]any{
				"zones": []map[string]any{{"name": region + "a"}},
			},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("cannot build infraConfig: %w", err)
		}
	}
	if platform == "converged-cloud" {
		infraConfig, err = marshalRaw(map[string]any{
			"apiVersion":           fmt.Sprintf("%s.provider.extensions.gardener.cloud/v1alpha1", platform),
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
				architecture := string(arch)
				var machineType string
				if platform == "aws" {
					machineType = "a1.2xlarge"
					if architecture == "amd64" {
						machineType = "m5.large"
					}
				} else if platform == "alicloud" {
					machineType = "ecs.t6-c1m2.large"
				} else if platform == "gcp" {
					machineType = "n1-standard-2"
					if architecture == "arm64" {
						machineType = "t2a-standard-2"
					}
				} else if platform == "converged-cloud" {
					machineType = "m1.xsmall"
				} else if platform == "az" {
					machineType = "Standard_DS2_v2"
				}

				zoneName := region + "a"
				if platform == "gcp" {
					zoneName = region + "-b"
				}
				if platform == "az" {
					zoneName = "1"
				}

				workers = append(workers, gardencorev1beta1.Worker{
					Name: fmt.Sprintf("gardenlinux-%s-%s-%s", major, strings.ToLower(platform), architecture),
					Machine: gardencorev1beta1.Machine{
						Type: machineType,
						Image: &gardencorev1beta1.ShootMachineImage{
							Name:    "gardenlinux",
							Version: &version,
						},
						Architecture: ptr(architecture),
					},
					Zones:   []string{zoneName},
					Maximum: 2,
					Minimum: 2,
				})
			}
		}
	}

	shoot := &gardencorev1beta1.Shoot{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core.gardener.cloud/v1beta1",
			Kind:       "Shoot",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("gardenlinux-%s-%s", major, strings.ToLower(platform)),
			Namespace: fmt.Sprintf("gardenlinux-%s", major),
		},
		Spec: gardencorev1beta1.ShootSpec{
			Provider: gardencorev1beta1.Provider{
				Type:                 platform,
				InfrastructureConfig: infraConfig,
				Workers:              workers,
			},
			Kubernetes: gardencorev1beta1.Kubernetes{
				Version: "latest",
			},
			CloudProfile: &gardencorev1beta1.CloudProfileReference{
				Name: fmt.Sprintf("gardenlinux-%s-%s", major, strings.ToLower(platform)),
				Kind: "NamespacedCloudProfile",
			},
			Region: region,
		},
	}

	jsonBytes, err := json.Marshal(shoot)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal shoot to JSON: %w", err)
	}
	var intermediate any
	if err := json.Unmarshal(jsonBytes, &intermediate); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal shoot JSON: %w", err)
	}

	shootYAML, err := yaml.Marshal(intermediate)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal shoot to YAML: %w", err)
	}

	return shoot, shootYAML, nil
}

func ptr[T any](v T) *T { return &v }

func BuildShootSpecYAML(version string, profile *gardencorev1beta1.NamespacedCloudProfile) ([]byte, error) {
	_, shootYAML, err := buildShootSpec(version, profile)
	return shootYAML, err
}
