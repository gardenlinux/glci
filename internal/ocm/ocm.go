package ocm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/cloudprovider"
	"github.com/gardenlinux/glci/internal/concurrency"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/log"
	"github.com/gardenlinux/glci/internal/ocm/access"
)

const (
	componentProvider = "SAP SE"
	githubRepoURL     = "https://" + gardenlinux.GardenLinuxRepo
)

// ComponentDescriptor is an OCM data structure that Gardener consumes.
type ComponentDescriptor struct {
	Meta      componentDescriptorMetadata  `yaml:"meta"`
	Component componentDescriptorComponent `yaml:"component"`
}

// ToYAML serializes a component desctiptor to YAML.
func (d *ComponentDescriptor) ToYAML() ([]byte, error) {
	return yaml.Marshal(d)
}

//nolint:tagliatelle // Defined by OCM.
type componentDescriptorMetadata struct {
	ConfiguredVersion string `yaml:"configuredSchemaVersion"`
}

//nolint:tagliatelle // Defined by OCM.
type componentDescriptorComponent struct {
	Name                string                                 `yaml:"name"`
	Version             string                                 `yaml:"version"`
	Labels              []componentDescriptorlabel             `yaml:"labels,omitempty"`
	CreationTime        string                                 `yaml:"creationTime"`
	Provider            string                                 `yaml:"provider"`
	RepositoryContexts  []componentDescriptorRepositoryContext `yaml:"repositoryContexts"`
	Sources             []componentDescriptorSource            `yaml:"sources"`
	ComponentReferences []struct{}                             `yaml:"componentReferences"`
	Resources           []componentDesciptorResource           `yaml:"resources"`
}

type componentDescriptorlabel struct {
	Name  string `yaml:"name"`
	Value any    `yaml:"value"`
}

//nolint:tagliatelle // Defined by OCM.
type componentDescriptorRepositoryContext struct {
	Type    string `yaml:"type"`
	BaseURL string `yaml:"baseUrl"`
}

type componentDescriptorSource struct {
	Name    string                     `yaml:"name"`
	Version string                     `yaml:"version"`
	Labels  []componentDescriptorlabel `yaml:"labels,omitempty"`
	Type    string                     `yaml:"type"`
	Access  componentDescriptorGitHub  `yaml:"access"`
}

//nolint:tagliatelle // Defined by OCM.
type componentDescriptorGitHub struct {
	Type    string `yaml:"type"`
	RepoURL string `yaml:"repoUrl"`
	Commit  string `yaml:"commit"`
}

//nolint:tagliatelle // Defined by OCM.
type componentDesciptorResource struct {
	Name          string                     `yaml:"name"`
	Version       string                     `yaml:"version"`
	ExtraIdentity map[string]string          `yaml:"extraIdentity,omitempty"`
	Labels        []componentDescriptorlabel `yaml:"labels,omitempty"`
	Type          string                     `yaml:"type"`
	Digest        componentDescriptorDigest  `yaml:"digest,omitzero"`
	Access        access.Spec                `yaml:"access"`
}

//nolint:tagliatelle // Defined by OCM.
type componentDescriptorDigest struct {
	HashAlgorithm          string `yaml:"hashAlgorithm"`
	NormalisationAlgorithm string `yaml:"normalisationAlgorithm"`
	Value                  string `yaml:"value"`
}

type nameVersion struct {
	name    string
	version string
}

// ManifestTarget pairs a manifest with the target that publishes it.
type ManifestTarget struct {
	Manifest *gardenlinux.Manifest
	Target   cloudprovider.PublishingTarget
}

// BuildComponentDescriptor generates a component desciptor that includes all data except the results of the publishing process.
func BuildComponentDescriptor(ctx context.Context, source cloudprovider.ArtifactSource, manifestTargets []ManifestTarget,
	ocmTarget cloudprovider.OCMTarget, aliases map[string][]string, glciVersion, version, commit string,
) (*ComponentDescriptor, error) {
	log.Debug(ctx, "Building component descriptor")

	descriptor := &ComponentDescriptor{
		Meta: componentDescriptorMetadata{
			ConfiguredVersion: "v2",
		},
		Component: componentDescriptorComponent{
			Name:    gardenlinux.GardenLinuxRepo,
			Version: version,
			Labels: []componentDescriptorlabel{
				{
					Name:  "glci_version",
					Value: glciVersion,
				},
			},
			CreationTime: time.Now().Format(time.RFC3339),
			Provider:     componentProvider,
			RepositoryContexts: []componentDescriptorRepositoryContext{
				{
					Type:    ocmTarget.OCMType(),
					BaseURL: ocmTarget.OCMRepositoryBase(),
				},
			},
			Sources: []componentDescriptorSource{
				{
					Name:    "gardenlinux",
					Version: version,
					Labels: []componentDescriptorlabel{
						{
							Name: "cloud.gardener.cnudie/dso/scanning-hints/source_analysis/v1",
							Value: map[string]any{
								"policy":  "skip",
								"comment": "repo only contains build instructions",
							},
						},
					},
					Type: "git",
					Access: componentDescriptorGitHub{
						Type:    "gitHub",
						RepoURL: githubRepoURL,
						Commit:  commit,
					},
				},
			},
			ComponentReferences: []struct{}{},
		},
	}

	packages := make([][]nameVersion, len(manifestTargets))
	fetchPackages := concurrency.NewActivitySync(ctx)
	for i, mt := range manifestTargets {
		fetchPackages.Go(func(ctx context.Context) (concurrency.ResultSyncFunc, error) {
			pkgs, err := getPackages(ctx, source, mt.Manifest)
			if err != nil {
				return nil, fmt.Errorf("cannot list packages for %s: %w", mt.Manifest.Flavor, err)
			}

			return func() error {
				packages[i] = pkgs

				return nil
			}, nil
		})
	}
	err := fetchPackages.Wait()
	if err != nil {
		return nil, err
	}

	for i, mt := range manifestTargets {
		labels := make([]componentDescriptorlabel, 0, 3)
		labels = append(labels, componentDescriptorlabel{
			Name: "gardener.cloud/gardenlinux/ci/build-metadata",
			Value: map[string]any{
				"modifiers":      mt.Manifest.Modifiers,
				"buildTimestamp": mt.Manifest.BuildTimestamp,
			},
		})
		if glciVersion != "" {
			labels = append(labels, componentDescriptorlabel{
				Name:  "gardenlinux.org/glci/version",
				Value: glciVersion,
			})
		}

		packageVersions := getPackageVersions(packages[i], aliases)
		if len(packageVersions) > 0 {
			labels = append(labels, componentDescriptorlabel{
				Name:  "cloud.cnudie/dso/scanning-hints/package-versions",
				Value: packageVersions,
			})
		}

		extraIdentity := map[string]string{
			"feature-flags":    strings.Join(mt.Manifest.Modifiers, ","),
			"architecture":     string(mt.Manifest.Architecture),
			"platform":         mt.Manifest.Platform,
			"platform_variant": mt.Manifest.PlatformVariant,
		}
		if mt.Manifest.PlatformVariant == "" {
			delete(extraIdentity, "platform_variant")
		}
		descriptor.Component.Resources = append(descriptor.Component.Resources, componentDesciptorResource{
			Name:          "gardenlinux",
			Version:       mt.Manifest.Version,
			ExtraIdentity: extraIdentity,
			Labels:        labels,
			Type:          "virtual_machine_image",
			Digest: componentDescriptorDigest{
				HashAlgorithm:          "NO-DIGEST",
				NormalisationAlgorithm: "EXCLUDE-FROM-SIGNATURE",
				Value:                  "NO-DIGEST",
			},
		}, componentDesciptorResource{
			Name:          "rootfs",
			Version:       mt.Manifest.Version,
			ExtraIdentity: extraIdentity,
			Labels: []componentDescriptorlabel{
				{
					Name: "gardener.cloud/gardenlinux/ci/build-metadata",
					Value: map[string]any{
						"modifiers":      mt.Manifest.Modifiers,
						"buildTimestamp": mt.Manifest.BuildTimestamp,
						"debianPackages": getPackageList(packages[i]),
					},
				},
				{
					Name: "cloud.gardener.cnudie/responsibles",
					Value: []map[string]string{
						{
							"type":  "emailAddress",
							"email": "andre.russ@sap.com",
						},
					},
				},
			},
			Type: "application/tar+vm-image-rootfs",
			Digest: componentDescriptorDigest{
				HashAlgorithm:          "NO-DIGEST",
				NormalisationAlgorithm: "EXCLUDE-FROM-SIGNATURE",
				Value:                  "NO-DIGEST",
			},
		},
		)
	}

	return descriptor, nil
}

func getPackages(ctx context.Context, source cloudprovider.ArtifactSource, manifest *gardenlinux.Manifest) ([]nameVersion, error) {
	log.Debug(ctx, "Getting packages")

	manifestPath, err := manifest.PathBySuffix(".manifest")
	if err != nil {
		return nil, fmt.Errorf("missing packagae manifest: %w", err)
	}

	var packageManifest io.ReadCloser
	packageManifest, err = source.GetObject(ctx, manifestPath.S3Key)
	if err != nil {
		return nil, fmt.Errorf("cannot get package manifest: %w", err)
	}
	defer func() {
		_ = packageManifest.Close()
	}()

	var packages []nameVersion
	scanner := bufio.NewScanner(packageManifest)
	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		} else if len(tokens) != 2 {
			return nil, fmt.Errorf("invalid package-version %s", line)
		}

		packages = append(packages, nameVersion{
			name:    tokens[0],
			version: tokens[1],
		})
	}
	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("cannot read package manifest: %w", err)
	}

	err = packageManifest.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close package manifest: %w", err)
	}

	return packages, nil
}

func getPackageVersions(packages []nameVersion, aliases map[string][]string) []map[string]any {
	packageVersions := make([]map[string]any, 0, len(packages))
	for _, p := range packages {
		a, ok := aliases[p.name]
		if !ok {
			a = []string{}
		}
		packageVersions = append(packageVersions, map[string]any{
			"name":    p.name,
			"aliases": a,
			"version": p.version,
		})
	}
	return packageVersions
}

func getPackageList(packages []nameVersion) []string {
	l := make([]string, 0, len(packages))
	for _, p := range packages {
		l = append(l, fmt.Sprintf("%s %s", p.name, p.version))
	}
	return l
}

// AddPublicationOutput adds the outputs of the publishing process to an existing component descriptor.
func AddPublicationOutput(ctx context.Context, descriptor *ComponentDescriptor, manifestTargets []ManifestTarget) error {
	if len(descriptor.Component.Resources) != len(manifestTargets)*2 {
		return fmt.Errorf("invalid component descriptor: expected %d resources, got %d", len(manifestTargets)*2,
			len(descriptor.Component.Resources))
	}

	for i, mt := range manifestTargets {
		if descriptor.Component.Resources[i*2].Type != "virtual_machine_image" {
			return fmt.Errorf("invalid component descriptor: resource %d has incorrect type %s", i*2,
				descriptor.Component.Resources[i*2].Type)
		}
		if descriptor.Component.Resources[i*2].Name != "gardenlinux" {
			return fmt.Errorf("invalid component descriptor: resource %d has incorrect name %s", i*2,
				descriptor.Component.Resources[i*2].Name)
		}

		imageAccess, err := mt.Target.ImageAccess(ctx, mt.Manifest)
		if err != nil {
			return fmt.Errorf("cannot get image access for %s: %w", mt.Manifest.Flavor, err)
		}
		if imageAccess == nil {
			return fmt.Errorf("missing image access for %s", mt.Manifest.Flavor)
		}
		descriptor.Component.Resources[i*2].Access = imageAccess

		var rootfsAccess access.Spec
		rootfsAccess, err = mt.Target.RootfsAccess(ctx, mt.Manifest)
		if err != nil {
			return fmt.Errorf("cannot get rootfs access for %s: %w", mt.Manifest.Flavor, err)
		}
		if rootfsAccess == nil {
			return fmt.Errorf("missing rootfs access for %s", mt.Manifest.Flavor)
		}
		descriptor.Component.Resources[i*2+1].Access = rootfsAccess

		descriptor.Component.Resources[i*2].Labels = append(descriptor.Component.Resources[i*2].Labels, componentDescriptorlabel{
			Name:  "gardener.cloud/gardenlinux/ci/published-image-metadata",
			Value: mt.Manifest.PublishedImageMetadata,
		})
	}

	return nil
}
