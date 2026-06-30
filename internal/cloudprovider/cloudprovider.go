package cloudprovider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/task"
)

// ArtifactSourceCategory is the module framework registry for ArtifactSource implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var ArtifactSourceCategory = module.NewCategory[ArtifactSource]()

// PublishingTargetCategory is the module framework registry for PublishingTarget implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var PublishingTargetCategory = module.NewCategory[PublishingTarget]()

// OCMTargetCategory is the module framework registry for OCMTarget implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var OCMTargetCategory = module.NewCategory[OCMTarget]()

// ArtifactSource is a source of artifacts which can retrieve arbitrary objects as well as retrieve and publish manifests.
type ArtifactSource interface {
	module.Module

	Type() string
	Repository() string
	GetObjectURL(ctx context.Context, key string) (string, error)
	GetObjectSize(ctx context.Context, key string) (int64, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, object io.Reader) error
}

// GetManifest retrieves a manifest from an artifact source.
func GetManifest(ctx context.Context, source ArtifactSource, key string) (*gardenlinux.Manifest, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = body.Close()
	}()

	var rawManifest map[string]any
	err = yaml.NewDecoder(body).Decode(&rawManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	manifest := &gardenlinux.Manifest{}
	var decoder *mapstructure.Decoder
	decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  manifest,
		TagName: "yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	err = decoder.Decode(rawManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	err = body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object: %w", err)
	}

	return manifest, nil
}

// PutManifest stores a manifest into an ArtifactSource.
func PutManifest(ctx context.Context, source ArtifactSource, key string, manifest *gardenlinux.Manifest) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	defer func() {
		_ = enc.Close()
	}()

	err := enc.Encode(manifest)
	if err != nil {
		return fmt.Errorf("cannot encode manifest: %w", err)
	}
	err = enc.Close()
	if err != nil {
		return fmt.Errorf("cannot encode manifest: %w", err)
	}

	return source.PutObject(ctx, key, &buf)
}

// PublishingTarget is a target onto which GLCI can publish Garden Linux images.
type PublishingTarget interface {
	module.Module

	Type() string
	ImageSuffix() string
	CanPublish(manifest *gardenlinux.Manifest) bool
	IsPublished(manifest *gardenlinux.Manifest) (bool, error)
	Publish(ctx context.Context, cname string, manifest *gardenlinux.Manifest) (PublishingOutput, error)
	Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error
	task.RollbackHandler
}

// PublishingOutput is an opaque representation of the result of a publishing operation.
type PublishingOutput any

func publishingOutput[PUBOUT any](generic PublishingOutput) (PUBOUT, error) {
	var output PUBOUT

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  &output,
		TagName: "yaml",
	})
	if err != nil {
		return output, fmt.Errorf("invalid publishing output: %w", err)
	}
	err = decoder.Decode(generic)
	if err != nil {
		return output, fmt.Errorf("invalid publishing output: %w", err)
	}

	return output, nil
}

func publishingOutputFromManifest[PUBOUT any](manifest *gardenlinux.Manifest) (PUBOUT, error) {
	output, err := publishingOutput[PUBOUT](manifest.PublishedImageMetadata)
	if err != nil {
		return output, fmt.Errorf("invalid published image metadata in manifest: %w", err)
	}

	return output, nil
}

// OCMTarget is a target onto which GLCI can publish an OCM component descriptor.
type OCMTarget interface {
	module.Module

	Type() string
	OCMType() string
	OCMRepositoryBase() string
	PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error
}

// Publication represents the act of publishing an image including what is being published where and what the result is.
type Publication struct {
	Cname    string
	Manifest *gardenlinux.Manifest
	Target   PublishingTarget
}

// KeyNotFoundError wraps a source-specific error inficating that a given key is not present.
type KeyNotFoundError struct {
	err error
}

func (e KeyNotFoundError) Error() string {
	return e.err.Error()
}

func platform(cname string) string {
	p, _, _ := strings.Cut(cname, "-")
	return p
}

func parseConfig[CONFIG any](cfg map[string]any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}

func parseCredentials[CREDS any](rawCreds map[string]any, creds *CREDS) error {
	err := mapstructure.Decode(rawCreds, creds)
	if err != nil {
		return fmt.Errorf("invalid credentials: %w", err)
	}

	return nil
}

func getObjectBytes(ctx context.Context, source ArtifactSource, key string) ([]byte, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = body.Close()
	}()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(body)
	if err != nil {
		return nil, fmt.Errorf("cannot read object: %w", err)
	}

	err = body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object: %w", err)
	}

	return buf.Bytes(), nil
}
