package cloudprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/gl"
)

// ArtifactSource is a source of artifacts which can retrieve arbitrary objects as well as retrieve and publish manifests.
type ArtifactSource interface {
	Type() string
	SetCredentials(credentials map[string]any) error
	SetSourceConfig(ctx context.Context, config map[string]any) error
	Close() error
	Repository() string
	GetObjectURL(key string) string
	GetObjectSize(ctx context.Context, key string) (int64, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, object io.Reader) error
}

// PublishingTarget is a target onto which GLCI can publish Garden Linux images.
type PublishingTarget interface {
	Type() string
	SetCredentials(credentials map[string]any) error
	SetTargetConfig(ctx context.Context, credentials map[string]any, sources map[string]ArtifactSource) error
	Close() error
	ImageSuffix() string
	IsPublished(manifest *gl.Manifest) (bool, error)
	AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error)
	RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error)
	Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput, error)
	Remove(ctx context.Context, manifest *gl.Manifest, sources map[string]ArtifactSource) error
}

// OCMTarget is a target onto which GLCI can publish an OCM component descriptor.
type OCMTarget interface {
	Type() string
	SetCredentials(credentials map[string]any) error
	SetOCMConfig(ctx context.Context, config map[string]any) error
	Close() error
	OCMRepository() string
	PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error
}

// NewArtifactSource returns a new ArtifactSource of a given type.
func NewArtifactSource(typ string) (ArtifactSource, error) {
	nf, ok := sources[typ]
	if !ok {
		return nil, fmt.Errorf("artifact source %s is not supported", typ)
	}

	return nf(), nil
}

// NewPublishingTarget returns a new PublishingTarget of a given type.
func NewPublishingTarget(typ string) (PublishingTarget, error) {
	nf, ok := targets[typ]
	if !ok {
		return nil, fmt.Errorf("publishing target %s is not supported", typ)
	}

	return nf(), nil
}

// NewOCMTarget returns a new OCMTarget of a given type.
func NewOCMTarget(typ string) (OCMTarget, error) {
	nf, ok := ocms[typ]
	if !ok {
		return nil, fmt.Errorf("OCM target %s is not supported", typ)
	}

	return nf(), nil
}

// GetManifest retrieves a manifest from an artifact source.
func GetManifest(ctx context.Context, source ArtifactSource, key string) (*gl.Manifest, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, err //nolint:wrapcheck // Directly wraps the source.
	}
	defer func() {
		_ = body.Close()
	}()

	var rawManifest map[string]any
	err = yaml.NewDecoder(body).Decode(&rawManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}

	manifest := &gl.Manifest{}
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
func PutManifest(ctx context.Context, source ArtifactSource, key string, manifest *gl.Manifest) error {
	var buf bytes.Buffer
	err := yaml.NewEncoder(&buf).Encode(manifest)
	if err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}

	return source.PutObject(ctx, key, &buf) //nolint:wrapcheck // Directly wraps the source.
}

// Publication represents the act of publishing an image including what is being published where and what the result is.
type Publication struct {
	Cname    string
	Manifest *gl.Manifest
	Target   PublishingTarget
}

// PublishingOutput is an opaque representation of the result of a publishing operation.
type PublishingOutput any

// KeyNotFoundError wraps a source-specific error inficating that a given key is not present.
type KeyNotFoundError struct {
	err error
}

func (e KeyNotFoundError) Error() string {
	return e.err.Error()
}

//nolint:gochecknoglobals // Required for automatic registration.
var (
	sources = make(map[string]newArtifactSourceFunc)
	targets = make(map[string]newPublishingTargetFunc)
	ocms    = make(map[string]newOCMTargetFunc)
)

type newArtifactSourceFunc func() ArtifactSource

func registerArtifactSource(nf newArtifactSourceFunc) {
	sources[nf().Type()] = nf
}

type newPublishingTargetFunc func() PublishingTarget

func registerPublishingTarget(nf newPublishingTargetFunc) {
	targets[nf().Type()] = nf
}

type newOCMTargetFunc func() OCMTarget

func registerOCMTarget(nf newOCMTargetFunc) {
	ocms[nf().Type()] = nf
}

func setCredentials[CREDS any](allCreds map[string]any, section string, creds *map[string]CREDS) error {
	rawCreds, ok := allCreds[section]
	if !ok {
		return errors.New("missing credentials")
	}

	var sCreds map[string]any
	sCreds, ok = rawCreds.(map[string]any)
	if !ok {
		return errors.New("invalid credentials")
	}

	if *creds == nil {
		*creds = make(map[string]CREDS, len(sCreds))
	}

	for configuration, cCreds := range sCreds {
		var c CREDS
		err := mapstructure.Decode(cCreds, &c)
		if err != nil {
			return fmt.Errorf("invalid credentials for configuration %s: %w", configuration, err)
		}

		(*creds)[configuration] = c
	}

	return nil
}

func setConfig[CONFIG any](cfg map[string]any, config *CONFIG) error {
	err := mapstructure.Decode(cfg, &config)
	if err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
}

func getObjectBytes(ctx context.Context, source ArtifactSource, key string) ([]byte, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, err //nolint:wrapcheck // Directly wraps the source.
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

func publishingOutput[PUBOUT any](generic PublishingOutput) (PUBOUT, error) {
	var output PUBOUT

	err := mapstructure.Decode(generic, &output)
	if err != nil {
		return output, fmt.Errorf("invalid publishing output: %w", err)
	}

	return output, nil
}

func publishingOutputFromManifest[PUBOUT any](manifest *gl.Manifest) (PUBOUT, error) {
	output, err := publishingOutput[PUBOUT](manifest.PublishedImageMetadata)
	if err != nil {
		return output, fmt.Errorf("invalid published image metadata in manifest: %w", err)
	}

	return output, nil
}
