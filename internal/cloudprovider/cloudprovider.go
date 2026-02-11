package cloudprovider

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/task"
)

//nolint:gochecknoglobals // Required for automatic registration.
var (
	sources = make(map[string]newArtifactSourceFunc)
	targets = make(map[string]newPublishingTargetFunc)
	ocms    = make(map[string]newOCMTargetFunc)
)

// ArtifactSource is a source of artifacts which can retrieve arbitrary objects as well as retrieve and publish manifests.
type ArtifactSource interface {
	Type() string
	SetSourceConfig(ctx context.Context, credsSource credsprovider.CredsSource, config map[string]any) error
	Repository() string
	GetObjectURL(ctx context.Context, key string) (string, error)
	GetObjectSize(ctx context.Context, key string) (int64, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, object io.Reader) error
	Close() error
}

// NewArtifactSource returns a new ArtifactSource of a given type.
func NewArtifactSource(typ string) (ArtifactSource, error) {
	nf, ok := sources[typ]
	if !ok {
		return nil, fmt.Errorf("artifact source %s is not supported", typ)
	}

	return nf(), nil
}

type newArtifactSourceFunc func() ArtifactSource

func registerArtifactSource(nf newArtifactSourceFunc) {
	sources[nf().Type()] = nf
}

// GetManifest retrieves a manifest from an artifact source.
func GetManifest(ctx context.Context, source ArtifactSource, key string) (*gl.Manifest, error) {
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
	Type() string
	SetTargetConfig(ctx context.Context, credsSource credsprovider.CredsSource, config map[string]any,
		sources map[string]ArtifactSource) error
	ImageSuffix() string
	CanPublish(manifest *gl.Manifest) bool
	IsPublished(manifest *gl.Manifest) (bool, error)
	AddOwnPublishingOutput(output, own PublishingOutput) (PublishingOutput, error)
	RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error)
	Publish(ctx context.Context, cname string, manifest *gl.Manifest, sources map[string]ArtifactSource) (PublishingOutput, error)
	Remove(ctx context.Context, manifest *gl.Manifest, sources map[string]ArtifactSource, steamroll bool) error
	Close() error
	task.RollbackHandler
}

// PublishingOutput is an opaque representation of the result of a publishing operation.
type PublishingOutput any

// NewPublishingTarget returns a new PublishingTarget of a given type.
func NewPublishingTarget(typ string) (PublishingTarget, error) {
	nf, ok := targets[typ]
	if !ok {
		return nil, fmt.Errorf("publishing target %s is not supported", typ)
	}

	return nf(), nil
}

type newPublishingTargetFunc func() PublishingTarget

func registerPublishingTarget(nf newPublishingTargetFunc) {
	targets[nf().Type()] = nf
}

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

func publishingOutputFromManifest[PUBOUT any](manifest *gl.Manifest) (PUBOUT, error) {
	output, err := publishingOutput[PUBOUT](manifest.PublishedImageMetadata)
	if err != nil {
		return output, fmt.Errorf("invalid published image metadata in manifest: %w", err)
	}

	return output, nil
}

// OCMTarget is a target onto which GLCI can publish an OCM component descriptor.
type OCMTarget interface {
	Type() string
	SetOCMConfig(ctx context.Context, credsSource credsprovider.CredsSource, config map[string]any) error
	OCMType() string
	OCMRepositoryBase() string
	PublishComponentDescriptor(ctx context.Context, version string, descriptor []byte) error
	Close() error
}

// NewOCMTarget returns a new OCMTarget of a given type.
func NewOCMTarget(typ string) (OCMTarget, error) {
	nf, ok := ocms[typ]
	if !ok {
		return nil, fmt.Errorf("OCM target %s is not supported", typ)
	}

	return nf(), nil
}

type newOCMTargetFunc func() OCMTarget

func registerOCMTarget(nf newOCMTargetFunc) {
	ocms[nf().Type()] = nf
}

// Publication represents the act of publishing an image including what is being published where and what the result is.
type Publication struct {
	Cname    string
	Manifest *gl.Manifest
	Target   PublishingTarget
}

// KeyNotFoundError wraps a source-specific error inficating that a given key is not present.
type KeyNotFoundError struct {
	err error
}

func (e KeyNotFoundError) Error() string {
	return e.err.Error()
}

func flavor(cname string) string {
	return strings.SplitN(cname, "-", 2)[0]
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
