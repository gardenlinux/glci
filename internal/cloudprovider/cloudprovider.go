package cloudprovider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/goccy/go-yaml"

	"github.com/gardenlinux/glci/internal/cli"
	"github.com/gardenlinux/glci/internal/gardenlinux"
	"github.com/gardenlinux/glci/internal/module"
	"github.com/gardenlinux/glci/internal/resilience"
)

const statusPollInterval = time.Second * 3

// ArtifactSourceCategory is the module framework registry for ArtifactSource implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var ArtifactSourceCategory = module.NewCategory[ArtifactSource]("source")

// PublishingTargetCategory is the module framework registry for PublishingTarget implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var PublishingTargetCategory = module.NewCategory[PublishingTarget]("target")

// OCMTargetCategory is the module framework registry for OCMTarget implementations.
//
//nolint:gochecknoglobals // Required for automatic registration.
var OCMTargetCategory = module.NewCategory[OCMTarget]("target")

// ObjectProperties holds the system properties of an artifact object.
type ObjectProperties struct {
	Size        int64
	ContentType string
	SHA256      string
}

// ArtifactSource is a source of artifacts which can retrieve arbitrary objects as well as retrieve and publish manifests.
type ArtifactSource interface {
	module.Module

	Repository() string
	GetObjectURL(ctx context.Context, key string) (string, error)
	GetObjectProperties(ctx context.Context, key string) (ObjectProperties, error)
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	PutObject(ctx context.Context, key string, object io.Reader, contentType string) error
}

// ReplicateArtifact copies an artifact object under key from one artifact source to another.
func ReplicateArtifact(ctx context.Context, origin, destination ArtifactSource, key string) error {
	properties, err := origin.GetObjectProperties(ctx, key)
	if err != nil {
		return fmt.Errorf("cannot get properties of object %s: %w", key, err)
	}

	var object io.ReadCloser
	object, err = origin.GetObject(ctx, key)
	if err != nil {
		return fmt.Errorf("cannot get object %s: %w", key, err)
	}
	defer func() {
		_ = object.Close()
	}()

	err = destination.PutObject(ctx, key, object, properties.ContentType)
	if err != nil {
		return fmt.Errorf("cannot put object %s: %w", key, err)
	}

	err = object.Close()
	if err != nil {
		return fmt.Errorf("cannot close object: %w", err)
	}

	return nil
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

// PutManifest stores a manifest into an ArtifactSource, stamping the version that wrote it.
func PutManifest(ctx context.Context, source ArtifactSource, key string, manifest *gardenlinux.Manifest) error {
	manifest.GLCIVersion = cli.Version(ctx)

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

	return source.PutObject(ctx, key, bytes.NewReader(buf.Bytes()), "text/yaml")
}

// GetGroupManifest retrieves a group manifest from an artifact source.
func GetGroupManifest(ctx context.Context, source ArtifactSource, key string) (*gardenlinux.GroupManifest, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = body.Close()
	}()

	var rawGroupManifest map[string]any
	err = yaml.NewDecoder(body).Decode(&rawGroupManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid group manifest: %w", err)
	}

	groupManifest := &gardenlinux.GroupManifest{}
	var decoder *mapstructure.Decoder
	decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result:  groupManifest,
		TagName: "yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("invalid group manifest: %w", err)
	}
	err = decoder.Decode(rawGroupManifest)
	if err != nil {
		return nil, fmt.Errorf("invalid group manifest: %w", err)
	}

	err = body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object: %w", err)
	}

	return groupManifest, nil
}

// PutGroupManifest stores a group manifest into an ArtifactSource, stamping the version that wrote it.
func PutGroupManifest(ctx context.Context, source ArtifactSource, key string, groupManifest *gardenlinux.GroupManifest) error {
	groupManifest.GLCIVersion = cli.Version(ctx)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	defer func() {
		_ = enc.Close()
	}()

	err := enc.Encode(groupManifest)
	if err != nil {
		return fmt.Errorf("cannot encode group manifest: %w", err)
	}
	err = enc.Close()
	if err != nil {
		return fmt.Errorf("cannot encode group manifest: %w", err)
	}

	return source.PutObject(ctx, key, bytes.NewReader(buf.Bytes()), "text/yaml")
}

// PublishingTarget is a target onto which GLCI can publish Garden Linux images.
type PublishingTarget interface {
	module.Module

	Type() string
	ImageSuffix() string
	RequiredReplications(manifest *gardenlinux.Manifest) ([]Replication, error)
	CanPublish(manifest *gardenlinux.Manifest) bool
	IsPublished(manifest *gardenlinux.Manifest) (bool, error)
	Publish(ctx context.Context, flavor string, manifest *gardenlinux.Manifest) (PublishingOutput, error)
	CanUnpublish() bool
	Unpublish(ctx context.Context, manifest *gardenlinux.Manifest, steamroll bool) error
	CanFuse() bool
	Fuse(ctx context.Context, flavorManifests []gardenlinux.FlavorManifest) (PublishingOutput, error)
	Unfuse(ctx context.Context, flavorManifests []gardenlinux.FlavorManifest, steamroll bool) error
	resilience.RollbackHandler
}

// Replication describes an artifact object to be copied from one artifact source to another.
type Replication struct {
	Origin        ArtifactSource
	OriginID      string
	Destination   ArtifactSource
	DestinationID string
	Key           string
	SHA256        string
}

// IsReplicated reports whether the destination already holds the artifact with the expected content digest and type.
func (r Replication) IsReplicated(ctx context.Context) (bool, error) {
	if r.SHA256 == "" {
		return false, nil
	}

	destination, err := r.Destination.GetObjectProperties(ctx, r.Key)
	if err != nil {
		_, ok := errors.AsType[*KeyNotFoundError](err)
		if ok {
			return false, nil
		}

		return false, fmt.Errorf("cannot get destination object properties: %w", err)
	}
	if destination.SHA256 == "" || destination.SHA256 != r.SHA256 {
		return false, nil
	}

	var origin ObjectProperties
	origin, err = r.Origin.GetObjectProperties(ctx, r.Key)
	if err != nil {
		return false, fmt.Errorf("cannot get origin object properties: %w", err)
	}

	return destination.ContentType == origin.ContentType, nil
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

func individualPublishingOutputFromManifest[PUBOUT any](manifest *gardenlinux.Manifest) (PUBOUT, error) {
	output, err := publishingOutput[PUBOUT](manifest.IndividualPublishedImageMetadata)
	if err != nil {
		return output, fmt.Errorf("invalid individual published image metadata in manifest: %w", err)
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

// KeyNotFoundError wraps a source-specific error inficating that a given key is not present.
type KeyNotFoundError struct {
	err error
}

func (e *KeyNotFoundError) Error() string {
	return e.err.Error()
}

//nolint:unused // Canonical base for targets that cannot be unpublished.
type notUnpublishableTarget struct{}

//nolint:unused // Canonical base for targets that cannot be unpublished.
func (notUnpublishableTarget) CanUnpublish() bool {
	return false
}

//nolint:unused // Canonical base for targets that cannot be unpublished.
func (notUnpublishableTarget) Unpublish(_ context.Context, _ *gardenlinux.Manifest, _ bool) error {
	return errors.New("target cannot unpublish")
}

//nolint:unused // Canonical base for targets that cannot be unpublished.
func (notUnpublishableTarget) RollbackDomain() string {
	return ""
}

//nolint:unused // Canonical base for targets that cannot be unpublished.
func (notUnpublishableTarget) Rollback(_ context.Context, _ map[string]resilience.Operation) error {
	return errors.New("target cannot rollback")
}

type nonFusableTarget struct{}

func (nonFusableTarget) CanFuse() bool {
	return false
}

func (nonFusableTarget) Fuse(_ context.Context, _ []gardenlinux.FlavorManifest) (PublishingOutput, error) {
	return nil, errors.New("target cannot fuse")
}

func (nonFusableTarget) Unfuse(_ context.Context, _ []gardenlinux.FlavorManifest, _ bool) error {
	return errors.New("target cannot unfuse")
}

type noReplicationsTarget struct{}

func (noReplicationsTarget) RequiredReplications(_ *gardenlinux.Manifest) ([]Replication, error) {
	return nil, nil
}

func platform(flavor string) string {
	p, _, _ := strings.Cut(flavor, "-")
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

func getObjectFile(ctx context.Context, source ArtifactSource, key string) (string, error) {
	body, err := source.GetObject(ctx, key)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = body.Close()
	}()

	var f *os.File
	f, err = os.CreateTemp("", "")
	if err != nil {
		return "", fmt.Errorf("cannot create file: %w", err)
	}

	var success bool
	defer func() {
		if success {
			return
		}

		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	_, err = io.Copy(f, body)
	if err != nil {
		return "", fmt.Errorf("cannot copy object to file %s: %w", f.Name(), err)
	}

	err = f.Close()
	if err != nil {
		return "", fmt.Errorf("cannot close file %s: %w", f.Name(), err)
	}

	err = body.Close()
	if err != nil {
		return "", fmt.Errorf("cannot close object: %w", err)
	}

	success = true
	return f.Name(), nil
}

func subset(original, subset []string) []string {
	res := make([]string, 0, min(len(original), len(subset)))
	for _, e := range original {
		if slices.Contains(subset, e) {
			res = append(res, e)
		}
	}
	return res
}

func equalSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	present := make(map[string]struct{}, len(a))
	for _, e := range a {
		present[e] = struct{}{}
	}
	for _, e := range b {
		_, ok := present[e]
		if !ok {
			return false
		}
	}

	return true
}
