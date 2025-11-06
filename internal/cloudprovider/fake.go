package cloudprovider

import (
	"context"
	"io"

	"github.com/gardenlinux/glci/internal/gl"
	"github.com/gardenlinux/glci/internal/task"
)

func init() {
	registerArtifactSource(func() ArtifactSource {
		return &fake{}
	})

	registerPublishingTarget(func() PublishingTarget {
		return &fake{}
	})

	registerOCMTarget(func() OCMTarget {
		return &fake{}
	})
}

func (*fake) Type() string {
	return "Fake"
}

func (*fake) SetCredentials(_ map[string]any) error {
	return nil
}

func (*fake) SetSourceConfig(_ context.Context, _ map[string]any) error {
	return nil
}

func (*fake) SetTargetConfig(_ context.Context, _ map[string]any, _ map[string]ArtifactSource) error {
	return nil
}

func (*fake) SetOCMConfig(_ context.Context, _ map[string]any) error {
	return nil
}

func (*fake) Close() error {
	return nil
}

func (*fake) Repository() string {
	return "fake"
}

func (*fake) GetObjectURL(_ context.Context, _ string) (string, error) {
	return "https://example.com/fake", nil
}

func (*fake) GetObjectSize(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

func (p *fake) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	return p, nil
}

func (*fake) PutObject(_ context.Context, _ string, _ io.Reader) error {
	return nil
}

func (*fake) ImageSuffix() string {
	return ".fake"
}

func (*fake) CanPublish(_ *gl.Manifest) bool {
	return true
}

func (*fake) IsPublished(_ *gl.Manifest) (bool, error) {
	return false, nil
}

func (*fake) AddOwnPublishingOutput(output, _ PublishingOutput) (PublishingOutput, error) {
	return output, nil
}

func (*fake) RemoveOwnPublishingOutput(output PublishingOutput) (PublishingOutput, error) {
	return output, nil
}

func (p *fake) Publish(_ context.Context, _ string, _ *gl.Manifest, _ map[string]ArtifactSource) (PublishingOutput, error) {
	return p, nil
}

func (*fake) CanRollback() string {
	return ""
}

func (*fake) Rollback(_ context.Context, _ map[string]task.Task) error {
	return nil
}

func (*fake) Remove(_ context.Context, _ *gl.Manifest, _ map[string]ArtifactSource, _ bool) error {
	return nil
}

func (*fake) OCMType() string {
	return "Fake"
}

func (*fake) OCMRepositoryBase() string {
	return "fake"
}

func (*fake) PublishComponentDescriptor(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (*fake) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

type fake struct{}
