package cloudprovider

import (
	"context"
	"io"

	"github.com/gardenlinux/glci/internal/gl"
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

type fake struct{}

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

func (p *fake) GetObject(_ context.Context, _ string) (io.ReadCloser, error) {
	return p, nil
}

func (*fake) GetObjectBytes(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

func (*fake) GetManifest(_ context.Context, _ string) (*gl.Manifest, error) {
	return &gl.Manifest{}, nil
}

func (*fake) PutManifest(_ context.Context, _ string, _ *gl.Manifest) error {
	return nil
}

func (*fake) ImageSuffix() string {
	return ".fake"
}

func (p *fake) Publish(_ context.Context, _ string, _ *gl.Manifest, _ map[string]ArtifactSource) (PublishingOutput, error) {
	return p, nil
}

func (*fake) Remove(_ context.Context, _ string, _ *gl.Manifest, _ map[string]ArtifactSource) error {
	return nil
}

func (*fake) OCMRepository() string {
	return "fake"
}

func (*fake) PublishComponentDescriptor(_ context.Context, _ string, _ []byte) error {
	return nil
}

func (*fake) Read(_ []byte) (int, error) {
	return 0, io.EOF
}
