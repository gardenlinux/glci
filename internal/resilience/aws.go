package resilience

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/guard"
	"github.com/gardenlinux/glci/internal/module"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("AWS_")
	env.Clean("_X_AMZN_")

	module.RegisterImpl(Category, "AWS", func(b *module.Base) StatePersistor {
		p := &aws{
			base: b,
		}
		p.retrier = guard.NewRetrier(guard.NewGenerationalRetryPolicy(func() uint64 {
			return p.credsGen.Load()
		}), guard.DelegatingTimeoutPolicy{})
		return p
	})
}

func (*aws) Type() string {
	return "AWS"
}

type aws struct {
	base *module.Base

	credsSource credsprovider.CredsSource

	stateCfg awsStateConfig
	key      string

	credentialsProvider awsCredentialsProvider
	credsGen            atomic.Uint64
	retrier             guard.Retrier
	s3Client            *s3.Client
}

type awsStateConfig struct {
	Config string `mapstructure:"config"`
	Region string `mapstructure:"region"`
	Bucket string `mapstructure:"bucket"`
}

func (p *aws) isConfigured() bool {
	return p.stateCfg.Bucket != "" && p.key != ""
}

type awsCredentials struct {
	AccessKey    string `mapstructure:"access_key"`
	SecretKey    string `mapstructure:"secret_key"`
	SessionToken string `mapstructure:"session_token"`
}

type awsCredentialsProvider struct {
	credentials atomic.Pointer[awsCredentials]
}

func (p *awsCredentialsProvider) Retrieve(_ context.Context) (awssdk.Credentials, error) {
	creds := p.credentials.Load()
	if creds == nil {
		return awssdk.Credentials{}, errors.New("credentials not set")
	}

	return awssdk.Credentials{
		AccessKeyID:     creds.AccessKey,
		SecretAccessKey: creds.SecretKey,
		SessionToken:    creds.SessionToken,
		Source:          "GL",
	}, nil
}

func (p *aws) applyCredentials(ctx context.Context, rawCreds map[string]any) error {
	var creds awsCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.credentialsProvider.credentials.Store(&creds)
	p.credsGen.Add(1)

	if p.s3Client != nil {
		return nil
	}

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(p.stateCfg.Region),
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = guard.Retries + 1
				o.MaxBackoff = guard.RetryMaxDelay
				o.RateLimiter = ratelimit.None
			})
		}), config.WithHTTPClient(awshttp.NewBuildableClient().WithTransportOptions(func(t *http.Transport) {
			t.ResponseHeaderTimeout = guard.Timeout
		})))
	if err != nil {
		return fmt.Errorf("cannot load default config: %w", err)
	}
	awsCfg.Credentials = &p.credentialsProvider

	s3Client := s3.NewFromConfig(awsCfg)

	p.s3Client = s3Client

	return nil
}

func (p *aws) SetID(id string) {
	p.key = "state_" + id + ".json"
}

func (p *aws) Load() ([]byte, error) {
	if !p.isConfigured() {
		return nil, errors.New("config or ID not set")
	}

	var r *s3.GetObjectOutput
	err := p.retrier.Do(context.Background(), "get object", func(ctx context.Context) error {
		var inErr error
		r, inErr = p.s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &p.stateCfg.Bucket,
			Key:    &p.key,
		})
		return inErr
	})
	if err != nil {
		_, ok := errors.AsType[*s3types.NoSuchKey](err)
		if !ok {
			return nil, fmt.Errorf("cannot get object %s from bucket %s: %w", p.key, p.stateCfg.Bucket, err)
		}
		return nil, nil
	}
	defer func() {
		_ = r.Body.Close()
	}()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r.Body)
	if err != nil {
		return nil, fmt.Errorf("cannot read object %s from bucket %s: %w", p.key, p.stateCfg.Bucket, err)
	}

	err = r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close object %s from bucket %s: %w", p.key, p.stateCfg.Bucket, err)
	}

	return buf.Bytes(), nil
}

func (p *aws) Save(state []byte) error {
	if !p.isConfigured() {
		return errors.New("config or ID not set")
	}

	err := p.retrier.Do(context.Background(), "put object", func(ctx context.Context) error {
		_, inErr := p.s3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:          &p.stateCfg.Bucket,
			Key:             &p.key,
			Body:            bytes.NewReader(state),
			ContentEncoding: new("utf-8"),
			ContentType:     new("application/json"),
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot put object %s to bucket %s: %w", p.key, p.stateCfg.Bucket, err)
	}

	return nil
}

func (p *aws) Clear() error {
	if !p.isConfigured() {
		return errors.New("config or ID not set")
	}

	err := p.retrier.Do(context.Background(), "delete object", func(ctx context.Context) error {
		_, inErr := p.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: &p.stateCfg.Bucket,
			Key:    &p.key,
		})
		return inErr
	})
	if err != nil {
		return fmt.Errorf("cannot delete object %s in bucket %s: %w", p.key, p.stateCfg.Bucket, err)
	}

	return nil
}

func (p *aws) Configure(rawCfg map[string]any) error {
	err := parseConfig(rawCfg, &p.stateCfg)
	if err != nil {
		return err
	}

	switch {
	case p.stateCfg.Config == "":
		return errors.New("missing config")
	case p.stateCfg.Region == "":
		return errors.New("missing region")
	case p.stateCfg.Bucket == "":
		return errors.New("missing bucket")
	}

	err = module.RegisterTypeRef[credsprovider.CredsSource](p.base, p, &p.credsSource)
	if err != nil {
		return fmt.Errorf("cannot register credentials: %w", err)
	}

	return nil
}

func (*aws) Configurables() []module.Configurable {
	return nil
}

func (p *aws) Start(ctx context.Context) error {
	err := p.credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.stateCfg.Config,
		Role:   "state",
	}, p.applyCredentials)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials: %w", err)
	}

	return nil
}

func (p *aws) Stop(ctx context.Context) error {
	if p.stateCfg.Config != "" {
		p.credsSource.ReleaseCreds(ctx, credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.stateCfg.Config,
			Role:   "state",
		})
	}

	return nil
}
