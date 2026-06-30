package task

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/credsprovider"
	"github.com/gardenlinux/glci/internal/env"
	"github.com/gardenlinux/glci/internal/module"
)

//nolint:gochecknoinits // Required for automatic registration.
func init() {
	env.Clean("AWS_")
	env.Clean("_X_AMZN_")

	registerStatePersistor(func() StatePersistor {
		return &aws{}
	})
	module.RegisterImpl(Category, "AWS", func(b *module.Base) StatePersistor {
		return &aws{
			base: b,
		}
	})
}

func (*aws) Type() string {
	return "AWS"
}

type aws struct {
	base *module.Base

	credsSource credsprovider.CredsSource

	stateCfg   awsStateConfig
	key        string
	clientsMtx sync.RWMutex
	s3Client   *s3.Client
}

type awsStateConfig struct {
	Config string `mapstructure:"config"`
	Region string `mapstructure:"region"`
	Bucket string `mapstructure:"bucket"`
}

func (p *aws) isConfigured() bool {
	return p.stateCfg.Bucket != "" && p.key != ""
}

func (p *aws) SetStateConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg map[string]any) error {
	p.credsSource = credsSource

	err := p.Configure(cfg)
	if err != nil {
		return err
	}

	return p.Start(ctx)
}

type awsCredentials struct {
	AccessKey    string `mapstructure:"access_key"`
	SecretKey    string `mapstructure:"secret_key"`
	SessionToken string `mapstructure:"session_token"`
}

func (p *aws) createClients(ctx context.Context, rawCreds map[string]any) error {
	var creds awsCredentials
	err := parseCredentials(rawCreds, &creds)
	if err != nil {
		return err
	}

	p.clientsMtx.Lock()
	defer p.clientsMtx.Unlock()

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(p.stateCfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKey, creds.SecretKey, creds.SessionToken)),
		config.WithRetryer(func() awssdk.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.RateLimiter = ratelimit.None
			})
		}))
	if err != nil {
		return fmt.Errorf("cannot load default config: %w", err)
	}
	p.s3Client = s3.NewFromConfig(awsCfg)

	return nil
}

func (p *aws) SetID(id string) {
	p.key = "state_" + id + ".json"
}

func (p *aws) Load() ([]byte, error) {
	if !p.isConfigured() {
		return nil, errors.New("config or ID not set")
	}

	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	r, err := p.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.stateCfg.Bucket,
		Key:    &p.key,
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

	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	_, err := p.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &p.stateCfg.Bucket,
		Key:             &p.key,
		Body:            bytes.NewReader(state),
		ContentEncoding: new("utf-8"),
		ContentType:     new("application/json"),
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

	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	_, err := p.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &p.stateCfg.Bucket,
		Key:    &p.key,
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

	if p.base == nil {
		return nil
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
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials: %w", err)
	}

	return nil
}

func (p *aws) Stop() error {
	return p.Close()
}

func (p *aws) Close() error {
	if p.stateCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.stateCfg.Config,
			Role:   "state",
		})
	}

	return nil
}
