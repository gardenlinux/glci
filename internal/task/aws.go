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
	"github.com/gardenlinux/glci/internal/ptr"
)

func init() {
	env.Clean("AWS_")
	env.Clean("_X_AMZN_")

	registerStatePersistor(func() StatePersistor {
		return &aws{}
	})
}

func (*aws) Type() string {
	return "AWS"
}

type aws struct {
	stateCfg    awsStateConfig
	key         string
	credsSource credsprovider.CredsSource
	clientsMtx  sync.RWMutex
	s3Client    *s3.Client
}

type awsStateConfig struct {
	Config string `mapstructure:"config"`
	Region string `mapstructure:"region"`
	Bucket string `mapstructure:"bucket"`
}

func (p *aws) isConfigured() bool {
	return p.stateCfg.Bucket != "" && p.key != ""
}

func (p *aws) SetStateConfig(ctx context.Context, credsSource credsprovider.CredsSource, cfg any) error {
	p.credsSource = credsSource

	err := parseConfig(cfg, &p.stateCfg)
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

	err = credsSource.AcquireCreds(ctx, credsprovider.CredsID{
		Type:   p.Type(),
		Config: p.stateCfg.Config,
	}, p.createClients)
	if err != nil {
		return fmt.Errorf("cannot acquire credentials: %w", err)
	}

	return nil
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

func (p *aws) clients() *s3.Client {
	p.clientsMtx.RLock()
	defer p.clientsMtx.RUnlock()

	return p.s3Client
}

func (p *aws) SetID(id string) {
	p.key = "state_" + id + ".json"
}

func (p *aws) Load() ([]byte, error) {
	if !p.isConfigured() {
		return nil, errors.New("config or ID not set")
	}

	s3Client := p.clients()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	r, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.stateCfg.Bucket,
		Key:    &p.key,
	})
	if err != nil {
		if !errors.As(err, ptr.P(&s3types.NoSuchKey{})) {
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

	s3Client := p.clients()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          &p.stateCfg.Bucket,
		Key:             &p.key,
		Body:            bytes.NewReader(state),
		ContentEncoding: ptr.P("utf-8"),
		ContentType:     ptr.P("application/json"),
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

	s3Client := p.clients()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	_, err := s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &p.stateCfg.Bucket,
		Key:    &p.key,
	})
	if err != nil {
		return fmt.Errorf("cannot delete object %s in bucket %s: %w", p.key, p.stateCfg.Bucket, err)
	}

	return nil
}

func (p *aws) Close() error {
	if p.stateCfg.Config != "" {
		p.credsSource.ReleaseCreds(credsprovider.CredsID{
			Type:   p.Type(),
			Config: p.stateCfg.Config,
		})
	}

	return nil
}
