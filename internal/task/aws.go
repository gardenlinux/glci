package task

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/logging"

	"github.com/gardenlinux/glci/internal/ptr"
)

func init() {
	registerStatePersistor(func() StatePersistor {
		return &aws{}
	})
}

func (*aws) Type() string {
	return "AWS"
}

func (p *aws) SetCredentials(creds map[string]any) error {
	return setCredentials(creds, "aws", &p.creds)
}

func (p *aws) SetStateConfig(ctx context.Context, cfg any) error {
	err := setConfig(cfg, &p.stateCfg)
	if err != nil {
		return err
	}

	if p.creds == nil {
		return errors.New("credentials not set")
	}
	creds, ok := p.creds[p.stateCfg.Config]
	if !ok {
		return fmt.Errorf("missing credentials config %s", p.stateCfg.Config)
	}

	var awsCfg awssdk.Config
	awsCfg, err = config.LoadDefaultConfig(ctx, config.WithLogger(logging.Nop{}), config.WithRegion(creds.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, "")))
	if err != nil {
		return fmt.Errorf("cannot load default config: %w", err)
	}
	p.s3Client = s3.NewFromConfig(awsCfg)

	return nil
}

func (p *aws) SetID(id string) {
	p.key = "state_" + id + ".json"
}

func (*aws) Close() error {
	return nil
}

func (p *aws) Load() ([]byte, error) {
	if !p.isConfigured() {
		return nil, errors.New("config or ID not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	r, err := p.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &p.stateCfg.Bucket,
		Key:    &p.key,
	})
	if err != nil {
		var noSuchKey *s3types.NoSuchKey
		if !errors.As(err, &noSuchKey) {
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*37)
	defer cancel()

	_, err := p.s3Client.PutObject(ctx, &s3.PutObjectInput{
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

type aws struct {
	creds    map[string]awsCredentials
	stateCfg awsStateCfg
	key      string
	s3Client *s3.Client
}

type awsCredentials struct {
	Region          string `mapstructure:"region"`
	AccessKeyID     string `mapstructure:"access_key_id"`
	SecretAccessKey string `mapstructure:"secret_access_key"`
}

type awsStateCfg struct {
	Config string `mapstructure:"config"`
	Bucket string `mapstructure:"bucket"`
}

func (p *aws) isConfigured() bool {
	return p.stateCfg.Bucket != "" && p.key != ""
}
