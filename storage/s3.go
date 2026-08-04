package storage

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config configures an S3-compatible backend. Works as-is against AWS
// S3, Scaleway Object Storage, and Cloudflare R2 (all S3-compatible, per
// prd.md's "Option 2 — Object Storage") — only Endpoint/Region change
// between providers.
type S3Config struct {
	Bucket    string
	Region    string
	AccessKey string
	SecretKey string

	// Endpoint overrides the default AWS endpoint. Leave empty for real
	// AWS S3. Examples:
	//   Scaleway:      https://s3.<region>.scw.cloud
	//   Cloudflare R2: https://<account-id>.r2.cloudflarestorage.com
	Endpoint string
}

// S3Store implements Store against S3-compatible object storage.
type S3Store struct {
	client *s3.Client
	bucket string
}

var _ Store = (*S3Store)(nil)

func NewS3Store(ctx context.Context, cfg S3Config) (*S3Store, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		// Most S3-compatible providers (Scaleway, R2, MinIO) require
		// path-style addressing rather than AWS's virtual-hosted style.
		o.UsePathStyle = true
	})

	return &S3Store{client: client, bucket: cfg.Bucket}, nil
}

func (s *S3Store) Save(ctx context.Context, key string, body io.Reader, size int64) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	})
	if err != nil {
		return fmt.Errorf("unable to upload object %q: %w", key, err)
	}

	return nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("unable to delete object %q: %w", key, err)
	}
	return nil
}
