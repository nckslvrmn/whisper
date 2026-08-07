package aws

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
)

type S3API interface {
	manager.UploadAPIClient
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3Store struct {
	client S3API
}

func NewS3Store() storagetypes.FileStore {
	cfg, _ := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(config.AWSRegion))
	return &S3Store{
		client: s3.NewFromConfig(cfg),
	}
}

func objectKey(id string) *string {
	return aws.String(id + ".enc")
}

func (s *S3Store) StoreEncryptedFile(ctx context.Context, id string, r io.Reader) error {
	// The uploader streams in parts, so the body length does not need to be
	// known up front and the whole file never lands in memory. Its replacement,
	// feature/s3/transfermanager, is still in preview.
	uploader := manager.NewUploader(s.client)          //nolint:staticcheck
	_, err := uploader.Upload(ctx, &s3.PutObjectInput{ //nolint:staticcheck
		Bucket:               aws.String(config.S3Bucket),
		Key:                  objectKey(id),
		Body:                 r,
		ACL:                  types.ObjectCannedACLPrivate,
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
	})
	if err != nil {
		return fmt.Errorf("failed to upload secret file to S3: %w", err)
	}

	return nil
}

func (s *S3Store) GetEncryptedFile(ctx context.Context, id string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(config.S3Bucket),
		Key:    objectKey(id),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, storagetypes.ErrNotFound
		}
		return nil, fmt.Errorf("failed to download secret file from S3: %w", err)
	}

	return storagetypes.DecodeStoredFile(out.Body)
}

func (s *S3Store) DeleteEncryptedFile(ctx context.Context, id string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(config.S3Bucket),
		Key:    objectKey(id),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete secret file from S3: %w", err)
	}

	return nil
}

func isS3NotFound(err error) bool {
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var notFound *types.NotFound
	return errors.As(err, &notFound)
}
