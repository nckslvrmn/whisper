package aws

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
)

type S3API interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3Store struct {
	client S3API
}

func NewS3Store() storagetypes.FileStore {
	cfg, _ := awsconfig.LoadDefaultConfig(context.TODO(), awsconfig.WithRegion(config.AWSRegion))
	return &S3Store{
		client: s3.NewFromConfig(cfg),
	}
}

func (s *S3Store) StoreEncryptedFile(secret_id string, data []byte) error {
	_, err := s.client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:               aws.String(config.S3Bucket),
		Key:                  aws.String(secret_id + ".enc"),
		Body:                 bytes.NewReader(data),
		ACL:                  types.ObjectCannedACLPrivate,
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
	})
	if err != nil {
		return fmt.Errorf("failed to upload secret file to S3: %w", err)
	}

	return nil
}

func (s *S3Store) GetEncryptedFile(secret_id string) ([]byte, error) {
	getObjectOutput, err := s.client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(config.S3Bucket),
		Key:    aws.String(secret_id + ".enc"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download secret file from S3: %w", err)
	}
	defer getObjectOutput.Body.Close()

	data, err := io.ReadAll(getObjectOutput.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the S3 file content: %w", err)
	}

	return data, nil
}

func (s *S3Store) DeleteEncryptedFile(secret_id string) error {
	_, err := s.client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(config.S3Bucket),
		Key:    aws.String(secret_id + ".enc"),
	})
	if err != nil {
		return fmt.Errorf("failed to delete secret file from S3: %w", err)
	}

	return nil
}

func (s *S3Store) DeleteFile(secret_id string) error {
	return s.DeleteEncryptedFile(secret_id)
}
