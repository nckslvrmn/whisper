package ots_s3

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

var s3Client *s3.Client

func initS3Client() {
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(utils.AWSRegion))
	s3Client = s3.NewFromConfig(cfg)
}

func StoreEncryptedFile(secret_id string, data []byte) error {
	if s3Client == nil {
		initS3Client()
	}

	_, err := s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:               aws.String(utils.S3Bucket),
		Key:                  aws.String(secret_id + ".enc"),
		Body:                 strings.NewReader(utils.B64E(data)),
		ACL:                  types.ObjectCannedACLPrivate,
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
	})
	if err != nil {
		return fmt.Errorf("failed to upload secret file to S3: %w", err)
	}

	return nil
}

func GetEncryptedFile(secret_id string) ([]byte, error) {
	if s3Client == nil {
		initS3Client()
	}

	getObjectOutput, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(utils.S3Bucket),
		Key:    aws.String(secret_id + ".enc"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download secret file from S3: %w", err)
	}
	defer getObjectOutput.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(getObjectOutput.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the S3 file content: %w", err)
	}

	return buf.Bytes(), nil
}

func DeleteEncryptedFile(secret_id string) error {
	if s3Client == nil {
		initS3Client()
	}
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(utils.S3Bucket),
		Key:    aws.String(secret_id + ".enc"),
	})
	if err != nil {
		return fmt.Errorf("failed to delete secret file from S3: %w", err)
	}

	return nil
}
