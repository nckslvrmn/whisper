package aws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

// MockS3Client implements S3API
type MockS3Client struct {
	putObject    func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	getObject    func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	deleteObject func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.putObject != nil {
		return m.putObject(ctx, params, optFns...)
	}
	return nil, errors.New("PutObject not implemented")
}

func (m *MockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.getObject != nil {
		return m.getObject(ctx, params, optFns...)
	}
	return nil, errors.New("GetObject not implemented")
}

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	if m.deleteObject != nil {
		return m.deleteObject(ctx, params, optFns...)
	}
	return nil, errors.New("DeleteObject not implemented")
}

// mockReadCloser implements io.ReadCloser for testing
type mockReadCloser struct {
	reader io.Reader
}

func (m mockReadCloser) Read(p []byte) (n int, err error) {
	return m.reader.Read(p)
}

func (m mockReadCloser) Close() error {
	return nil
}

func TestS3Store_StoreEncryptedFile(t *testing.T) {
	tests := []struct {
		name     string
		secretID string
		data     []byte
		mockFn   func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
		wantErr  bool
	}{
		{
			name:     "successful store",
			secretID: "test-id",
			data:     []byte("test data"),
			mockFn: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				if *params.Bucket != utils.S3Bucket {
					return nil, errors.New("invalid bucket name")
				}
				if *params.Key != "test-id.enc" {
					return nil, errors.New("invalid key")
				}
				if params.ACL != types.ObjectCannedACLPrivate {
					return nil, errors.New("invalid ACL")
				}
				if params.ServerSideEncryption != types.ServerSideEncryptionAwsKms {
					return nil, errors.New("invalid encryption setting")
				}
				return &s3.PutObjectOutput{}, nil
			},
			wantErr: false,
		},
		{
			name:     "s3 error",
			secretID: "test-id",
			data:     []byte("test data"),
			mockFn: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				return nil, errors.New("s3 error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &S3Store{
				client: &MockS3Client{
					putObject: tt.mockFn,
				},
			}

			err := store.StoreEncryptedFile(tt.secretID, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestS3Store_GetEncryptedFile(t *testing.T) {
	testData := []byte("test data")

	tests := []struct {
		name     string
		secretID string
		mockFn   func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
		want     []byte
		wantErr  bool
	}{
		{
			name:     "successful get",
			secretID: "test-id",
			mockFn: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				if *params.Bucket != utils.S3Bucket {
					return nil, errors.New("invalid bucket name")
				}
				if *params.Key != "test-id.enc" {
					return nil, errors.New("invalid key")
				}
				return &s3.GetObjectOutput{
					Body: mockReadCloser{reader: strings.NewReader(string(testData))},
				}, nil
			},
			want:    testData,
			wantErr: false,
		},
		{
			name:     "s3 error",
			secretID: "test-id",
			mockFn: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				return nil, errors.New("s3 error")
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:     "invalid base64",
			secretID: "test-id",
			mockFn: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				return &s3.GetObjectOutput{
					Body: mockReadCloser{reader: strings.NewReader("invalid base64")},
				}, nil
			},
			want:    []byte("invalid base64"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &S3Store{
				client: &MockS3Client{
					getObject: tt.mockFn,
				},
			}

			got, err := store.GetEncryptedFile(tt.secretID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("GetEncryptedFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS3Store_DeleteEncryptedFile(t *testing.T) {
	tests := []struct {
		name     string
		secretID string
		mockFn   func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
		wantErr  bool
	}{
		{
			name:     "successful delete",
			secretID: "test-id",
			mockFn: func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
				if *params.Bucket != utils.S3Bucket {
					return nil, errors.New("invalid bucket name")
				}
				if *params.Key != "test-id.enc" {
					return nil, errors.New("invalid key")
				}
				return &s3.DeleteObjectOutput{}, nil
			},
			wantErr: false,
		},
		{
			name:     "s3 error",
			secretID: "test-id",
			mockFn: func(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
				return nil, errors.New("s3 error")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &S3Store{
				client: &MockS3Client{
					deleteObject: tt.mockFn,
				},
			}

			err := store.DeleteEncryptedFile(tt.secretID)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteEncryptedFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
