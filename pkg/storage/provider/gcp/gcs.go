package gcp

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	storagetypes "github.com/nckslvrmn/secure_secret_share/pkg/storage/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
	"google.golang.org/api/option"
)

// BucketHandleInterface defines the interface for bucket operations we use
type BucketHandleInterface interface {
	Object(name string) ObjectHandleInterface
}

// ObjectHandleInterface defines the interface for object operations we use
type ObjectHandleInterface interface {
	NewReader(ctx context.Context) (io.ReadCloser, error)
	NewWriter(ctx context.Context) io.WriteCloser
	Delete(ctx context.Context) error
}

// bucketHandleWrapper wraps storage.BucketHandle to implement BucketHandleInterface
type bucketHandleWrapper struct {
	bucket *storage.BucketHandle
}

func (b *bucketHandleWrapper) Object(name string) ObjectHandleInterface {
	return &objectHandleWrapper{obj: b.bucket.Object(name)}
}

// objectHandleWrapper wraps storage.ObjectHandle to implement ObjectHandleInterface
type objectHandleWrapper struct {
	obj *storage.ObjectHandle
}

func (o *objectHandleWrapper) NewReader(ctx context.Context) (io.ReadCloser, error) {
	return o.obj.NewReader(ctx)
}

func (o *objectHandleWrapper) NewWriter(ctx context.Context) io.WriteCloser {
	return o.obj.NewWriter(ctx)
}

func (o *objectHandleWrapper) Delete(ctx context.Context) error {
	return o.obj.Delete(ctx)
}

type GCSStore struct {
	client *storage.Client
	bucket BucketHandleInterface
}

func NewGCSStore() storagetypes.FileStore {
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithScopes(storage.ScopeReadWrite))
	if err != nil {
		panic(fmt.Errorf("failed to create GCS client: %v", err))
	}

	return &GCSStore{
		client: client,
		bucket: &bucketHandleWrapper{bucket: client.Bucket(utils.GCSBucket)},
	}
}

func (g *GCSStore) StoreEncryptedFile(secret_id string, data []byte) error {
	ctx := context.Background()

	// Create a new object in the bucket
	obj := g.bucket.Object(secret_id + ".enc")
	writer := obj.NewWriter(ctx)

	// Write the encrypted data
	if _, err := io.Copy(writer, bytes.NewReader(data)); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write encrypted file to GCS: %w", err)
	}

	// Close the writer
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer: %w", err)
	}

	return nil
}

func (g *GCSStore) GetEncryptedFile(secret_id string) ([]byte, error) {
	ctx := context.Background()

	// Get the object from the bucket
	obj := g.bucket.Object(secret_id + ".enc")
	reader, err := obj.NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file from GCS: %w", err)
	}
	defer reader.Close()

	// Read the encrypted data
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file content from GCS: %w", err)
	}

	return data, nil
}

func (g *GCSStore) DeleteEncryptedFile(secret_id string) error {
	ctx := context.Background()

	// Delete the object from the bucket
	obj := g.bucket.Object(secret_id + ".enc")
	if err := obj.Delete(ctx); err != nil {
		// If the object doesn't exist, that's fine
		if err == storage.ErrObjectNotExist {
			return nil
		}
		return fmt.Errorf("failed to delete encrypted file from GCS: %w", err)
	}

	return nil
}
