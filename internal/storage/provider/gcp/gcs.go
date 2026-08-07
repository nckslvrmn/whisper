package gcp

import (
	"context"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"google.golang.org/api/option"
)

type BucketHandleInterface interface {
	Object(name string) ObjectHandleInterface
}

type ObjectHandleInterface interface {
	NewReader(ctx context.Context) (io.ReadCloser, error)
	NewWriter(ctx context.Context) io.WriteCloser
	Delete(ctx context.Context) error
}

type bucketHandleWrapper struct {
	bucket *storage.BucketHandle
}

func (b *bucketHandleWrapper) Object(name string) ObjectHandleInterface {
	return &objectHandleWrapper{obj: b.bucket.Object(name)}
}

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
		bucket: &bucketHandleWrapper{bucket: client.Bucket(config.GCSBucket)},
	}
}

func (g *GCSStore) StoreEncryptedFile(ctx context.Context, id string, r io.Reader) error {
	writer := g.bucket.Object(id + ".enc").NewWriter(ctx)

	if _, err := io.Copy(writer, r); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write encrypted file to GCS: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close GCS writer: %w", err)
	}

	return nil
}

func (g *GCSStore) GetEncryptedFile(ctx context.Context, id string) (io.ReadCloser, error) {
	reader, err := g.bucket.Object(id + ".enc").NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, storagetypes.ErrNotFound
		}
		return nil, fmt.Errorf("failed to read encrypted file from GCS: %w", err)
	}

	return storagetypes.DecodeStoredFile(reader)
}

func (g *GCSStore) DeleteEncryptedFile(ctx context.Context, id string) error {
	if err := g.bucket.Object(id + ".enc").Delete(ctx); err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil
		}
		return fmt.Errorf("failed to delete encrypted file from GCS: %w", err)
	}

	return nil
}

func (g *GCSStore) Close() error {
	if g.client == nil {
		return nil
	}
	return g.client.Close()
}
