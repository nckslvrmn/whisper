package ots_gcs

import (
	"context"
	"fmt"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/nckslvrmn/go_ots/pkg/utils"
	"google.golang.org/api/option"
)

type GCSStore struct {
	client *storage.Client
	bucket *storage.BucketHandle
}

func NewGCSStore() *GCSStore {
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithScopes(storage.ScopeReadWrite))
	if err != nil {
		panic(fmt.Errorf("failed to create GCS client: %v", err))
	}

	return &GCSStore{
		client: client,
		bucket: client.Bucket(utils.GCSBucket),
	}
}

func (g *GCSStore) StoreEncryptedFile(secret_id string, data []byte) error {
	ctx := context.Background()

	// Create a new object in the bucket
	obj := g.bucket.Object(secret_id + ".enc")
	writer := obj.NewWriter(ctx)

	// Write the encrypted data
	if _, err := io.Copy(writer, strings.NewReader(utils.B64E(data))); err != nil {
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
