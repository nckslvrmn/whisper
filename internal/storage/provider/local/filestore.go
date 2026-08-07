package local

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
)

func isValidSecretId(secretId string) bool {
	return !strings.Contains(secretId, "/") &&
		!strings.Contains(secretId, "\\") &&
		!strings.Contains(secretId, "..") &&
		secretId != ""
}

type LocalFileStore struct {
	dataDir string
}

func NewLocalFileStore(dataDir string) storagetypes.FileStore {
	filesDir := filepath.Join(dataDir, "files")

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		log.Printf("Warning: failed to create files directory: %v", err)
	}

	log.Printf("Local file store initialized at %s", filesDir)
	return &LocalFileStore{
		dataDir: filesDir,
	}
}

func (l *LocalFileStore) StoreEncryptedFile(ctx context.Context, id string, r io.Reader) error {
	if !isValidSecretId(id) {
		return fmt.Errorf("invalid secretId")
	}

	f, err := os.OpenFile(filepath.Join(l.dataDir, id), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to store encrypted file: %w", err)
	}

	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return fmt.Errorf("failed to store encrypted file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to store encrypted file: %w", err)
	}

	return nil
}

func (l *LocalFileStore) GetEncryptedFile(ctx context.Context, id string) (io.ReadCloser, error) {
	if !isValidSecretId(id) {
		return nil, fmt.Errorf("invalid secretId")
	}

	f, err := os.Open(filepath.Join(l.dataDir, id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, storagetypes.ErrNotFound
		}
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	return storagetypes.DecodeStoredFile(f)
}

func (l *LocalFileStore) DeleteEncryptedFile(ctx context.Context, id string) error {
	if !isValidSecretId(id) {
		return fmt.Errorf("invalid secretId")
	}

	err := os.Remove(filepath.Join(l.dataDir, id))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete encrypted file: %w", err)
	}

	return nil
}
