package local

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	storagetypes "github.com/nckslvrmn/secure_secret_share/internal/storage/types"
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

func (l *LocalFileStore) StoreEncryptedFile(secretId string, data []byte) error {
	if !isValidSecretId(secretId) {
		return fmt.Errorf("invalid secretId")
	}

	filePath := filepath.Join(l.dataDir, secretId)

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to store encrypted file: %w", err)
	}

	return nil
}

func (l *LocalFileStore) GetEncryptedFile(secretId string) ([]byte, error) {
	if !isValidSecretId(secretId) {
		return nil, fmt.Errorf("invalid secretId")
	}

	filePath := filepath.Join(l.dataDir, secretId)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found")
		}
		return nil, fmt.Errorf("failed to read encrypted file: %w", err)
	}

	return data, nil
}

func (l *LocalFileStore) DeleteEncryptedFile(secretId string) error {
	if !isValidSecretId(secretId) {
		return fmt.Errorf("invalid secretId")
	}

	filePath := filepath.Join(l.dataDir, secretId)

	err := os.Remove(filePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete encrypted file: %w", err)
	}

	return nil
}

func (l *LocalFileStore) DeleteFile(secretId string) error {
	return l.DeleteEncryptedFile(secretId)
}
