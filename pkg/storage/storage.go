package storage

import (
	"fmt"

	"github.com/nckslvrmn/go_ots/pkg/ots_dynamo"
	"github.com/nckslvrmn/go_ots/pkg/ots_firestore"
	"github.com/nckslvrmn/go_ots/pkg/ots_gcs"
	"github.com/nckslvrmn/go_ots/pkg/ots_s3"
	"github.com/nckslvrmn/go_ots/pkg/simple_crypt"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

// SecretStore defines the interface for storing and retrieving secrets
type SecretStore interface {
	StoreSecret(s *simple_crypt.Secret) error
	GetSecret(secretId string) (*simple_crypt.Secret, error)
	DeleteSecret(secretId string) error
	UpdateSecret(s *simple_crypt.Secret) error
}

// FileStore defines the interface for storing and retrieving encrypted files
type FileStore interface {
	StoreEncryptedFile(secret_id string, data []byte) error
	GetEncryptedFile(secret_id string) ([]byte, error)
	DeleteEncryptedFile(secret_id string) error
}

var secretStore SecretStore
var fileStore FileStore

// Initialize sets up the appropriate storage backend based on environment variables
func Initialize() error {
	// Check if AWS configuration is provided
	if utils.UsesAWS {
		secretStore = ots_dynamo.NewDynamoStore()
		fileStore = ots_s3.NewS3Store()
		return nil
	}

	// Check if Google Cloud configuration is provided
	if utils.UsesGCP {
		secretStore, _ = ots_firestore.NewFirestoreStore()
		fileStore = ots_gcs.NewGCSStore()
		return nil
	}

	return fmt.Errorf("no valid storage configuration found")
}

// GetSecretStore returns the configured secret store
func GetSecretStore() SecretStore {
	return secretStore
}

// GetFileStore returns the configured file store
func GetFileStore() FileStore {
	return fileStore
}
