package storage

import (
	"fmt"

	"github.com/nckslvrmn/go_ots/pkg/simple_crypt"
	"github.com/nckslvrmn/go_ots/pkg/storage/provider/aws"
	"github.com/nckslvrmn/go_ots/pkg/storage/provider/gcp"
	"github.com/nckslvrmn/go_ots/pkg/storage/types"
	"github.com/nckslvrmn/go_ots/pkg/utils"
)

var secretStore types.SecretStore
var fileStore types.FileStore

// Initialize sets up the appropriate storage backend based on environment variables
func Initialize() error {
	// Check if AWS configuration is provided
	if utils.UsesAWS {
		secretStore = aws.NewDynamoStore()
		fileStore = aws.NewS3Store()
		return nil
	}

	// Check if Google Cloud configuration is provided
	if utils.UsesGCP {
		var err error
		secretStore, err = gcp.NewFirestoreStore()
		if err != nil {
			return fmt.Errorf("failed to initialize Firestore: %v", err)
		}
		fileStore = gcp.NewGCSStore()
		return nil
	}

	return fmt.Errorf("no valid storage configuration found")
}

// GetSecretStore returns the configured secret store
func GetSecretStore() types.SecretStore {
	return secretStore
}

// GetFileStore returns the configured file store
func GetFileStore() types.FileStore {
	return fileStore
}

// SetSecretStore sets the secret store (for testing)
func SetSecretStore(store types.SecretStore) {
	secretStore = store
}

// SetFileStore sets the file store (for testing)
func SetFileStore(store types.FileStore) {
	fileStore = store
}

// NewSecret creates a new secret (for testing)
func NewSecret() *simple_crypt.Secret {
	return simple_crypt.NewSecret()
}
