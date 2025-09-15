package storage

import (
	"fmt"
	"os"

	"github.com/nckslvrmn/secure_secret_share/internal/storage/mock"
	"github.com/nckslvrmn/secure_secret_share/internal/storage/provider/aws"
	"github.com/nckslvrmn/secure_secret_share/internal/storage/provider/gcp"
	"github.com/nckslvrmn/secure_secret_share/internal/storage/types"
)

var secretStore types.SecretStore
var fileStore types.FileStore

// Initialize sets up the appropriate storage backend based on environment variables
func Initialize() error {
	// Check for AWS configuration
	if os.Getenv("DYNAMO_TABLE") != "" && os.Getenv("S3_BUCKET") != "" {
		// Use AWS storage
		secretStore = aws.NewDynamoStore()
		fileStore = aws.NewS3Store()
		return nil
	}

	// Check for GCP configuration
	if os.Getenv("FIRESTORE_DATABASE") != "" && os.Getenv("GCS_BUCKET") != "" {
		// Use GCP storage
		var err error
		secretStore, err = gcp.NewFirestoreStore()
		if err != nil {
			return fmt.Errorf("failed to initialize Firestore: %w", err)
		}
		fileStore = gcp.NewGCSStore()
		return nil
	}

	// Fall back to mock storage for development
	secretStore = mock.NewMockSecretStore()
	fileStore = mock.NewMockFileStore()
	return nil
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
