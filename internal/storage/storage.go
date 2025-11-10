package storage

import (
	"fmt"
	"log"

	"github.com/nckslvrmn/whisper/internal/config"
	"github.com/nckslvrmn/whisper/internal/storage/provider/aws"
	"github.com/nckslvrmn/whisper/internal/storage/provider/gcp"
	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
	"github.com/nckslvrmn/whisper/internal/storage/types"
)

var secretStore types.SecretStore
var fileStore types.FileStore

func Initialize() error {
	if err := config.LoadStorageConfig(); err != nil {
		return fmt.Errorf("failed to load storage config: %w", err)
	}

	if config.UsesAWS {
		log.Println("Initializing AWS storage providers (DynamoDB and S3)")
		secretStore = aws.NewDynamoStore()
		fileStore = aws.NewS3Store()
		return nil
	}

	if config.UsesGCP {
		log.Println("Initializing GCP storage providers (Firestore and GCS)")
		var err error
		secretStore, err = gcp.NewFirestoreStore()
		if err != nil {
			return fmt.Errorf("failed to initialize Firestore: %w", err)
		}
		fileStore = gcp.NewGCSStore()
		return nil
	}

	log.Println("No AWS or GCP configuration found, using local storage providers (SQLite and file system)")

	fileStore = local.NewLocalFileStore(config.DataDir)

	var err error
	secretStore, err = local.NewSQLiteStore(config.DataDir, fileStore)
	if err != nil {
		return fmt.Errorf("failed to initialize SQLite store: %w", err)
	}

	return nil
}

func GetSecretStore() types.SecretStore {
	return secretStore
}

func GetFileStore() types.FileStore {
	return fileStore
}

func SetSecretStore(store types.SecretStore) {
	secretStore = store
}

func SetFileStore(store types.FileStore) {
	fileStore = store
}
