package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type FirestoreStore struct {
	client *firestore.Client
}

func NewFirestoreStore() (storagetypes.SecretStore, error) {
	ctx := context.Background()
	client, err := firestore.NewClientWithDatabase(ctx, config.GCPProjectID, config.FirestoreDatabase)
	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client: %w", err)
	}

	return &FirestoreStore{
		client: client,
	}, nil
}

func (f *FirestoreStore) StoreSecretRaw(secretId string, data []byte, ttl *int64, viewCount *int) error {
	ctx := context.Background()

	secretData := map[string]any{
		"data": utils.B64E(data),
	}

	if viewCount != nil {
		secretData["view_count"] = *viewCount
	}

	if ttl != nil {
		secretData["ttl"] = *ttl
	}

	_, err := f.client.Collection(config.FirestoreDatabase).Doc(secretId).Set(ctx, secretData)
	if err != nil {
		return fmt.Errorf("failed to store secret in Firestore: %w", err)
	}

	return nil
}

func (f *FirestoreStore) GetSecretRaw(secretId string) ([]byte, error) {
	ctx := context.Background()

	snapshot, err := f.client.Collection(config.FirestoreDatabase).Doc(secretId).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to get secret from Firestore: %w", err)
	}

	docData := snapshot.Data()

	if encData, ok := docData["data"].(string); ok {
		data, err := utils.B64D(encData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode data: %w", err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("data field not found")
}

func (f *FirestoreStore) DeleteSecret(secretId string) error {
	ctx := context.Background()

	_, err := f.client.Collection(config.FirestoreDatabase).Doc(secretId).Delete(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil // Document already deleted or doesn't exist
		}
		return fmt.Errorf("failed to delete secret from Firestore: %w", err)
	}

	return nil
}

func (f *FirestoreStore) UpdateSecretRaw(secretId string, data []byte) error {
	ctx := context.Background()

	_, err := f.client.Collection(config.FirestoreDatabase).Doc(secretId).Update(ctx, []firestore.Update{
		{
			Path:  "data",
			Value: utils.B64E(data),
		},
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return fmt.Errorf("secret not found")
		}
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}
