package gcp

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
	storagetypes "github.com/nckslvrmn/secure_secret_share/internal/storage/types"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreClientInterface defines the interface for Firestore client operations we use
type FirestoreClientInterface interface {
	Collection(path string) CollectionRefInterface
	Close() error
}

// CollectionRefInterface defines the interface for collection operations we use
type CollectionRefInterface interface {
	Doc(id string) DocumentRefInterface
}

// DocumentRefInterface defines the interface for document operations we use
type DocumentRefInterface interface {
	Get(ctx context.Context) (DocumentSnapshotInterface, error)
	Set(ctx context.Context, data interface{}) (*firestore.WriteResult, error)
	Delete(ctx context.Context, opts ...firestore.Precondition) (*firestore.WriteResult, error)
	Update(ctx context.Context, updates []firestore.Update, opts ...firestore.Precondition) (*firestore.WriteResult, error)
}

// DocumentSnapshotInterface defines the interface for document snapshot operations we use
type DocumentSnapshotInterface interface {
	Data() map[string]interface{}
}

// firestoreClientWrapper wraps firestore.Client to implement FirestoreClientInterface
type firestoreClientWrapper struct {
	client *firestore.Client
}

func (f *firestoreClientWrapper) Collection(path string) CollectionRefInterface {
	return &collectionRefWrapper{collection: f.client.Collection(path)}
}

func (f *firestoreClientWrapper) Close() error {
	return f.client.Close()
}

// collectionRefWrapper wraps firestore.CollectionRef to implement CollectionRefInterface
type collectionRefWrapper struct {
	collection *firestore.CollectionRef
}

func (c *collectionRefWrapper) Doc(id string) DocumentRefInterface {
	return &documentRefWrapper{doc: c.collection.Doc(id)}
}

// documentRefWrapper wraps firestore.DocumentRef to implement DocumentRefInterface
type documentRefWrapper struct {
	doc *firestore.DocumentRef
}

func (d *documentRefWrapper) Get(ctx context.Context) (DocumentSnapshotInterface, error) {
	snapshot, err := d.doc.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &documentSnapshotWrapper{snapshot: snapshot}, nil
}

func (d *documentRefWrapper) Set(ctx context.Context, data interface{}) (*firestore.WriteResult, error) {
	return d.doc.Set(ctx, data)
}

func (d *documentRefWrapper) Delete(ctx context.Context, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	return d.doc.Delete(ctx, opts...)
}

func (d *documentRefWrapper) Update(ctx context.Context, updates []firestore.Update, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	return d.doc.Update(ctx, updates, opts...)
}

// documentSnapshotWrapper wraps firestore.DocumentSnapshot to implement DocumentSnapshotInterface
type documentSnapshotWrapper struct {
	snapshot *firestore.DocumentSnapshot
}

func (d *documentSnapshotWrapper) Data() map[string]interface{} {
	return d.snapshot.Data()
}

type FirestoreStore struct {
	client FirestoreClientInterface
}

func NewFirestoreStore() (storagetypes.SecretStore, error) {
	ctx := context.Background()
	client, err := firestore.NewClientWithDatabase(ctx, utils.GCPProjectID, utils.FirestoreDatabase)
	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client: %v", err)
	}

	return &FirestoreStore{
		client: &firestoreClientWrapper{client: client},
	}, nil
}

func (f *FirestoreStore) StoreSecretRaw(secretId string, data []byte, ttl int64, viewCount int) error {
	ctx := context.Background()

	// Create document data
	secretData := map[string]interface{}{
		"view_count": viewCount,
		"data":       utils.B64E(data),
		"ttl":        ttl,
	}

	// Store in Firestore using secret_id as document ID
	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Set(ctx, secretData)
	if err != nil {
		return fmt.Errorf("failed to store secret in Firestore: %w", err)
	}

	return nil
}

func (f *FirestoreStore) GetSecretRaw(secretId string) ([]byte, error) {
	ctx := context.Background()

	// Get document from Firestore
	doc, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to get secret from Firestore: %w", err)
	}

	// Extract data from document
	docData := doc.Data()

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

	// Delete document from Firestore
	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Delete(ctx)
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

	// Update the data field
	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Update(ctx, []firestore.Update{
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
