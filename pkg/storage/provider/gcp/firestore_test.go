package gcp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cloud.google.com/go/firestore"
	"github.com/nckslvrmn/secure_secret_share/pkg/simple_crypt"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockDocumentSnapshot implements DocumentSnapshotInterface
type mockDocumentSnapshot struct {
	data map[string]interface{}
}

func (m *mockDocumentSnapshot) Data() map[string]interface{} {
	return m.data
}

// mockDocumentRef implements DocumentRefInterface
type mockDocumentRef struct {
	data      map[string]interface{}
	getErr    error
	setErr    error
	delErr    error
	updateErr error
	exists    bool
}

func (m *mockDocumentRef) Get(ctx context.Context) (DocumentSnapshotInterface, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if !m.exists {
		return nil, status.Error(codes.NotFound, "document not found")
	}
	return &mockDocumentSnapshot{
		data: m.data,
	}, nil
}

func (m *mockDocumentRef) Set(ctx context.Context, data interface{}) (*firestore.WriteResult, error) {
	if m.setErr != nil {
		return nil, m.setErr
	}
	if mapData, ok := data.(map[string]interface{}); ok {
		m.data = mapData
		m.exists = true
	}
	return &firestore.WriteResult{}, nil
}

func (m *mockDocumentRef) Delete(ctx context.Context, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	if m.delErr != nil {
		return nil, m.delErr
	}
	m.exists = false
	m.data = nil
	return &firestore.WriteResult{}, nil
}

func (m *mockDocumentRef) Update(ctx context.Context, updates []firestore.Update, opts ...firestore.Precondition) (*firestore.WriteResult, error) {
	if m.updateErr != nil {
		return nil, m.updateErr
	}
	if !m.exists {
		return nil, status.Error(codes.NotFound, "document not found")
	}
	for _, update := range updates {
		m.data[update.Path] = update.Value
	}
	return &firestore.WriteResult{}, nil
}

// mockCollectionRef implements CollectionRefInterface
type mockCollectionRef struct {
	docs map[string]*mockDocumentRef
}

func (m *mockCollectionRef) Doc(id string) DocumentRefInterface {
	if doc, ok := m.docs[id]; ok {
		return doc
	}
	doc := &mockDocumentRef{
		data: make(map[string]interface{}),
	}
	m.docs[id] = doc
	return doc
}

// mockFirestoreClient implements FirestoreClientInterface
type mockFirestoreClient struct {
	collection *mockCollectionRef
}

func (m *mockFirestoreClient) Collection(path string) CollectionRefInterface {
	return m.collection
}

func (m *mockFirestoreClient) Close() error {
	return nil
}

// testFirestoreStore is a test-specific version of FirestoreStore that accepts our interfaces
type testFirestoreStore struct {
	client FirestoreClientInterface
}

func (f *testFirestoreStore) StoreSecret(s *simple_crypt.Secret) error {
	ctx := context.Background()

	secretData := map[string]interface{}{
		"view_count": s.ViewCount,
		"data":       utils.B64E(s.Data),
		"is_file":    s.IsFile,
		"nonce":      utils.B64E(s.Nonce),
		"salt":       utils.B64E(s.Salt),
		"header":     utils.B64E(s.Header),
		"ttl":        s.TTL,
	}

	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(s.SecretId).Set(ctx, secretData)
	if err != nil {
		return fmt.Errorf("failed to store secret in Firestore: %w", err)
	}

	return nil
}

func (f *testFirestoreStore) GetSecret(secretId string) (*simple_crypt.Secret, error) {
	ctx := context.Background()

	doc, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, fmt.Errorf("secret not found")
		}
		return nil, fmt.Errorf("failed to get secret from Firestore: %w", err)
	}

	secret := &simple_crypt.Secret{
		SecretId: secretId,
	}

	data := doc.Data()

	if viewCount, ok := data["view_count"].(int64); ok {
		secret.ViewCount = int(viewCount)
	}

	if isFile, ok := data["is_file"].(bool); ok {
		secret.IsFile = isFile
	}

	if encData, ok := data["data"].(string); ok {
		secret.Data, err = utils.B64D(encData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode data: %w", err)
		}
	}

	if nonce, ok := data["nonce"].(string); ok {
		secret.Nonce, err = utils.B64D(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decode nonce: %w", err)
		}
	}

	if salt, ok := data["salt"].(string); ok {
		secret.Salt, err = utils.B64D(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode salt: %w", err)
		}
	}

	if header, ok := data["header"].(string); ok {
		secret.Header, err = utils.B64D(header)
		if err != nil {
			return nil, fmt.Errorf("failed to decode header: %w", err)
		}
	}

	return secret, nil
}

func (f *testFirestoreStore) DeleteSecret(secretId string) error {
	ctx := context.Background()

	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(secretId).Delete(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return fmt.Errorf("failed to delete secret from Firestore: %w", err)
	}

	return nil
}

func (f *testFirestoreStore) UpdateSecret(s *simple_crypt.Secret) error {
	ctx := context.Background()

	_, err := f.client.Collection(utils.FirestoreDatabase).Doc(s.SecretId).Update(ctx, []firestore.Update{
		{
			Path:  "view_count",
			Value: s.ViewCount,
		},
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return fmt.Errorf("secret not found")
		}
		return fmt.Errorf("failed to update view count for secret: %w", err)
	}

	return nil
}

func TestFirestoreStore_StoreSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *simple_crypt.Secret
		setErr  error
		wantErr bool
	}{
		{
			name: "successful store",
			secret: &simple_crypt.Secret{
				SecretId:  "test-id",
				ViewCount: 1,
				Data:      []byte("test data"),
				IsFile:    false,
				Nonce:     []byte("test nonce"),
				Salt:      []byte("test salt"),
				Header:    []byte("test header"),
				TTL:       3600,
			},
			wantErr: false,
		},
		{
			name: "store error",
			secret: &simple_crypt.Secret{
				SecretId: "test-id",
			},
			setErr:  errors.New("failed to store"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collection := &mockCollectionRef{
				docs: make(map[string]*mockDocumentRef),
			}
			doc := &mockDocumentRef{
				data:   make(map[string]interface{}),
				setErr: tt.setErr,
			}
			collection.docs[tt.secret.SecretId] = doc

			store := &testFirestoreStore{
				client: &mockFirestoreClient{
					collection: collection,
				},
			}

			err := store.StoreSecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("StoreSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify stored data
				if doc.data["view_count"] != tt.secret.ViewCount {
					t.Errorf("StoreSecret() view_count = %v, want %v", doc.data["view_count"], tt.secret.ViewCount)
				}
				if doc.data["data"] != utils.B64E(tt.secret.Data) {
					t.Errorf("StoreSecret() data = %v, want %v", doc.data["data"], utils.B64E(tt.secret.Data))
				}
				if doc.data["is_file"] != tt.secret.IsFile {
					t.Errorf("StoreSecret() is_file = %v, want %v", doc.data["is_file"], tt.secret.IsFile)
				}
			}
		})
	}
}

func TestFirestoreStore_GetSecret(t *testing.T) {
	tests := []struct {
		name     string
		secretId string
		mockData map[string]interface{}
		exists   bool
		getErr   error
		wantErr  bool
	}{
		{
			name:     "successful get",
			secretId: "test-id",
			mockData: map[string]interface{}{
				"view_count": int64(1),
				"data":       utils.B64E([]byte("test data")),
				"is_file":    false,
				"nonce":      utils.B64E([]byte("test nonce")),
				"salt":       utils.B64E([]byte("test salt")),
				"header":     utils.B64E([]byte("test header")),
				"ttl":        3600,
			},
			exists:  true,
			wantErr: false,
		},
		{
			name:     "not found",
			secretId: "non-existent",
			exists:   false,
			wantErr:  true,
		},
		{
			name:     "get error",
			secretId: "test-id",
			getErr:   errors.New("failed to get"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collection := &mockCollectionRef{
				docs: make(map[string]*mockDocumentRef),
			}
			doc := &mockDocumentRef{
				data:   tt.mockData,
				exists: tt.exists,
				getErr: tt.getErr,
			}
			collection.docs[tt.secretId] = doc

			store := &testFirestoreStore{
				client: &mockFirestoreClient{
					collection: collection,
				},
			}

			got, err := store.GetSecret(tt.secretId)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if got.SecretId != tt.secretId {
					t.Errorf("GetSecret() SecretId = %v, want %v", got.SecretId, tt.secretId)
				}
				if got.ViewCount != int(tt.mockData["view_count"].(int64)) {
					t.Errorf("GetSecret() ViewCount = %v, want %v", got.ViewCount, tt.mockData["view_count"])
				}
				if string(got.Data) != "test data" {
					t.Errorf("GetSecret() Data = %v, want %v", string(got.Data), "test data")
				}
			}
		})
	}
}

func TestFirestoreStore_DeleteSecret(t *testing.T) {
	tests := []struct {
		name     string
		secretId string
		exists   bool
		delErr   error
		wantErr  bool
	}{
		{
			name:     "successful delete",
			secretId: "test-id",
			exists:   true,
			wantErr:  false,
		},
		{
			name:     "not found",
			secretId: "non-existent",
			exists:   false,
			wantErr:  false,
		},
		{
			name:     "delete error",
			secretId: "test-id",
			exists:   true,
			delErr:   errors.New("failed to delete"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collection := &mockCollectionRef{
				docs: make(map[string]*mockDocumentRef),
			}
			doc := &mockDocumentRef{
				exists: tt.exists,
				delErr: tt.delErr,
			}
			collection.docs[tt.secretId] = doc

			store := &testFirestoreStore{
				client: &mockFirestoreClient{
					collection: collection,
				},
			}

			err := store.DeleteSecret(tt.secretId)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.exists {
				if doc.exists {
					t.Error("DeleteSecret() document still exists after deletion")
				}
			}
		})
	}
}

func TestFirestoreStore_UpdateSecret(t *testing.T) {
	tests := []struct {
		name      string
		secret    *simple_crypt.Secret
		exists    bool
		updateErr error
		wantErr   bool
	}{
		{
			name: "successful update",
			secret: &simple_crypt.Secret{
				SecretId:  "test-id",
				ViewCount: 0,
			},
			exists:  true,
			wantErr: false,
		},
		{
			name: "not found",
			secret: &simple_crypt.Secret{
				SecretId:  "non-existent",
				ViewCount: 0,
			},
			exists:  false,
			wantErr: true,
		},
		{
			name: "update error",
			secret: &simple_crypt.Secret{
				SecretId:  "test-id",
				ViewCount: 0,
			},
			exists:    true,
			updateErr: errors.New("failed to update"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collection := &mockCollectionRef{
				docs: make(map[string]*mockDocumentRef),
			}
			doc := &mockDocumentRef{
				data:      make(map[string]interface{}),
				exists:    tt.exists,
				updateErr: tt.updateErr,
			}
			collection.docs[tt.secret.SecretId] = doc

			store := &testFirestoreStore{
				client: &mockFirestoreClient{
					collection: collection,
				},
			}

			err := store.UpdateSecret(tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("UpdateSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.exists {
				if doc.data["view_count"] != tt.secret.ViewCount {
					t.Errorf("UpdateSecret() view_count = %v, want %v", doc.data["view_count"], tt.secret.ViewCount)
				}
			}
		})
	}
}
