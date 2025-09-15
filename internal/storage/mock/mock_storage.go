package mock

import (
	"fmt"
	"time"
)

// MockSecretStore implements the SecretStore interface for testing
type MockSecretStore struct {
	secrets map[string][]byte
	metadata map[string]struct{
		TTL int64
		ViewCount int
	}
}

func NewMockSecretStore() *MockSecretStore {
	return &MockSecretStore{
		secrets: make(map[string][]byte),
		metadata: make(map[string]struct{
			TTL int64
			ViewCount int
		}),
	}
}

func (m *MockSecretStore) StoreSecretRaw(secretId string, data []byte, ttl int64, viewCount int) error {
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}
	m.secrets[secretId] = data
	m.metadata[secretId] = struct{
		TTL int64
		ViewCount int
	}{
		TTL: ttl,
		ViewCount: viewCount,
	}
	return nil
}

func (m *MockSecretStore) GetSecretRaw(secretId string) ([]byte, error) {
	// Check if secret exists
	if data, ok := m.secrets[secretId]; ok {
		// Check TTL
		if meta, ok := m.metadata[secretId]; ok {
			if meta.TTL > 0 && meta.TTL < time.Now().Unix() {
				delete(m.secrets, secretId)
				delete(m.metadata, secretId)
				return nil, fmt.Errorf("secret expired")
			}
		}
		return data, nil
	}
	return nil, fmt.Errorf("secret not found")
}

func (m *MockSecretStore) UpdateSecretRaw(secretId string, data []byte) error {
	if _, ok := m.secrets[secretId]; !ok {
		return fmt.Errorf("secret not found")
	}
	m.secrets[secretId] = data
	return nil
}

func (m *MockSecretStore) DeleteSecret(secretId string) error {
	delete(m.secrets, secretId)
	delete(m.metadata, secretId)
	return nil
}

// MockFileStore implements the FileStore interface for testing
type MockFileStore struct {
	files map[string][]byte
}

func NewMockFileStore() *MockFileStore {
	return &MockFileStore{
		files: make(map[string][]byte),
	}
}

func (m *MockFileStore) StoreEncryptedFile(secret_id string, data []byte) error {
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}
	m.files[secret_id] = data
	return nil
}

func (m *MockFileStore) GetEncryptedFile(secret_id string) ([]byte, error) {
	if data, ok := m.files[secret_id]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("file not found")
}

func (m *MockFileStore) DeleteEncryptedFile(secret_id string) error {
	delete(m.files, secret_id)
	return nil
}

func (m *MockFileStore) DeleteFile(secret_id string) error {
	return m.DeleteEncryptedFile(secret_id)
}