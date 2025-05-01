package mock

import (
	"fmt"

	"github.com/nckslvrmn/go_ots/pkg/simple_crypt"
)

// MockSecretStore implements the SecretStore interface for testing
type MockSecretStore struct {
	secrets map[string]*simple_crypt.Secret
}

func NewMockSecretStore() *MockSecretStore {
	return &MockSecretStore{
		secrets: make(map[string]*simple_crypt.Secret),
	}
}

func (m *MockSecretStore) StoreSecret(s *simple_crypt.Secret) error {
	if s == nil {
		return fmt.Errorf("secret cannot be nil")
	}
	m.secrets[s.SecretId] = s
	return nil
}

func (m *MockSecretStore) GetSecret(secretId string) (*simple_crypt.Secret, error) {
	if secret, ok := m.secrets[secretId]; ok {
		return secret, nil
	}
	return nil, fmt.Errorf("secret not found")
}

func (m *MockSecretStore) DeleteSecret(secretId string) error {
	delete(m.secrets, secretId)
	return nil
}

func (m *MockSecretStore) UpdateSecret(s *simple_crypt.Secret) error {
	if s == nil {
		return fmt.Errorf("secret cannot be nil")
	}
	if _, ok := m.secrets[s.SecretId]; !ok {
		return fmt.Errorf("secret not found")
	}
	m.secrets[s.SecretId] = s
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
