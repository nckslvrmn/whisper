package types

import "github.com/nckslvrmn/go_ots/pkg/simple_crypt"

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
