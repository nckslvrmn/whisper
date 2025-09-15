package types

// SecretStore defines the interface for storing and retrieving secrets
type SecretStore interface {
	// Raw methods for E2E encryption
	StoreSecretRaw(secretId string, data []byte, ttl int64, viewCount int) error
	GetSecretRaw(secretId string) ([]byte, error)
	UpdateSecretRaw(secretId string, data []byte) error
	DeleteSecret(secretId string) error
}

// FileStore defines the interface for storing and retrieving encrypted files
type FileStore interface {
	StoreEncryptedFile(secret_id string, data []byte) error
	GetEncryptedFile(secret_id string) ([]byte, error)
	DeleteEncryptedFile(secret_id string) error
	DeleteFile(secret_id string) error
}
