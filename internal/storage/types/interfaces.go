package types

type SecretStore interface {
	StoreSecretRaw(secretId string, data []byte, ttl *int64, viewCount *int) error
	GetSecretRaw(secretId string) ([]byte, error)
	UpdateSecretRaw(secretId string, data []byte) error
	DeleteSecret(secretId string) error
}

type FileStore interface {
	StoreEncryptedFile(secret_id string, data []byte) error
	GetEncryptedFile(secret_id string) ([]byte, error)
	DeleteEncryptedFile(secret_id string) error
	DeleteFile(secret_id string) error
}
