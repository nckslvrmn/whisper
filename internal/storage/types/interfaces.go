package types

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by every provider when a secret or file does not
// exist, or when a secret's views are already exhausted.
var ErrNotFound = errors.New("secret not found")

// UnlimitedViews is the remaining count ConsumeView reports for secrets with
// no view limit.
const UnlimitedViews = -1

type SecretStore interface {
	StoreSecret(ctx context.Context, id string, payload []byte, ttl *int64, viewCount *int) error
	GetSecret(ctx context.Context, id string) (payload []byte, ttl *int64, err error)
	// ConsumeView atomically decrements the view counter. It returns the
	// remaining count, UnlimitedViews for secrets with no limit, or
	// ErrNotFound if the secret is missing or exhausted. When the count
	// reaches 0 the store deletes the secret record itself. File deletion
	// stays with the caller.
	ConsumeView(ctx context.Context, id string) (remaining int, err error)
	DeleteSecret(ctx context.Context, id string) error
}

type FileStore interface {
	StoreEncryptedFile(ctx context.Context, id string, r io.Reader) error
	GetEncryptedFile(ctx context.Context, id string) (io.ReadCloser, error)
	DeleteEncryptedFile(ctx context.Context, id string) error
}
