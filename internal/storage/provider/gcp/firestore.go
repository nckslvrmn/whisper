package gcp

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/firestore"
	"github.com/nckslvrmn/whisper/internal/config"
	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// docStore exists so the ConsumeView transaction can be tested without a
// Firestore emulator.
type docStore interface {
	Get(ctx context.Context, id string) (map[string]any, error)
	Set(ctx context.Context, id string, data map[string]any) error
	Delete(ctx context.Context, id string) error
	RunTransaction(ctx context.Context, f func(ctx context.Context, tx docTx) error) error
}

type docTx interface {
	Get(id string) (map[string]any, error)
	Set(id string, data map[string]any) error
	Delete(id string) error
}

type FirestoreStore struct {
	client *firestore.Client
	docs   docStore
}

func NewFirestoreStore() (storagetypes.SecretStore, error) {
	ctx := context.Background()
	client, err := firestore.NewClientWithDatabase(ctx, config.GCPProjectID, config.FirestoreDatabase)
	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client: %w", err)
	}

	return &FirestoreStore{
		client: client,
		docs:   &firestoreDocs{client: client},
	}, nil
}

func (f *FirestoreStore) StoreSecret(ctx context.Context, id string, payload []byte, ttl *int64, viewCount *int) error {
	data := map[string]any{
		"data": string(payload),
	}

	if viewCount != nil && *viewCount > 0 {
		data["view_count"] = int64(*viewCount)
	}

	if ttl != nil {
		data["ttl"] = *ttl
	}

	if err := f.docs.Set(ctx, id, data); err != nil {
		return fmt.Errorf("failed to store secret in Firestore: %w", err)
	}

	return nil
}

func (f *FirestoreStore) GetSecret(ctx context.Context, id string) ([]byte, *int64, error) {
	data, err := f.docs.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	stored, ok := data["data"].(string)
	if !ok {
		return nil, nil, fmt.Errorf("data field not found")
	}

	payload, err := storagetypes.DecodeStoredPayload(stored)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return payload, intField(data, "ttl"), nil
}

func (f *FirestoreStore) ConsumeView(ctx context.Context, id string) (int, error) {
	remaining := storagetypes.UnlimitedViews

	err := f.docs.RunTransaction(ctx, func(ctx context.Context, tx docTx) error {
		data, err := tx.Get(id)
		if err != nil {
			return err
		}

		// An absent counter means unlimited, and so does 0: the last view
		// deletes the doc, so a stored 0 can only be legacy data.
		viewCount := intField(data, "view_count")
		if viewCount == nil || *viewCount == 0 {
			remaining = storagetypes.UnlimitedViews
			return nil
		}

		if *viewCount <= 1 {
			remaining = 0
			return tx.Delete(id)
		}

		next := *viewCount - 1
		if int64(int(next)) != next {
			return fmt.Errorf("view_count %d is out of range", *viewCount)
		}

		remaining = int(next)
		data["view_count"] = next
		return tx.Set(id, data)
	})
	if err != nil {
		if errors.Is(err, storagetypes.ErrNotFound) {
			return 0, storagetypes.ErrNotFound
		}
		return 0, fmt.Errorf("failed to consume view: %w", err)
	}

	return remaining, nil
}

func (f *FirestoreStore) DeleteSecret(ctx context.Context, id string) error {
	if err := f.docs.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete secret from Firestore: %w", err)
	}
	return nil
}

func (f *FirestoreStore) Close() error {
	if f.client == nil {
		return nil
	}
	return f.client.Close()
}

func intField(data map[string]any, name string) *int64 {
	switch v := data[name].(type) {
	case int64:
		return &v
	case int:
		n := int64(v)
		return &n
	case float64:
		n := int64(v)
		return &n
	default:
		return nil
	}
}

// --- Firestore-backed docStore ---

type firestoreDocs struct {
	client *firestore.Client
}

func (d *firestoreDocs) doc(id string) *firestore.DocumentRef {
	return d.client.Collection(config.FirestoreDatabase).Doc(id)
}

func (d *firestoreDocs) Get(ctx context.Context, id string) (map[string]any, error) {
	snapshot, err := d.doc(id).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, storagetypes.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get secret from Firestore: %w", err)
	}
	return snapshot.Data(), nil
}

func (d *firestoreDocs) Set(ctx context.Context, id string, data map[string]any) error {
	_, err := d.doc(id).Set(ctx, data)
	return err
}

func (d *firestoreDocs) Delete(ctx context.Context, id string) error {
	_, err := d.doc(id).Delete(ctx)
	if err != nil && status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

func (d *firestoreDocs) RunTransaction(ctx context.Context, f func(ctx context.Context, tx docTx) error) error {
	return d.client.RunTransaction(ctx, func(ctx context.Context, tx *firestore.Transaction) error {
		return f(ctx, &firestoreTx{docs: d, tx: tx})
	})
}

type firestoreTx struct {
	docs *firestoreDocs
	tx   *firestore.Transaction
}

func (t *firestoreTx) Get(id string) (map[string]any, error) {
	snapshot, err := t.tx.Get(t.docs.doc(id))
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, storagetypes.ErrNotFound
		}
		return nil, err
	}
	return snapshot.Data(), nil
}

func (t *firestoreTx) Set(id string, data map[string]any) error {
	return t.tx.Set(t.docs.doc(id), data)
}

func (t *firestoreTx) Delete(id string) error {
	return t.tx.Delete(t.docs.doc(id))
}
