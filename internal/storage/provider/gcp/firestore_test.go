package gcp

import (
	"context"
	"errors"
	"maps"
	"math"
	"testing"

	storagetypes "github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

// fakeDocs applies transaction mutations immediately, which is enough to cover
// the ConsumeView decision tree.
type fakeDocs struct {
	docs map[string]map[string]any
}

func (f *fakeDocs) Get(ctx context.Context, id string) (map[string]any, error) {
	doc, ok := f.docs[id]
	if !ok {
		return nil, storagetypes.ErrNotFound
	}
	return maps.Clone(doc), nil
}

func (f *fakeDocs) Set(ctx context.Context, id string, data map[string]any) error {
	f.docs[id] = maps.Clone(data)
	return nil
}

func (f *fakeDocs) Delete(ctx context.Context, id string) error {
	delete(f.docs, id)
	return nil
}

func (f *fakeDocs) RunTransaction(ctx context.Context, fn func(ctx context.Context, tx docTx) error) error {
	return fn(ctx, &fakeTx{docs: f})
}

type fakeTx struct {
	docs *fakeDocs
}

func (t *fakeTx) Get(id string) (map[string]any, error) {
	return t.docs.Get(context.Background(), id)
}

func (t *fakeTx) Set(id string, data map[string]any) error {
	return t.docs.Set(context.Background(), id, data)
}

func (t *fakeTx) Delete(id string) error {
	return t.docs.Delete(context.Background(), id)
}

func newTestFirestoreStore(t *testing.T) (*FirestoreStore, *fakeDocs) {
	t.Helper()
	fake := &fakeDocs{docs: map[string]map[string]any{}}
	return &FirestoreStore{docs: fake}, fake
}

func ptrInt(n int) *int       { return &n }
func ptrInt64(n int64) *int64 { return &n }

// --- StoreSecret / GetSecret ---

func TestFirestore_StoreAndGetSecret(t *testing.T) {
	store, fake := newTestFirestoreStore(t)
	ctx := context.Background()

	ttl := int64(1893456000)
	payload := []byte(`{"passwordHash":"abc"}`)
	if err := store.StoreSecret(ctx, "abcdefghijklmnop", payload, &ttl, ptrInt(2)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	if stored := fake.docs["abcdefghijklmnop"]["data"]; stored != string(payload) {
		t.Errorf("stored data = %v, want raw JSON %q", stored, payload)
	}

	got, gotTTL, err := store.GetSecret(ctx, "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if gotTTL == nil || *gotTTL != ttl {
		t.Errorf("ttl = %v, want %d", gotTTL, ttl)
	}
}

func TestFirestore_StoreSecret_UnlimitedOmitsViewCount(t *testing.T) {
	store, fake := newTestFirestoreStore(t)

	if err := store.StoreSecret(context.Background(), "unlimited1234567", []byte(`{}`), nil, ptrInt(0)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	if _, ok := fake.docs["unlimited1234567"]["view_count"]; ok {
		t.Error("view_count field must be absent for unlimited secrets")
	}
}

func TestFirestore_GetSecret_NotFound(t *testing.T) {
	store, _ := newTestFirestoreStore(t)

	_, _, err := store.GetSecret(context.Background(), "missing123456789")
	if !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFirestore_GetSecret_LegacyBase64Payload(t *testing.T) {
	store, fake := newTestFirestoreStore(t)

	payload := []byte(`{"passwordHash":"abc","ttl":123}`)
	fake.docs["legacyblob123456"] = map[string]any{
		"data":       utils.B64E(payload),
		"view_count": int64(3),
	}

	got, _, err := store.GetSecret(context.Background(), "legacyblob123456")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

// --- ConsumeView ---

func TestFirestore_ConsumeView_Decrements(t *testing.T) {
	store, fake := newTestFirestoreStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "consume123456789", []byte(`{}`), nil, ptrInt(3))

	remaining, err := store.ConsumeView(ctx, "consume123456789")
	if err != nil || remaining != 2 {
		t.Fatalf("remaining = %d, err = %v", remaining, err)
	}
	if got := fake.docs["consume123456789"]["view_count"]; got != int64(2) {
		t.Errorf("stored view_count = %v, want 2", got)
	}
}

func TestFirestore_ConsumeView_LastViewDeletesDoc(t *testing.T) {
	store, fake := newTestFirestoreStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "lastview12345678", []byte(`{}`), nil, ptrInt(1))

	remaining, err := store.ConsumeView(ctx, "lastview12345678")
	if err != nil || remaining != 0 {
		t.Fatalf("remaining = %d, err = %v", remaining, err)
	}
	if _, ok := fake.docs["lastview12345678"]; ok {
		t.Error("doc should be deleted on the last view")
	}
}

func TestFirestore_ConsumeView_Unlimited(t *testing.T) {
	store, _ := newTestFirestoreStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "nolimit123456789", []byte(`{}`), nil, nil)

	remaining, err := store.ConsumeView(ctx, "nolimit123456789")
	if err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}
	if remaining != storagetypes.UnlimitedViews {
		t.Errorf("remaining = %d, want UnlimitedViews", remaining)
	}
}

func TestFirestore_ConsumeView_LegacyZeroMeansUnlimited(t *testing.T) {
	store, fake := newTestFirestoreStore(t)

	fake.docs["legacyzero123456"] = map[string]any{"data": `{}`, "view_count": int64(0)}

	remaining, err := store.ConsumeView(context.Background(), "legacyzero123456")
	if err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}
	if remaining != storagetypes.UnlimitedViews {
		t.Errorf("remaining = %d, want UnlimitedViews", remaining)
	}
	if _, ok := fake.docs["legacyzero123456"]; !ok {
		t.Error("an unlimited secret must not be deleted")
	}
}

func TestFirestore_ConsumeView_Missing(t *testing.T) {
	store, _ := newTestFirestoreStore(t)

	if _, err := store.ConsumeView(context.Background(), "missing123456789"); !errors.Is(err, storagetypes.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFirestore_ConsumeView_PreservesPayload(t *testing.T) {
	store, fake := newTestFirestoreStore(t)
	ctx := context.Background()

	payload := []byte(`{"passwordHash":"abc"}`)
	store.StoreSecret(ctx, "keeppayload12345", payload, ptrInt64(1893456000), ptrInt(2))

	if _, err := store.ConsumeView(ctx, "keeppayload12345"); err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}

	if got := fake.docs["keeppayload12345"]["data"]; got != string(payload) {
		t.Errorf("data = %v, want %q", got, payload)
	}
	if got := fake.docs["keeppayload12345"]["ttl"]; got != int64(1893456000) {
		t.Errorf("ttl = %v, want it preserved through the decrement", got)
	}
}

func TestFirestore_ConsumeView_OutOfRangeCounterFailsClosed(t *testing.T) {
	store, fake := newTestFirestoreStore(t)

	fake.docs["corrupted1234567"] = map[string]any{"data": `{}`, "view_count": int64(math.MaxInt64)}

	remaining, err := store.ConsumeView(context.Background(), "corrupted1234567")
	if err != nil {
		return
	}
	if remaining != math.MaxInt64-1 {
		t.Errorf("remaining = %d, want an error or an exact decrement, never unlimited", remaining)
	}
}

// --- DeleteSecret ---

func TestFirestore_DeleteSecret(t *testing.T) {
	store, fake := newTestFirestoreStore(t)
	ctx := context.Background()

	store.StoreSecret(ctx, "deleteme12345678", []byte(`{}`), nil, nil)
	if err := store.DeleteSecret(ctx, "deleteme12345678"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, ok := fake.docs["deleteme12345678"]; ok {
		t.Error("doc should be gone after DeleteSecret")
	}
}
