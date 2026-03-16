package local_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
)

// newTestStore creates a SQLiteStore backed by a temp directory.
// The returned cleanup func removes the temp dir.
func newTestStore(t *testing.T) (interface {
	StoreSecretRaw(string, []byte, *int64, *int) error
	GetSecretRaw(string) ([]byte, error)
	UpdateSecretRaw(string, []byte) error
	DeleteSecret(string) error
}, func()) {
	t.Helper()
	dir := t.TempDir()
	store, err := local.NewSQLiteStore(dir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store, func() { os.RemoveAll(dir) }
}

// --- NewSQLiteStore ---

func TestNewSQLiteStore_CreatesDB(t *testing.T) {
	dir := t.TempDir()
	_, err := local.NewSQLiteStore(dir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	dbPath := filepath.Join(dir, "secrets.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("secrets.db was not created")
	}
}

func TestNewSQLiteStore_CreatesDataDir(t *testing.T) {
	base := t.TempDir()
	newDir := filepath.Join(base, "nonexistent", "subdir")

	_, err := local.NewSQLiteStore(newDir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		t.Error("data directory was not created")
	}
}

// --- StoreSecretRaw / GetSecretRaw ---

func TestStoreAndGetSecret(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	data := []byte(`{"passwordHash":"abc","encryptedData":"xyz"}`)
	if err := store.StoreSecretRaw("abcdefghijklmnop", data, nil, nil); err != nil {
		t.Fatalf("StoreSecretRaw: %v", err)
	}

	got, err := store.GetSecretRaw("abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetSecretRaw: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestStoreSecretRaw_WithTTL(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ttl := time.Now().Add(24 * time.Hour).Unix()
	data := []byte(`{"test":"ttl"}`)

	if err := store.StoreSecretRaw("ttlsecret1234567", data, &ttl, nil); err != nil {
		t.Fatalf("StoreSecretRaw with TTL: %v", err)
	}

	got, err := store.GetSecretRaw("ttlsecret1234567")
	if err != nil {
		t.Fatalf("GetSecretRaw: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestStoreSecretRaw_WithViewCount(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	vc := 5
	data := []byte(`{"test":"vc"}`)

	if err := store.StoreSecretRaw("vcsecret12345678", data, nil, &vc); err != nil {
		t.Fatalf("StoreSecretRaw with viewCount: %v", err)
	}

	got, err := store.GetSecretRaw("vcsecret12345678")
	if err != nil {
		t.Fatalf("GetSecretRaw: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestGetSecretRaw_NotFound(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	_, err := store.GetSecretRaw("doesnotexist1234")
	if err == nil {
		t.Fatal("expected error for non-existent secret")
	}
}

func TestStoreSecretRaw_DataIsBase64Encoded(t *testing.T) {
	// The SQLite store base64-encodes data before storing.
	// Round-tripping should give back exactly the original bytes.
	store, cleanup := newTestStore(t)
	defer cleanup()

	original := []byte{0, 1, 2, 3, 255, 254, 253}
	if err := store.StoreSecretRaw("binarydata123456", original, nil, nil); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := store.GetSecretRaw("binarydata123456")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("binary round-trip failed: got %v, want %v", got, original)
	}
}

func TestStoreSecretRaw_JSONRoundTrip(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	payload := map[string]any{
		"passwordHash":  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"encryptedData": "dGVzdA==",
		"nonce":         "bm9uY2U=",
		"header":        "aGVhZGVy",
		"isFile":        false,
		"viewCount":     float64(3),
	}
	data, _ := json.Marshal(payload)

	if err := store.StoreSecretRaw("jsonround12345678", data, nil, nil); err != nil {
		t.Fatalf("store: %v", err)
	}

	got, err := store.GetSecretRaw("jsonround12345678")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(got, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result["passwordHash"] != payload["passwordHash"] {
		t.Errorf("passwordHash mismatch")
	}
}

// --- UpdateSecretRaw ---

func TestUpdateSecretRaw_Success(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	original := []byte(`{"v":1}`)
	updated := []byte(`{"v":2}`)

	store.StoreSecretRaw("updatesecret1234", original, nil, nil)

	if err := store.UpdateSecretRaw("updatesecret1234", updated); err != nil {
		t.Fatalf("UpdateSecretRaw: %v", err)
	}

	got, _ := store.GetSecretRaw("updatesecret1234")
	if string(got) != string(updated) {
		t.Errorf("got %q, want %q", got, updated)
	}
}

func TestUpdateSecretRaw_NotFound(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	err := store.UpdateSecretRaw("nonexistent12345", []byte(`{}`))
	if err == nil {
		t.Fatal("expected error updating non-existent secret")
	}
}

// --- DeleteSecret ---

func TestDeleteSecret_Success(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	data := []byte(`{"test":"delete"}`)
	store.StoreSecretRaw("deletesecret1234", data, nil, nil)

	if err := store.DeleteSecret("deletesecret1234"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	_, err := store.GetSecretRaw("deletesecret1234")
	if err == nil {
		t.Fatal("secret should not exist after deletion")
	}
}

func TestDeleteSecret_NonExistent_NoError(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// Deleting a non-existent secret should not return an error
	if err := store.DeleteSecret("nonexistent12345"); err != nil {
		t.Errorf("unexpected error deleting non-existent secret: %v", err)
	}
}

// --- Isolation: multiple secrets ---

func TestMultipleSecretsIsolated(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	a := []byte(`{"id":"a"}`)
	b := []byte(`{"id":"b"}`)

	store.StoreSecretRaw("aaaaaaaaaaaaaaa1", a, nil, nil)
	store.StoreSecretRaw("bbbbbbbbbbbbbbb1", b, nil, nil)

	gotA, _ := store.GetSecretRaw("aaaaaaaaaaaaaaa1")
	gotB, _ := store.GetSecretRaw("bbbbbbbbbbbbbbb1")

	if string(gotA) != string(a) {
		t.Errorf("secret A mismatch")
	}
	if string(gotB) != string(b) {
		t.Errorf("secret B mismatch")
	}
}
