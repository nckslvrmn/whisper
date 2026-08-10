package local_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
	"github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

func newTestStore(t *testing.T) (types.SecretStore, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := local.NewSQLiteStore(dir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() {
		if closer, ok := store.(interface{ Close() error }); ok {
			closer.Close()
		}
	})
	return store, dir
}

func ptrInt(n int) *int { return &n }

// --- NewSQLiteStore ---

func TestNewSQLiteStore_CreatesDB(t *testing.T) {
	_, dir := newTestStore(t)

	if _, err := os.Stat(filepath.Join(dir, "secrets.db")); os.IsNotExist(err) {
		t.Error("secrets.db was not created")
	}
}

func TestNewSQLiteStore_CreatesDataDir(t *testing.T) {
	newDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")

	store, err := local.NewSQLiteStore(newDir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.(interface{ Close() error }).Close()

	if _, err := os.Stat(newDir); os.IsNotExist(err) {
		t.Error("data directory was not created")
	}
}

// --- StoreSecret / GetSecret ---

func TestStoreAndGetSecret(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	data := []byte(`{"passwordHash":"abc","encryptedData":"xyz"}`)
	if err := store.StoreSecret(ctx, "abcdefghijklmnop", data, nil, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	got, ttl, err := store.GetSecret(ctx, "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
	if ttl != nil {
		t.Errorf("ttl = %v, want nil", *ttl)
	}
}

func TestGetSecret_ReturnsTTL(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	want := time.Now().Add(24 * time.Hour).Unix()
	if err := store.StoreSecret(ctx, "ttlsecret1234567", []byte(`{"a":1}`), &want, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	_, ttl, err := store.GetSecret(ctx, "ttlsecret1234567")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if ttl == nil || *ttl != want {
		t.Errorf("ttl = %v, want %d", ttl, want)
	}
}

func TestGetSecret_NotFound(t *testing.T) {
	store, _ := newTestStore(t)

	_, _, err := store.GetSecret(context.Background(), "doesnotexist1234")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestStoreSecret_PayloadStoredAsRawJSON(t *testing.T) {
	store, dir := newTestStore(t)
	ctx := context.Background()

	payload := []byte(`{"passwordHash":"abc"}`)
	if err := store.StoreSecret(ctx, "rawjson123456789", payload, nil, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	var stored string
	queryColumn(t, dir, `SELECT data FROM secrets WHERE secret_id = ?`, "rawjson123456789", &stored)
	if stored != string(payload) {
		t.Errorf("stored value = %q, want raw JSON %q", stored, payload)
	}
}

func TestStoreSecret_UnlimitedViewCountStoredAsNull(t *testing.T) {
	store, dir := newTestStore(t)

	if err := store.StoreSecret(context.Background(), "unlimited1234567", []byte(`{}`), nil, ptrInt(0)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	var viewCount sql.NullInt64
	queryColumn(t, dir, `SELECT view_count FROM secrets WHERE secret_id = ?`, "unlimited1234567", &viewCount)
	if viewCount.Valid {
		t.Errorf("view_count = %d, want NULL", viewCount.Int64)
	}
}

// --- ConsumeView ---

func TestConsumeView_DecrementsAndDeletesAtZero(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	if err := store.StoreSecret(ctx, "consume123456789", []byte(`{}`), nil, ptrInt(2)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	remaining, err := store.ConsumeView(ctx, "consume123456789")
	if err != nil || remaining != 1 {
		t.Fatalf("first consume: remaining = %d, err = %v", remaining, err)
	}

	remaining, err = store.ConsumeView(ctx, "consume123456789")
	if err != nil || remaining != 0 {
		t.Fatalf("second consume: remaining = %d, err = %v", remaining, err)
	}

	if _, _, err := store.GetSecret(ctx, "consume123456789"); !errors.Is(err, types.ErrNotFound) {
		t.Errorf("secret should be deleted at zero, got err = %v", err)
	}

	if _, err := store.ConsumeView(ctx, "consume123456789"); !errors.Is(err, types.ErrNotFound) {
		t.Errorf("exhausted consume: err = %v, want ErrNotFound", err)
	}
}

func TestConsumeView_Unlimited(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	if err := store.StoreSecret(ctx, "nolimit123456789", []byte(`{}`), nil, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	for i := 0; i < 3; i++ {
		remaining, err := store.ConsumeView(ctx, "nolimit123456789")
		if err != nil {
			t.Fatalf("consume %d: %v", i, err)
		}
		if remaining != types.UnlimitedViews {
			t.Errorf("remaining = %d, want UnlimitedViews", remaining)
		}
	}

	if _, _, err := store.GetSecret(ctx, "nolimit123456789"); err != nil {
		t.Errorf("unlimited secret should survive: %v", err)
	}
}

func TestConsumeView_Missing(t *testing.T) {
	store, _ := newTestStore(t)

	if _, err := store.ConsumeView(context.Background(), "missing123456789"); !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// A legacy row can carry a literal 0, which has always meant unlimited.
func TestConsumeView_LegacyZeroMeansUnlimited(t *testing.T) {
	store, dir := newTestStore(t)
	ctx := context.Background()

	seedLegacyRow(t, dir, "legacyzero123456", utils.B64E([]byte(`{"passwordHash":"abc"}`)), sql.NullInt64{Int64: 0, Valid: true}, sql.NullInt64{})

	remaining, err := store.ConsumeView(ctx, "legacyzero123456")
	if err != nil {
		t.Fatalf("ConsumeView: %v", err)
	}
	if remaining != types.UnlimitedViews {
		t.Errorf("remaining = %d, want UnlimitedViews", remaining)
	}
}

// Rows written before the raw-JSON switch hold base64 text.
func TestGetSecret_LegacyBase64Payload(t *testing.T) {
	store, dir := newTestStore(t)

	payload := []byte(`{"passwordHash":"abc","viewCount":3,"ttl":123}`)
	ttl := time.Now().Add(time.Hour).Unix()
	seedLegacyRow(t, dir, "legacyblob123456", utils.B64E(payload), sql.NullInt64{Int64: 3, Valid: true}, sql.NullInt64{Int64: ttl, Valid: true})

	got, gotTTL, err := store.GetSecret(context.Background(), "legacyblob123456")
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

func TestConsumeView_ConcurrentSingleView(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	if err := store.StoreSecret(ctx, "raceyrace1234567", []byte(`{}`), nil, ptrInt(1)); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, notFound int

	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			remaining, err := store.ConsumeView(ctx, "raceyrace1234567")

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && remaining == 0:
				successes++
			case errors.Is(err, types.ErrNotFound):
				notFound++
			default:
				t.Errorf("unexpected result: remaining = %d, err = %v", remaining, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1", successes)
	}
	if notFound != goroutines-1 {
		t.Errorf("notFound = %d, want %d", notFound, goroutines-1)
	}
}

// --- DeleteSecret ---

func TestDeleteSecret_Success(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	if err := store.StoreSecret(ctx, "deletesecret1234", []byte(`{}`), nil, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	if err := store.DeleteSecret(ctx, "deletesecret1234"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}

	if _, _, err := store.GetSecret(ctx, "deletesecret1234"); !errors.Is(err, types.ErrNotFound) {
		t.Fatal("secret should not exist after deletion")
	}
}

func TestDeleteSecret_NonExistent_NoError(t *testing.T) {
	store, _ := newTestStore(t)

	if err := store.DeleteSecret(context.Background(), "nonexistent12345"); err != nil {
		t.Errorf("unexpected error deleting non-existent secret: %v", err)
	}
}

func TestMultipleSecretsIsolated(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	a := []byte(`{"id":"a"}`)
	b := []byte(`{"id":"b"}`)
	store.StoreSecret(ctx, "aaaaaaaaaaaaaaa1", a, nil, nil)
	store.StoreSecret(ctx, "bbbbbbbbbbbbbbb1", b, nil, nil)

	gotA, _, _ := store.GetSecret(ctx, "aaaaaaaaaaaaaaa1")
	gotB, _, _ := store.GetSecret(ctx, "bbbbbbbbbbbbbbb1")

	if string(gotA) != string(a) || string(gotB) != string(b) {
		t.Errorf("secrets are not isolated: %q / %q", gotA, gotB)
	}
}

// --- Close ---

func TestClose_StopsJanitorAndDB(t *testing.T) {
	dir := t.TempDir()
	store, err := local.NewSQLiteStore(dir, nil)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	if err := store.(interface{ Close() error }).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := store.StoreSecret(context.Background(), "afterclose123456", []byte(`{}`), nil, nil); err == nil {
		t.Error("store should fail after Close")
	}
}

// --- helpers ---

func openTestDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "secrets.db"))
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func queryColumn(t *testing.T, dir, query, secretId string, dest any) {
	t.Helper()
	if err := openTestDB(t, dir).QueryRow(query, secretId).Scan(dest); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
}

func seedLegacyRow(t *testing.T, dir, secretId, data string, viewCount, ttl sql.NullInt64) {
	t.Helper()
	db := openTestDB(t, dir)
	_, err := db.Exec(
		`INSERT INTO secrets (secret_id, data, view_count, ttl, created_at) VALUES (?, ?, ?, ?, ?)`,
		secretId, data, viewCount, ttl, time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
}
