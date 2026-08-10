package local_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
	"github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

func newTestFileStore(t *testing.T) (types.FileStore, string) {
	t.Helper()
	dir := t.TempDir()
	return local.NewLocalFileStore(dir), dir
}

func storeBytes(t *testing.T, store types.FileStore, id string, data []byte) error {
	t.Helper()
	return store.StoreEncryptedFile(context.Background(), id, bytes.NewReader(data))
}

func readFile(t *testing.T, store types.FileStore, id string) ([]byte, error) {
	t.Helper()
	rc, err := store.GetEncryptedFile(context.Background(), id)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// --- StoreEncryptedFile / GetEncryptedFile ---

func TestFileStore_StoreAndGet(t *testing.T) {
	store, _ := newTestFileStore(t)

	data := []byte{0, 1, 127, 128, 255, 42, 7}
	if err := storeBytes(t, store, "abcdefghijklmnop", data); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}

	got, err := readFile(t, store, "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %v, want %v", got, data)
	}
}

func TestFileStore_StoresRawBytes(t *testing.T) {
	store, dir := newTestFileStore(t)

	data := []byte{0xFF, 0x00, 0xAB, 0xCD}
	if err := storeBytes(t, store, "rawbytes12345678", data); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, "files", "rawbytes12345678"))
	if err != nil {
		t.Fatalf("read on-disk file: %v", err)
	}
	if !bytes.Equal(onDisk, data) {
		t.Errorf("on-disk bytes = %v, want raw ciphertext %v", onDisk, data)
	}
}

// Files written before the raw-bytes switch hold URL-safe base64 text.
func TestFileStore_LegacyBase64File(t *testing.T) {
	store, dir := newTestFileStore(t)

	want := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0xFE}, 300)
	path := filepath.Join(dir, "files", "legacyfile123456")
	if err := os.WriteFile(path, []byte(utils.B64E(want)), 0644); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	got, err := readFile(t, store, "legacyfile123456")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("legacy file did not decode to original ciphertext")
	}
}

func TestFileStore_Get_NotFound(t *testing.T) {
	store, _ := newTestFileStore(t)

	_, err := readFile(t, store, "doesnotexist1234")
	if !errors.Is(err, types.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestFileStore_StoreOverwrites(t *testing.T) {
	store, _ := newTestFileStore(t)

	storeBytes(t, store, "overwrite1234567", bytes.Repeat([]byte{0xEE}, 100))
	storeBytes(t, store, "overwrite1234567", []byte{0xEE, 0xEE})

	got, err := readFile(t, store, "overwrite1234567")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("len = %d, want 2 (previous content must be truncated)", len(got))
	}
}

// --- DeleteEncryptedFile ---

func TestFileStore_DeleteEncryptedFile(t *testing.T) {
	store, _ := newTestFileStore(t)
	storeBytes(t, store, "deletable1234567", []byte{0xAA, 0xBB})

	if err := store.DeleteEncryptedFile(context.Background(), "deletable1234567"); err != nil {
		t.Fatalf("DeleteEncryptedFile: %v", err)
	}

	if _, err := readFile(t, store, "deletable1234567"); !errors.Is(err, types.ErrNotFound) {
		t.Fatal("file should not exist after deletion")
	}
}

func TestFileStore_DeleteEncryptedFile_NonExistent_NoError(t *testing.T) {
	store, _ := newTestFileStore(t)

	if err := store.DeleteEncryptedFile(context.Background(), "nonexistent12345"); err != nil {
		t.Errorf("unexpected error deleting non-existent file: %v", err)
	}
}

// --- Path traversal protection ---

func TestFileStore_PathTraversal_Rejected(t *testing.T) {
	store, _ := newTestFileStore(t)
	ctx := context.Background()

	for _, id := range []string{"../evil", "a/b", "a\\b", ""} {
		if err := storeBytes(t, store, id, []byte{1}); err == nil {
			t.Errorf("StoreEncryptedFile(%q) should be rejected", id)
		}
		if _, err := store.GetEncryptedFile(ctx, id); err == nil {
			t.Errorf("GetEncryptedFile(%q) should be rejected", id)
		}
		if err := store.DeleteEncryptedFile(ctx, id); err == nil {
			t.Errorf("DeleteEncryptedFile(%q) should be rejected", id)
		}
	}
}

// --- Isolation ---

func TestFileStore_MultipleFilesIsolated(t *testing.T) {
	store, _ := newTestFileStore(t)

	storeBytes(t, store, "file111111111111", []byte{0xF0, 0x01})
	storeBytes(t, store, "file222222222222", []byte{0xF0, 0x02})

	a, _ := readFile(t, store, "file111111111111")
	b, _ := readFile(t, store, "file222222222222")

	if !bytes.Equal(a, []byte{0xF0, 0x01}) || !bytes.Equal(b, []byte{0xF0, 0x02}) {
		t.Errorf("files are not isolated: %v / %v", a, b)
	}
}

func TestNewLocalFileStore_CreatesFilesSubdir(t *testing.T) {
	_, dir := newTestFileStore(t)

	if _, err := os.Stat(filepath.Join(dir, "files")); os.IsNotExist(err) {
		t.Error("NewLocalFileStore should create 'files' subdirectory")
	}
}
