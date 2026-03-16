package local_test

import (
	"os"
	"testing"

	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
)

func newTestFileStore(t *testing.T) (interface {
	StoreEncryptedFile(string, []byte) error
	GetEncryptedFile(string) ([]byte, error)
	DeleteEncryptedFile(string) error
	DeleteFile(string) error
}, string) {
	t.Helper()
	dir := t.TempDir()
	store := local.NewLocalFileStore(dir)
	return store, dir
}

// --- StoreEncryptedFile / GetEncryptedFile ---

func TestFileStore_StoreAndGet(t *testing.T) {
	store, _ := newTestFileStore(t)

	data := []byte("encrypted file content")
	if err := store.StoreEncryptedFile("abcdefghijklmnop", data); err != nil {
		t.Fatalf("StoreEncryptedFile: %v", err)
	}

	got, err := store.GetEncryptedFile("abcdefghijklmnop")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestFileStore_StoreAndGet_BinaryData(t *testing.T) {
	store, _ := newTestFileStore(t)

	data := []byte{0, 1, 127, 128, 255}
	store.StoreEncryptedFile("binaryfile123456", data)

	got, err := store.GetEncryptedFile("binaryfile123456")
	if err != nil {
		t.Fatalf("GetEncryptedFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("binary round-trip failed")
	}
}

func TestFileStore_Get_NotFound(t *testing.T) {
	store, _ := newTestFileStore(t)

	_, err := store.GetEncryptedFile("doesnotexist1234")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// --- DeleteEncryptedFile ---

func TestFileStore_DeleteEncryptedFile(t *testing.T) {
	store, _ := newTestFileStore(t)

	store.StoreEncryptedFile("deletable1234567", []byte("data"))

	if err := store.DeleteEncryptedFile("deletable1234567"); err != nil {
		t.Fatalf("DeleteEncryptedFile: %v", err)
	}

	_, err := store.GetEncryptedFile("deletable1234567")
	if err == nil {
		t.Fatal("file should not exist after deletion")
	}
}

func TestFileStore_DeleteEncryptedFile_NonExistent_NoError(t *testing.T) {
	store, _ := newTestFileStore(t)

	if err := store.DeleteEncryptedFile("nonexistent12345"); err != nil {
		t.Errorf("unexpected error deleting non-existent file: %v", err)
	}
}

// --- DeleteFile (alias) ---

func TestFileStore_DeleteFile_IsAlias(t *testing.T) {
	store, _ := newTestFileStore(t)

	store.StoreEncryptedFile("deletefile123456", []byte("data"))

	if err := store.DeleteFile("deletefile123456"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	_, err := store.GetEncryptedFile("deletefile123456")
	if err == nil {
		t.Fatal("file should not exist after DeleteFile")
	}
}

// --- Path traversal protection ---

func TestFileStore_PathTraversal_DotDot(t *testing.T) {
	store, _ := newTestFileStore(t)

	err := store.StoreEncryptedFile("../evil", []byte("bad"))
	if err == nil {
		t.Error("StoreEncryptedFile should reject '..' in secretId")
	}
}

func TestFileStore_PathTraversal_Slash(t *testing.T) {
	store, _ := newTestFileStore(t)

	err := store.StoreEncryptedFile("a/b", []byte("bad"))
	if err == nil {
		t.Error("StoreEncryptedFile should reject '/' in secretId")
	}
}

func TestFileStore_PathTraversal_Backslash(t *testing.T) {
	store, _ := newTestFileStore(t)

	err := store.StoreEncryptedFile("a\\b", []byte("bad"))
	if err == nil {
		t.Error("StoreEncryptedFile should reject '\\' in secretId")
	}
}

func TestFileStore_EmptySecretID_Rejected(t *testing.T) {
	store, _ := newTestFileStore(t)

	err := store.StoreEncryptedFile("", []byte("data"))
	if err == nil {
		t.Error("StoreEncryptedFile should reject empty secretId")
	}
}

func TestFileStore_Get_PathTraversal_Rejected(t *testing.T) {
	store, _ := newTestFileStore(t)

	_, err := store.GetEncryptedFile("../etc/passwd")
	if err == nil {
		t.Error("GetEncryptedFile should reject path traversal in secretId")
	}
}

func TestFileStore_Delete_PathTraversal_Rejected(t *testing.T) {
	store, _ := newTestFileStore(t)

	err := store.DeleteEncryptedFile("../something")
	if err == nil {
		t.Error("DeleteEncryptedFile should reject path traversal in secretId")
	}
}

// --- Multiple files isolated ---

func TestFileStore_MultipleFilesIsolated(t *testing.T) {
	store, _ := newTestFileStore(t)

	store.StoreEncryptedFile("file1111111111111", []byte("content-a"))
	store.StoreEncryptedFile("file2222222222222", []byte("content-b"))

	a, _ := store.GetEncryptedFile("file1111111111111")
	b, _ := store.GetEncryptedFile("file2222222222222")

	if string(a) != "content-a" {
		t.Errorf("file A: got %q", a)
	}
	if string(b) != "content-b" {
		t.Errorf("file B: got %q", b)
	}
}

// --- NewLocalFileStore creates files subdir ---

func TestNewLocalFileStore_CreatesFilesSubdir(t *testing.T) {
	dir := t.TempDir()
	local.NewLocalFileStore(dir)

	filesDir := dir + "/files"
	if _, err := os.Stat(filesDir); os.IsNotExist(err) {
		t.Error("NewLocalFileStore should create 'files' subdirectory")
	}
}
