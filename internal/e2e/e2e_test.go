package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/config"
	"github.com/nckslvrmn/whisper/internal/handlers"
	"github.com/nckslvrmn/whisper/internal/storage"
	"github.com/nckslvrmn/whisper/internal/storage/provider/local"
	"github.com/nckslvrmn/whisper/internal/storage/types"
	"github.com/nckslvrmn/whisper/pkg/client"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

// newServer runs the real handlers over local storage in a temp dir, so this
// suite pins the wire protocol between the server and the Go SDK.
func newServer(t *testing.T) *client.Client {
	t.Helper()

	config.AdvancedFeatures = true
	config.MaxFileSizeMB = 8
	config.MaxTextSizeMB = 1

	dir := t.TempDir()
	fileStore := local.NewLocalFileStore(dir)
	secretStore, err := local.NewSQLiteStore(dir, fileStore)
	if err != nil {
		t.Fatalf("sqlite store: %v", err)
	}
	t.Cleanup(func() { storage.Close() })

	storage.SetFileStore(fileStore)
	storage.SetSecretStore(secretStore)

	e := echo.New()
	e.HideBanner = true
	e.POST("/encrypt", handlers.EncryptString)
	e.POST("/encrypt_file", handlers.EncryptFile)
	e.POST("/decrypt", handlers.Decrypt)

	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)

	c, err := client.New(srv.URL)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

func TestE2E_TextRoundTrip(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	stored, err := c.StoreText(ctx, "the eagle has landed", &client.StoreOptions{
		ViewCount: client.Views(2),
		Expiry:    client.ExpireIn(time.Hour),
	})
	if err != nil {
		t.Fatalf("StoreText: %v", err)
	}

	got, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if got.IsFile {
		t.Fatal("text secret came back as a file")
	}
	if got.Text != "the eagle has landed" {
		t.Errorf("text = %q", got.Text)
	}
}

func TestE2E_FileRoundTrip(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	data := bytes.Repeat([]byte{0x00, 0xFF, 0x42, 0x7F}, 64*1024)
	stored, err := c.StoreFile(ctx, "notes.bin", "application/octet-stream", data, &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(time.Hour),
	})
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	got, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if !got.IsFile || got.File == nil {
		t.Fatalf("expected a file, got %+v", got)
	}
	if got.File.Name != "notes.bin" || got.File.ContentType != "application/octet-stream" {
		t.Errorf("metadata = %q/%q", got.File.Name, got.File.ContentType)
	}
	if !bytes.Equal(got.File.Data, data) {
		t.Error("file bytes mismatch")
	}
}

func TestE2E_ViewExhaustion(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	stored, err := c.StoreText(ctx, "one shot", &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(time.Hour),
	})
	if err != nil {
		t.Fatalf("StoreText: %v", err)
	}

	if _, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase); err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}

	_, err = c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	assertAPIStatus(t, err, http.StatusNotFound)
}

func TestE2E_FileViewExhaustionDeletesFile(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	stored, err := c.StoreFile(ctx, "note.txt", "text/plain", []byte("pretend this is a file"), &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(time.Hour),
	})
	if err != nil {
		t.Fatalf("StoreFile: %v", err)
	}

	if _, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase); err != nil {
		t.Fatalf("first Retrieve: %v", err)
	}

	_, err = c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	assertAPIStatus(t, err, http.StatusNotFound)

	if _, err := storage.GetFileStore().GetEncryptedFile(ctx, stored.SecretID); !errors.Is(err, types.ErrNotFound) {
		t.Errorf("encrypted file should be gone, got err = %v", err)
	}
}

// The server rejects a TTL in the past, so the expired record is seeded
// straight into storage with the SDK's own crypto.
func TestE2E_TTLExpiry(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	payload, passphrase, err := client.EncryptText("already expired", nil, nil)
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}

	record, err := json.Marshal(map[string]any{
		"passwordHash":  payload.PasswordHash,
		"encryptedData": payload.EncryptedData,
		"nonce":         payload.Nonce,
		"header":        payload.Header,
		"isFile":        false,
	})
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	secretId := utils.RandString(16, true)
	expired := time.Now().Add(-time.Hour).Unix()
	if err := storage.GetSecretStore().StoreSecret(ctx, secretId, record, &expired, nil); err != nil {
		t.Fatalf("StoreSecret: %v", err)
	}

	_, err = c.Retrieve(ctx, secretId, passphrase)
	assertAPIStatus(t, err, http.StatusNotFound)

	if _, _, err := storage.GetSecretStore().GetSecret(ctx, secretId); !errors.Is(err, types.ErrNotFound) {
		t.Errorf("expired secret should be deleted, got err = %v", err)
	}
}

func TestE2E_WrongPassphrase(t *testing.T) {
	c := newServer(t)
	ctx := context.Background()

	stored, err := c.StoreText(ctx, "secret", &client.StoreOptions{
		ViewCount: client.Views(1),
		Expiry:    client.ExpireIn(time.Hour),
	})
	if err != nil {
		t.Fatalf("StoreText: %v", err)
	}

	_, wrong, err := client.EncryptText("anything", nil, nil)
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}

	_, err = c.Retrieve(ctx, stored.SecretID, wrong)
	assertAPIStatus(t, err, http.StatusNotFound)

	// The failed attempt must leave the single view intact.
	got, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		t.Fatalf("Retrieve after wrong passphrase: %v", err)
	}
	if got.Text != "secret" {
		t.Errorf("text = %q", got.Text)
	}
}

func TestE2E_AdvancedFeaturesDisabled(t *testing.T) {
	c := newServer(t)
	config.AdvancedFeatures = false
	defer func() { config.AdvancedFeatures = true }()

	_, err := c.StoreText(context.Background(), "no limits given", nil)
	assertAPIStatus(t, err, http.StatusBadRequest)
}

func assertAPIStatus(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected HTTP %d, got nil error", want)
	}
	apiErr, ok := err.(*client.APIError)
	if !ok {
		t.Fatalf("expected *client.APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != want {
		t.Errorf("status = %d, want %d: %s", apiErr.StatusCode, want, apiErr.Message)
	}
}
