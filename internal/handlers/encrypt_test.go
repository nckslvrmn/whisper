package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/config"
)

// futureTTL returns a Unix timestamp 24 hours from now.
func futureTTL() int64 { return time.Now().Add(24 * time.Hour).Unix() }

// encryptBody builds a JSON body for EncryptString tests.
func encryptBody(t *testing.T, extra map[string]any) string {
	t.Helper()
	m := map[string]any{
		"passwordHash":  validHash,
		"encryptedData": "dGVzdA==",
		"nonce":         "bm9uY2U=",
		"header":        "aGVhZGVy",
	}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encryptBody marshal: %v", err)
	}
	return string(b)
}

// --- EncryptString ---

func TestEncryptString_Success_AdvancedOff(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false

	vc := 3
	ttl := futureTTL()
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": ttl})

	c, rec := newEchoContext(body)
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	resp := decodeResponse(rec)
	if resp["status"] != "success" {
		t.Errorf("status = %v, want success", resp["status"])
	}
	secretId, _ := resp["secretId"].(string)
	if len(secretId) != 16 {
		t.Errorf("secretId = %q, want 16-char string", secretId)
	}
}

func TestEncryptString_Success_AdvancedOn(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	// No viewCount or ttl — allowed when AdvancedFeatures is true
	c, rec := newEchoContext(encryptBody(t, nil))
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestEncryptString_AdvancedOff_MissingTTL_ReturnsError(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false

	vc := 3
	body := encryptBody(t, map[string]any{"viewCount": vc})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	if err == nil {
		t.Fatal("expected error when TTL missing and AdvancedFeatures=false")
	}
}

func TestEncryptString_AdvancedOff_MissingViewCount_ReturnsError(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false

	body := encryptBody(t, map[string]any{"ttl": futureTTL()})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	if err == nil {
		t.Fatal("expected error when viewCount missing and AdvancedFeatures=false")
	}
}

func TestEncryptString_MissingPasswordHash(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	body := `{"encryptedData":"dGVzdA==","nonce":"bm9uY2U=","header":"aGVhZGVy"}`
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_InvalidPasswordHash(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	body := encryptBody(t, map[string]any{"passwordHash": "tooshort"})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_MissingEncryptedData(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	body := fmt.Sprintf(`{"passwordHash":%q,"nonce":"x","header":"y"}`, validHash)
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_TTL_InThePast(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	pastTTL := time.Now().Add(-1 * time.Hour).Unix()
	vc := 1
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": pastTTL})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_TTL_ExceedsThirtyDays(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	farFuture := time.Now().Add(31 * 24 * time.Hour).Unix()
	vc := 1
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": farFuture})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_ViewCount_AboveMax(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	vc := 11
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": futureTTL()})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_ViewCount_Negative(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	vc := -1
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": futureTTL()})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_ViewCount_Zero_Unlimited(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	// viewCount=0 means unlimited — should succeed
	vc := 0
	body := encryptBody(t, map[string]any{"viewCount": vc, "ttl": futureTTL()})
	c, rec := newEchoContext(body)
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error for viewCount=0: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestEncryptString_InvalidJSON(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	c, _ := newEchoContext("{invalid json")
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptString_StoreError_Returns500(t *testing.T) {
	ss, fs := setupMockStores()
	ss.failOp = "store"
	_ = fs
	config.AdvancedFeatures = true

	body := encryptBody(t, nil)
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusInternalServerError)
}

func TestEncryptString_SecretIDStoredInStore(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	c, rec := newEchoContext(encryptBody(t, nil))
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp := decodeResponse(rec)
	secretId, _ := resp["secretId"].(string)

	ss.mu.Lock()
	_, stored := ss.secrets[secretId]
	ss.mu.Unlock()

	if !stored {
		t.Error("secret was not found in store under returned secretId")
	}
}

func TestEncryptString_TextSizeExceedsLimit(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	body := encryptBody(t, map[string]any{"encryptedData": strings.Repeat("x", MaxTextSize+1)})
	c, _ := newEchoContext(body)
	err := EncryptString(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

// --- EncryptFile ---

func TestEncryptFile_Success_NoFileData(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	body := fmt.Sprintf(`{"passwordHash":%q,"nonce":"bm9uY2U=","header":"aGVhZGVy","isFile":true}`, validHash)
	c, rec := newEchoContext(body)
	if err := EncryptFile(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	resp := decodeResponse(rec)
	if resp["status"] != "success" {
		t.Errorf("status = %v, want success", resp["status"])
	}
}

func TestEncryptFile_Success_WithFileData(t *testing.T) {
	ss, fs := setupMockStores()
	_ = ss
	config.AdvancedFeatures = true

	// Small base64-encoded "file" payload
	body := fmt.Sprintf(`{"passwordHash":%q,"nonce":"bm9uY2U=","header":"aGVhZGVy","isFile":true,"encryptedFile":"dGVzdGZpbGVkYXRh"}`, validHash)
	c, rec := newEchoContext(body)
	if err := EncryptFile(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	resp := decodeResponse(rec)
	secretId, _ := resp["secretId"].(string)

	fs.mu.Lock()
	_, fileStored := fs.files[secretId]
	fs.mu.Unlock()

	if !fileStored {
		t.Error("encrypted file was not stored in file store")
	}
}

func TestEncryptFile_MissingPasswordHash(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	c, _ := newEchoContext(`{"isFile":true,"nonce":"x","header":"y"}`)
	err := EncryptFile(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestEncryptFile_FileSizeExceedsLimit(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	oversized := strings.Repeat("x", MaxFileSize+1)
	body := fmt.Sprintf(`{"passwordHash":%q,"encryptedFile":%q,"nonce":"x","header":"y"}`, validHash, oversized)
	c, _ := newEchoContext(body)
	err := EncryptFile(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

// --- helper ---

func assertHTTPError(t *testing.T, err error, wantCode int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected HTTP error %d, got nil", wantCode)
	}
	he, ok := err.(*echo.HTTPError)
	if !ok {
		t.Fatalf("expected *echo.HTTPError, got %T: %v", err, err)
	}
	if he.Code != wantCode {
		t.Errorf("HTTP status = %d, want %d", he.Code, wantCode)
	}
}
