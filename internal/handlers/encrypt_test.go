package handlers

import (
	"encoding/json"
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
		if v == nil {
			delete(m, k)
			continue
		}
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

	body := encryptBody(t, map[string]any{"viewCount": 3, "ttl": futureTTL()})

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
	if secretId, _ := resp["secretId"].(string); len(secretId) != 16 {
		t.Errorf("secretId = %q, want 16-char string", secretId)
	}
}

func TestEncryptString_Success_AdvancedOn(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	c, rec := newEchoContext(encryptBody(t, nil))
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestEncryptString_StoredPayloadHasNoViewCountOrTTL(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = false

	ttl := futureTTL()
	c, rec := newEchoContext(encryptBody(t, map[string]any{"viewCount": 4, "ttl": ttl}))
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secretId, _ := decodeResponse(rec)["secretId"].(string)
	ss.mu.Lock()
	stored := ss.secrets[secretId]
	ss.mu.Unlock()
	if stored == nil {
		t.Fatal("secret was not stored")
	}

	var payload map[string]any
	if err := json.Unmarshal(stored.payload, &payload); err != nil {
		t.Fatalf("stored payload is not JSON: %v", err)
	}
	if _, ok := payload["viewCount"]; ok {
		t.Error("stored payload must not carry viewCount")
	}
	if _, ok := payload["ttl"]; ok {
		t.Error("stored payload must not carry ttl")
	}
	if stored.viewCount == nil || *stored.viewCount != 4 {
		t.Errorf("native viewCount = %v, want 4", stored.viewCount)
	}
	if stored.ttl == nil || *stored.ttl != ttl {
		t.Errorf("native ttl = %v, want %d", stored.ttl, ttl)
	}
}

func TestEncryptString_AdvancedOff_MissingTTL(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false

	c, _ := newEchoContext(encryptBody(t, map[string]any{"viewCount": 3}))
	assertHTTPError(t, EncryptString(c), http.StatusBadRequest)
}

func TestEncryptString_AdvancedOff_MissingViewCount(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false

	c, _ := newEchoContext(encryptBody(t, map[string]any{"ttl": futureTTL()}))
	assertHTTPError(t, EncryptString(c), http.StatusBadRequest)
}

func TestEncryptString_ValidationFailsBeforeStorage(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	cases := map[string]string{
		"missing password hash": `{"encryptedData":"dGVzdA==","nonce":"bm9uY2U=","header":"aGVhZGVy"}`,
		"invalid password hash": encryptBody(t, map[string]any{"passwordHash": "tooshort"}),
		"missing data":          encryptBody(t, map[string]any{"encryptedData": nil}),
		"missing nonce":         encryptBody(t, map[string]any{"nonce": nil}),
		"missing header":        encryptBody(t, map[string]any{"header": nil}),
		"ttl in the past":       encryptBody(t, map[string]any{"ttl": time.Now().Add(-time.Hour).Unix()}),
		"ttl beyond 30 days":    encryptBody(t, map[string]any{"ttl": time.Now().Add(31 * 24 * time.Hour).Unix()}),
		"view count too high":   encryptBody(t, map[string]any{"viewCount": 11}),
		"view count negative":   encryptBody(t, map[string]any{"viewCount": -1}),
		"invalid json":          "{invalid json",
		"text too large":        encryptBody(t, map[string]any{"encryptedData": strings.Repeat("x", MaxTextSize()+1)}),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c, _ := newEchoContext(body)
			assertHTTPError(t, EncryptString(c), http.StatusBadRequest)
			if ss.called("store") {
				t.Error("storage was written despite a validation failure")
			}
		})
	}
}

func TestEncryptString_ViewCount_Zero_Unlimited(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	c, rec := newEchoContext(encryptBody(t, map[string]any{"viewCount": 0, "ttl": futureTTL()}))
	if err := EncryptString(c); err != nil {
		t.Fatalf("unexpected error for viewCount=0: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestEncryptString_StoreError_Returns500(t *testing.T) {
	ss, _ := setupMockStores()
	ss.failOp = "store"
	config.AdvancedFeatures = true

	c, _ := newEchoContext(encryptBody(t, nil))
	assertHTTPError(t, EncryptString(c), http.StatusInternalServerError)
}

// --- EncryptFile ---

func TestEncryptFile_Success(t *testing.T) {
	ss, fs := setupMockStores()
	config.AdvancedFeatures = true

	c, rec := newMultipartContext([][2]string{
		{"payload", filePayloadJSON(nil)},
		{"file", "rawciphertextbytes"},
	})
	if err := EncryptFile(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	secretId, _ := decodeResponse(rec)["secretId"].(string)
	if !fs.has(secretId) {
		t.Error("encrypted file was not stored")
	}
	if !ss.has(secretId) {
		t.Error("secret record was not stored")
	}

	fs.mu.Lock()
	stored := string(fs.files[secretId])
	fs.mu.Unlock()
	if stored != "rawciphertextbytes" {
		t.Errorf("stored file = %q, want the raw bytes as sent", stored)
	}
}

func TestEncryptFile_RecordStoreFailure_DeletesFile(t *testing.T) {
	ss, fs := setupMockStores()
	ss.failOp = "store"
	config.AdvancedFeatures = true

	c, _ := newMultipartContext([][2]string{
		{"payload", filePayloadJSON(nil)},
		{"file", "rawciphertextbytes"},
	})
	assertHTTPError(t, EncryptFile(c), http.StatusInternalServerError)

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.files) != 0 {
		t.Errorf("orphaned file left behind: %v", fs.files)
	}
}

func TestEncryptFile_MalformedUploads(t *testing.T) {
	config.AdvancedFeatures = true

	cases := map[string][][2]string{
		"missing payload part":  {{"file", "data"}},
		"parts out of order":    {{"file", "data"}, {"payload", filePayloadJSON(nil)}},
		"missing file part":     {{"payload", filePayloadJSON(nil)}},
		"empty file part":       {{"payload", filePayloadJSON(nil)}, {"file", ""}},
		"invalid payload json":  {{"payload", "{nope"}, {"file", "data"}},
		"missing metadata":      {{"payload", filePayloadJSON(map[string]any{"encryptedMetadata": nil})}, {"file", "data"}},
		"missing password hash": {{"payload", filePayloadJSON(map[string]any{"passwordHash": nil})}, {"file", "data"}},
		"missing nonce":         {{"payload", filePayloadJSON(map[string]any{"nonce": nil})}, {"file", "data"}},
		"extra part":            {{"payload", filePayloadJSON(nil)}, {"file", "data"}, {"surprise", "x"}},
	}

	for name, parts := range cases {
		t.Run(name, func(t *testing.T) {
			ss, fs := setupMockStores()
			c, _ := newMultipartContext(parts)
			assertHTTPError(t, EncryptFile(c), http.StatusBadRequest)

			if ss.called("store") {
				t.Error("secret record written for a rejected upload")
			}
			fs.mu.Lock()
			defer fs.mu.Unlock()
			if len(fs.files) != 0 {
				t.Errorf("orphaned file left behind: %v", fs.files)
			}
		})
	}
}

func TestEncryptFile_NotMultipart(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = true

	c, _ := newEchoContext(`{"passwordHash":"` + validHash + `"}`)
	assertHTTPError(t, EncryptFile(c), http.StatusBadRequest)
}

func TestEncryptFile_OversizedFilePart(t *testing.T) {
	_, fs := setupMockStores()
	config.AdvancedFeatures = true

	orig := config.MaxFileSizeMB
	config.MaxFileSizeMB = 1
	defer func() { config.MaxFileSizeMB = orig }()

	c, _ := newMultipartContext([][2]string{
		{"payload", filePayloadJSON(nil)},
		{"file", strings.Repeat("x", MaxFileSize()+1)},
	})
	assertHTTPError(t, EncryptFile(c), http.StatusBadRequest)

	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.files) != 0 {
		t.Errorf("oversized upload left a file behind: %v", fs.files)
	}
}

func TestEncryptFile_AdvancedOff_RequiresLimits(t *testing.T) {
	setupMockStores()
	config.AdvancedFeatures = false
	defer func() { config.AdvancedFeatures = true }()

	c, _ := newMultipartContext([][2]string{
		{"payload", filePayloadJSON(nil)},
		{"file", "data"},
	})
	assertHTTPError(t, EncryptFile(c), http.StatusBadRequest)
}

func TestEncryptFile_StoredPayloadIsFile(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	c, rec := newMultipartContext([][2]string{
		{"payload", filePayloadJSON(nil)},
		{"file", "data"},
	})
	if err := EncryptFile(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secretId, _ := decodeResponse(rec)["secretId"].(string)
	ss.mu.Lock()
	stored := ss.secrets[secretId]
	ss.mu.Unlock()

	var payload SecretPayload
	if err := json.Unmarshal(stored.payload, &payload); err != nil {
		t.Fatalf("stored payload is not JSON: %v", err)
	}
	if !payload.IsFile {
		t.Error("isFile = false, want true")
	}
	if payload.EncryptedData != "" {
		t.Errorf("encryptedData = %q, want empty for file secrets", payload.EncryptedData)
	}
	if payload.EncryptedMetadata != "bWV0YQ==" {
		t.Errorf("encryptedMetadata = %q", payload.EncryptedMetadata)
	}
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
		t.Errorf("HTTP status = %d, want %d: %v", he.Code, wantCode, he.Message)
	}
}
