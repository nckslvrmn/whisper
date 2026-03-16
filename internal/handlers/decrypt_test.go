package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nckslvrmn/whisper/internal/config"
)

// storeSecret pre-populates the mock store with a secret JSON blob.
func storeSecret(t *testing.T, ss *mockSecretStore, secretId string, data map[string]any) {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("storeSecret marshal: %v", err)
	}
	if err := ss.StoreSecretRaw(secretId, b, nil, nil); err != nil {
		t.Fatalf("storeSecret: %v", err)
	}
}

// decryptBody builds a decrypt request JSON body.
func decryptBody(secretId, passwordHash string) string {
	b, _ := json.Marshal(map[string]string{
		"secret_id":    secretId,
		"passwordHash": passwordHash,
	})
	return string(b)
}

// validSecretData returns a minimal valid secret map for the given hash.
func validSecretData(hash string) map[string]any {
	return map[string]any{
		"passwordHash":  hash,
		"encryptedData": "dGVzdA==",
		"nonce":         "bm9uY2U=",
		"header":        "aGVhZGVy",
		"isFile":        false,
	}
}

// --- Decrypt happy path ---

func TestDecrypt_Success(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	const id = "abcdefghijklmnop"
	storeSecret(t, ss, id, validSecretData(validHash))

	c, rec := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	resp := decodeResponse(rec)
	if resp["encryptedData"] != "dGVzdA==" {
		t.Errorf("encryptedData = %v", resp["encryptedData"])
	}
	if resp["isFile"] != false {
		t.Errorf("isFile = %v, want false", resp["isFile"])
	}
}

func TestDecrypt_SecretDeletedAfterSingleView(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	const id = "abcdefghijklmno1"
	vc := 1
	data := validSecretData(validHash)
	data["viewCount"] = vc
	storeSecret(t, ss, id, data)

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	// Second attempt must return 404
	c2, _ := newEchoContext(decryptBody(id, validHash))
	err := Decrypt(c2)
	assertHTTPError(t, err, http.StatusNotFound)
}

func TestDecrypt_ViewCountDecremented(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	const id = "abcdefghijklmno2"
	data := validSecretData(validHash)
	data["viewCount"] = float64(3)
	storeSecret(t, ss, id, data)

	// First view
	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	// Secret should still exist with viewCount=2
	raw, err := ss.GetSecretRaw(id)
	if err != nil {
		t.Fatalf("secret should still exist: %v", err)
	}
	var updated map[string]any
	json.Unmarshal(raw, &updated)
	if updated["viewCount"] != float64(2) {
		t.Errorf("viewCount = %v, want 2", updated["viewCount"])
	}
}

func TestDecrypt_NoViewCount_SecretPersists(t *testing.T) {
	ss, _ := setupMockStores()
	config.AdvancedFeatures = true

	const id = "abcdefghijklmno3"
	storeSecret(t, ss, id, validSecretData(validHash))

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Without viewCount, secret should still be in store
	if _, err := ss.GetSecretRaw(id); err != nil {
		t.Error("secret should persist when no viewCount is set")
	}
}

// --- Decrypt: TTL enforcement ---

func TestDecrypt_ExpiredTTL_Returns404(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno4"
	data := validSecretData(validHash)
	data["ttl"] = float64(time.Now().Add(-1 * time.Hour).Unix())
	storeSecret(t, ss, id, data)

	c, _ := newEchoContext(decryptBody(id, validHash))
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusNotFound)
}

func TestDecrypt_ExpiredSecret_DeletedFromStore(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno5"
	data := validSecretData(validHash)
	data["ttl"] = float64(time.Now().Add(-1 * time.Hour).Unix())
	storeSecret(t, ss, id, data)

	c, _ := newEchoContext(decryptBody(id, validHash))
	Decrypt(c) // ignore error — we expect 404

	if _, err := ss.GetSecretRaw(id); err == nil {
		t.Error("expired secret should be deleted from store")
	}
}

func TestDecrypt_ValidTTL_Succeeds(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno6"
	data := validSecretData(validHash)
	data["ttl"] = float64(time.Now().Add(1 * time.Hour).Unix())
	storeSecret(t, ss, id, data)

	c, rec := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// --- Decrypt: validation errors ---

func TestDecrypt_MissingSecretID(t *testing.T) {
	setupMockStores()

	c, _ := newEchoContext(`{"passwordHash":"` + validHash + `"}`)
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestDecrypt_InvalidSecretIDFormat(t *testing.T) {
	setupMockStores()

	c, _ := newEchoContext(`{"secret_id":"invalid!","passwordHash":"` + validHash + `"}`)
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestDecrypt_SecretNotFound(t *testing.T) {
	setupMockStores()

	c, _ := newEchoContext(decryptBody("abcdefghijklmnop", validHash))
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusNotFound)
}

func TestDecrypt_MissingPasswordHash_Returns404(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno7"
	storeSecret(t, ss, id, validSecretData(validHash))

	c, _ := newEchoContext(`{"secret_id":"` + id + `"}`)
	err := Decrypt(c)
	// handler returns 404 (not 400) when passwordHash is empty
	assertHTTPError(t, err, http.StatusNotFound)
}

func TestDecrypt_InvalidPasswordHashFormat(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno8"
	storeSecret(t, ss, id, validSecretData(validHash))

	c, _ := newEchoContext(`{"secret_id":"` + id + `","passwordHash":"tooshort"}`)
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

func TestDecrypt_WrongPasswordHash_Returns404(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno9"
	storeSecret(t, ss, id, validSecretData(validHash))

	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	c, _ := newEchoContext(decryptBody(id, wrongHash))
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusNotFound)
}

func TestDecrypt_InvalidJSON(t *testing.T) {
	setupMockStores()

	c, _ := newEchoContext("{invalid json")
	err := Decrypt(c)
	assertHTTPError(t, err, http.StatusBadRequest)
}

// --- Decrypt: file secrets ---

func TestDecrypt_FileSecret_ReturnsEncryptedFile(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmnoa"
	data := map[string]any{
		"passwordHash":      validHash,
		"encryptedData":     "",
		"encryptedMetadata": "bWV0YQ==",
		"nonce":             "bm9uY2U=",
		"header":            "aGVhZGVy",
		"isFile":            true,
	}
	storeSecret(t, ss, id, data)
	fs.files[id] = []byte("encryptedfilecontent")

	c, rec := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	resp := decodeResponse(rec)
	if resp["isFile"] != true {
		t.Errorf("isFile = %v, want true", resp["isFile"])
	}
	if resp["encryptedFile"] != "encryptedfilecontent" {
		t.Errorf("encryptedFile = %v", resp["encryptedFile"])
	}
}

func TestDecrypt_FileSecret_DeletedOnLastView(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmnob"
	data := map[string]any{
		"passwordHash": validHash,
		"nonce":        "bm9uY2U=",
		"header":       "aGVhZGVy",
		"isFile":       true,
		"viewCount":    float64(1),
	}
	storeSecret(t, ss, id, data)
	fs.files[id] = []byte("filedata")

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	fs.mu.Lock()
	_, fileExists := fs.files[id]
	fs.mu.Unlock()
	if fileExists {
		t.Error("file should be deleted after last view")
	}
}
