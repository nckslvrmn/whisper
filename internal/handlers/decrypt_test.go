package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	echo "github.com/labstack/echo/v4"
)

func seedSecret(t *testing.T, ss *mockSecretStore, secretId string, payload SecretPayload, ttl *int64, viewCount *int) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("seedSecret marshal: %v", err)
	}
	if err := ss.StoreSecret(t.Context(), secretId, b, ttl, viewCount); err != nil {
		t.Fatalf("seedSecret: %v", err)
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

func textPayload(hash string) SecretPayload {
	return SecretPayload{
		PasswordHash:  hash,
		EncryptedData: "dGVzdA==",
		Nonce:         "bm9uY2U=",
		Header:        "aGVhZGVy",
	}
}

func filePayload(hash string) SecretPayload {
	return SecretPayload{
		PasswordHash:      hash,
		EncryptedMetadata: "bWV0YQ==",
		Nonce:             "bm9uY2U=",
		Header:            "aGVhZGVy",
		IsFile:            true,
	}
}

func ptrInt(n int) *int       { return &n }
func ptrInt64(n int64) *int64 { return &n }

// --- text secrets ---

func TestDecrypt_Success(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmnop"
	seedSecret(t, ss, id, textPayload(validHash), nil, nil)

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

	const id = "abcdefghijklmno1"
	seedSecret(t, ss, id, textPayload(validHash), nil, ptrInt(1))

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	c2, _ := newEchoContext(decryptBody(id, validHash))
	assertHTTPError(t, Decrypt(c2), http.StatusNotFound)
}

func TestDecrypt_ViewCountDecremented(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno2"
	seedSecret(t, ss, id, textPayload(validHash), nil, ptrInt(3))

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("first decrypt: %v", err)
	}

	ss.mu.Lock()
	defer ss.mu.Unlock()
	stored, ok := ss.secrets[id]
	if !ok {
		t.Fatal("secret should still exist")
	}
	if stored.viewCount == nil || *stored.viewCount != 2 {
		t.Errorf("viewCount = %v, want 2", stored.viewCount)
	}
}

func TestDecrypt_UnlimitedViews_SecretPersists(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno3"
	seedSecret(t, ss, id, textPayload(validHash), nil, nil)

	for i := 0; i < 3; i++ {
		c, _ := newEchoContext(decryptBody(id, validHash))
		if err := Decrypt(c); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}

	if !ss.has(id) {
		t.Error("secret should persist when views are unlimited")
	}
}

func TestDecrypt_ConcurrentLastView_OneWinner(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno4"
	seedSecret(t, ss, id, textPayload(validHash), nil, ptrInt(1))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var ok, notFound int

	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, rec := newEchoContext(decryptBody(id, validHash))
			<-start
			err := Decrypt(c)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && rec.Code == http.StatusOK:
				ok++
			case err != nil && err.(*echo.HTTPError).Code == http.StatusNotFound:
				notFound++
			default:
				t.Errorf("unexpected result: code = %d, err = %v", rec.Code, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if ok != 1 || notFound != 1 {
		t.Errorf("got %d success and %d not-found, want exactly 1 of each", ok, notFound)
	}
}

// --- TTL enforcement ---

func TestDecrypt_ExpiredTTL_DeletesAnd404s(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmno5"
	seedSecret(t, ss, id, filePayload(validHash), ptrInt64(time.Now().Add(-time.Hour).Unix()), nil)
	fs.put(id, []byte("filedata"))

	c, _ := newEchoContext(decryptBody(id, validHash))
	assertHTTPError(t, Decrypt(c), http.StatusNotFound)

	if ss.has(id) {
		t.Error("expired secret should be deleted from the store")
	}
	if fs.has(id) {
		t.Error("expired file should be deleted from the file store")
	}
}

func TestDecrypt_ValidTTL_Succeeds(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno6"
	seedSecret(t, ss, id, textPayload(validHash), ptrInt64(time.Now().Add(time.Hour).Unix()), nil)

	c, rec := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// --- validation ---

func TestDecrypt_MalformedRequests_400BeforeStorage(t *testing.T) {
	cases := map[string]string{
		"missing secret_id":       `{"passwordHash":"` + validHash + `"}`,
		"invalid secret_id":       `{"secret_id":"invalid!","passwordHash":"` + validHash + `"}`,
		"missing password hash":   `{"secret_id":"abcdefghijklmnop"}`,
		"password hash too short": `{"secret_id":"abcdefghijklmnop","passwordHash":"tooshort"}`,
		"invalid json":            "{invalid json",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ss, fs := setupMockStores()
			c, _ := newEchoContext(body)
			assertHTTPError(t, Decrypt(c), http.StatusBadRequest)

			ss.mu.Lock()
			defer ss.mu.Unlock()
			fs.mu.Lock()
			defer fs.mu.Unlock()
			if len(ss.calls) != 0 || len(fs.calls) != 0 {
				t.Errorf("storage was touched: secrets %v, files %v", ss.calls, fs.calls)
			}
		})
	}
}

func TestDecrypt_SecretNotFound(t *testing.T) {
	setupMockStores()

	c, _ := newEchoContext(decryptBody("abcdefghijklmnop", validHash))
	assertHTTPError(t, Decrypt(c), http.StatusNotFound)
}

func TestDecrypt_WrongPasswordHash_404AndViewIntact(t *testing.T) {
	ss, _ := setupMockStores()

	const id = "abcdefghijklmno7"
	seedSecret(t, ss, id, textPayload(validHash), nil, ptrInt(1))

	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	c, _ := newEchoContext(decryptBody(id, wrongHash))
	assertHTTPError(t, Decrypt(c), http.StatusNotFound)

	if ss.called("consume") {
		t.Error("a wrong passphrase must not consume a view")
	}
	if !ss.has(id) {
		t.Error("secret should still exist after a wrong passphrase")
	}
}

func TestDecrypt_StoreReadFailure_Returns500(t *testing.T) {
	ss, _ := setupMockStores()
	ss.failOp = "get"

	c, _ := newEchoContext(decryptBody("abcdefghijklmno8", validHash))
	assertHTTPError(t, Decrypt(c), http.StatusInternalServerError)
}

// --- file secrets ---

func TestDecrypt_FileSecret_StreamsBinary(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmnoa"
	seedSecret(t, ss, id, filePayload(validHash), nil, nil)
	fs.put(id, []byte{0x00, 0xFF, 0x10, 0x20})

	c, rec := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get(echo.HeaderContentType); got != echo.MIMEOctetStream {
		t.Errorf("content type = %q, want %q", got, echo.MIMEOctetStream)
	}
	if got := rec.Header().Get("X-Whisper-Encrypted-Metadata"); got != "bWV0YQ==" {
		t.Errorf("metadata header = %q", got)
	}
	if got := rec.Header().Get("X-Whisper-Nonce"); got != "bm9uY2U=" {
		t.Errorf("nonce header = %q", got)
	}
	if got := rec.Header().Get("X-Whisper-Header"); got != "aGVhZGVy" {
		t.Errorf("header header = %q", got)
	}
	if got := rec.Body.Bytes(); string(got) != string([]byte{0x00, 0xFF, 0x10, 0x20}) {
		t.Errorf("body = %v, want the raw ciphertext", got)
	}
}

func TestDecrypt_FileSecret_DeletedOnLastView(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmnob"
	seedSecret(t, ss, id, filePayload(validHash), nil, ptrInt(1))
	fs.put(id, []byte("filedata"))

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if fs.has(id) {
		t.Error("file should be deleted after the last view")
	}
	if ss.has(id) {
		t.Error("secret record should be deleted after the last view")
	}
}

func TestDecrypt_FileReadFailure_500AndViewIntact(t *testing.T) {
	ss, fs := setupMockStores()
	fs.failOp = "get"

	const id = "abcdefghijklmnoc"
	seedSecret(t, ss, id, filePayload(validHash), nil, ptrInt(1))
	fs.put(id, []byte("filedata"))

	c, _ := newEchoContext(decryptBody(id, validHash))
	assertHTTPError(t, Decrypt(c), http.StatusInternalServerError)

	if ss.called("consume") {
		t.Error("a file store failure must not consume a view")
	}
	if !ss.has(id) {
		t.Error("secret should still exist after a file store failure")
	}
}

func TestDecrypt_FileSecret_SurvivesUntilLastView(t *testing.T) {
	ss, fs := setupMockStores()

	const id = "abcdefghijklmnod"
	seedSecret(t, ss, id, filePayload(validHash), nil, ptrInt(2))
	fs.put(id, []byte("filedata"))

	c, _ := newEchoContext(decryptBody(id, validHash))
	if err := Decrypt(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !fs.has(id) {
		t.Error("file should survive while views remain")
	}
}
