package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEncryptDecryptTextRoundtrip(t *testing.T) {
	payload, pass, err := EncryptText("hello, whisper!", Views(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pass) != SaltB64Len+PassphraseLen {
		t.Fatalf("display passphrase length: got %d, want %d", len(pass), SaltB64Len+PassphraseLen)
	}
	if len(payload.PasswordHash) != 64 {
		t.Fatalf("password hash length: got %d, want 64", len(payload.PasswordHash))
	}

	resp := &DecryptResponse{
		EncryptedData: payload.EncryptedData,
		Nonce:         payload.Nonce,
		Header:        payload.Header,
		IsFile:        false,
	}
	got, err := DecryptText(resp, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello, whisper!" {
		t.Fatalf("roundtrip text mismatch: %q", got)
	}
}

func TestEncryptDecryptFileRoundtrip(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	payload, pass, err := EncryptFile("thing.bin", "application/octet-stream", data, Views(1), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp := &DecryptResponse{
		EncryptedFile:     payload.EncryptedFile,
		EncryptedMetadata: payload.EncryptedMetadata,
		Nonce:             payload.Nonce,
		Header:            payload.Header,
		IsFile:            true,
	}
	got, err := DecryptFile(resp, pass)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "thing.bin" || got.ContentType != "application/octet-stream" {
		t.Fatalf("metadata mismatch: %+v", got)
	}
	if !bytes.Equal(got.Data, data) {
		t.Fatal("file bytes mismatch")
	}
}

func TestDecryptTextWrongPassphraseFails(t *testing.T) {
	payload, _, err := EncryptText("top secret", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Make a structurally valid but wrong display passphrase.
	_, badPass, err := EncryptText("anything", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &DecryptResponse{
		EncryptedData: payload.EncryptedData,
		Nonce:         payload.Nonce,
		Header:        payload.Header,
	}
	if _, err := DecryptText(resp, badPass); err == nil {
		t.Fatal("expected decrypt with wrong passphrase to fail")
	}
}

func TestHashPasswordDeterministic(t *testing.T) {
	salt := bytes.Repeat([]byte{0x42}, SaltSize)
	h1, err := HashPassword("hunter2", salt)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword("hunter2", salt)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("HashPassword not deterministic")
	}
	if len(h1) != 64 {
		t.Fatalf("hash length: got %d, want 64", len(h1))
	}
}

// fakeServer is a minimal in-memory implementation of the /encrypt, /encrypt_file,
// and /decrypt endpoints — enough to exercise Client end-to-end without pulling
// in the real storage layer.
type fakeServer struct {
	mu      sync.Mutex
	secrets map[string]map[string]any
}

func newFakeServer() *httptest.Server {
	fs := &fakeServer{secrets: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/encrypt", fs.handleEncrypt(false))
	mux.HandleFunc("/encrypt_file", fs.handleEncrypt(true))
	mux.HandleFunc("/decrypt", fs.handleDecrypt)
	return httptest.NewServer(mux)
}

func (fs *fakeServer) handleEncrypt(isFile bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Use a fixed-length ID to match server regex requirements.
		id := "0123456789abcdef"
		for i := 0; ; i++ {
			fs.mu.Lock()
			_, exists := fs.secrets[id]
			fs.mu.Unlock()
			if !exists {
				break
			}
			id = strings.Repeat("a", 15) + string(rune('a'+i))
		}
		body["isFile"] = isFile
		fs.mu.Lock()
		fs.secrets[id] = body
		fs.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "success", "secretId": id})
	}
}

func (fs *fakeServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SecretID     string `json:"secret_id"`
		PasswordHash string `json:"passwordHash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fs.mu.Lock()
	secret, ok := fs.secrets[req.SecretID]
	fs.mu.Unlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if secret["passwordHash"] != req.PasswordHash {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	resp := map[string]any{
		"encryptedData":     secret["encryptedData"],
		"encryptedMetadata": secret["encryptedMetadata"],
		"nonce":             secret["nonce"],
		"header":            secret["header"],
		"isFile":            secret["isFile"],
	}
	if ef, ok := secret["encryptedFile"]; ok {
		resp["encryptedFile"] = ef
	}
	json.NewEncoder(w).Encode(resp)
}

func TestNewBaseURLValidation(t *testing.T) {
	t.Run("accepts http and https with optional sub-path", func(t *testing.T) {
		cases := []string{
			"http://localhost:8080",
			"https://whisper.example.com",
			"https://whisper.example.com/",
			"https://proxy.example.com/whisper",
		}
		for _, in := range cases {
			c, err := New(in)
			if err != nil {
				t.Fatalf("New(%q): unexpected error: %v", in, err)
			}
			if !strings.HasSuffix(c.BaseURL.Path, "/") {
				t.Fatalf("New(%q): BaseURL.Path %q should end with /", in, c.BaseURL.Path)
			}
		}
	})
	t.Run("rejects bad inputs", func(t *testing.T) {
		cases := []string{
			"",
			"not a url",
			"ftp://example.com",
			"https:///missing-host",
			"https://example.com?x=1",
			"https://example.com#frag",
		}
		for _, in := range cases {
			if _, err := New(in); err == nil {
				t.Fatalf("New(%q): expected error, got nil", in)
			}
		}
	})
	t.Run("preserves sub-path in resolved URLs", func(t *testing.T) {
		c, err := New("https://proxy.example.com/whisper")
		if err != nil {
			t.Fatal(err)
		}
		got := c.resolve("encrypt")
		want := "https://proxy.example.com/whisper/encrypt"
		if got != want {
			t.Fatalf("resolve under sub-path: got %q, want %q", got, want)
		}
	})
}

func TestClient_StoreRetrieveText(t *testing.T) {
	srv := newFakeServer()
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.StoreText(context.Background(), "the eagle has landed", &StoreOptions{
		ViewCount: Views(3),
		Expiry:    ExpireIn(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored.SecretID == "" || stored.DisplayPassphrase == "" {
		t.Fatalf("missing fields: %+v", stored)
	}
	if !strings.HasPrefix(stored.URL, srv.URL+"/secret/") {
		t.Fatalf("unexpected URL: %s", stored.URL)
	}

	got, err := c.Retrieve(context.Background(), stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if got.IsFile {
		t.Fatal("got file for text round-trip")
	}
	if got.Text != "the eagle has landed" {
		t.Fatalf("text mismatch: %q", got.Text)
	}
}

func TestClient_StoreRetrieveFile(t *testing.T) {
	srv := newFakeServer()
	defer srv.Close()

	data := []byte("binary\x00content\xff here")
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.StoreFile(context.Background(), "notes.bin", "application/octet-stream", data, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := c.Retrieve(context.Background(), stored.SecretID, stored.DisplayPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsFile || got.File == nil {
		t.Fatalf("expected file, got %+v", got)
	}
	if got.File.Name != "notes.bin" || got.File.ContentType != "application/octet-stream" {
		t.Fatalf("metadata mismatch: %+v", got.File)
	}
	if !bytes.Equal(got.File.Data, data) {
		t.Fatal("file bytes mismatch")
	}
}

func TestClient_RetrieveWrongPassphrase(t *testing.T) {
	srv := newFakeServer()
	defer srv.Close()

	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.StoreText(context.Background(), "x", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Use a fresh (wrong) passphrase of the right shape.
	_, bogus, err := EncryptText("anything", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Retrieve(context.Background(), stored.SecretID, bogus)
	if err == nil {
		t.Fatal("expected retrieve with wrong passphrase to fail")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", apiErr.StatusCode)
	}
}
