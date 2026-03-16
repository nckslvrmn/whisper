package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/storage"
)

// validHash is a 64-char lowercase hex string accepted by validatePasswordHash.
const validHash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

// --- mockSecretStore ---

type mockSecretStore struct {
	mu      sync.Mutex
	secrets map[string][]byte
	// Set to "store", "get", "update", or "delete" to force that operation to fail.
	failOp string
}

func newMockSecretStore() *mockSecretStore {
	return &mockSecretStore{secrets: make(map[string][]byte)}
}

func (m *mockSecretStore) StoreSecretRaw(secretId string, data []byte, ttl *int64, viewCount *int) error {
	if m.failOp == "store" {
		return errors.New("mock store error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[secretId] = data
	return nil
}

func (m *mockSecretStore) GetSecretRaw(secretId string) ([]byte, error) {
	if m.failOp == "get" {
		return nil, errors.New("mock get error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.secrets[secretId]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return d, nil
}

func (m *mockSecretStore) UpdateSecretRaw(secretId string, data []byte) error {
	if m.failOp == "update" {
		return errors.New("mock update error")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.secrets[secretId]; !ok {
		return errors.New("secret not found")
	}
	m.secrets[secretId] = data
	return nil
}

func (m *mockSecretStore) DeleteSecret(secretId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, secretId)
	return nil
}

// --- mockFileStore ---

type mockFileStore struct {
	mu    sync.Mutex
	files map[string][]byte
}

func newMockFileStore() *mockFileStore {
	return &mockFileStore{files: make(map[string][]byte)}
}

func (m *mockFileStore) StoreEncryptedFile(secretId string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[secretId] = data
	return nil
}

func (m *mockFileStore) GetEncryptedFile(secretId string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.files[secretId]
	if !ok {
		return nil, errors.New("file not found")
	}
	return d, nil
}

func (m *mockFileStore) DeleteEncryptedFile(secretId string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, secretId)
	return nil
}

func (m *mockFileStore) DeleteFile(secretId string) error {
	return m.DeleteEncryptedFile(secretId)
}

// --- helpers ---

// setupMockStores injects fresh mock stores and returns them for assertions.
func setupMockStores() (*mockSecretStore, *mockFileStore) {
	ss := newMockSecretStore()
	fs := newMockFileStore()
	storage.SetSecretStore(ss)
	storage.SetFileStore(fs)
	return ss, fs
}

// newEchoContext creates a test Echo POST context with a JSON body.
func newEchoContext(body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// decodeResponse unmarshals the response body into a map.
func decodeResponse(rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		return nil
	}
	return m
}
