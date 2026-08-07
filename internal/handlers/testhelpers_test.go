package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/storage"
	"github.com/nckslvrmn/whisper/internal/storage/types"
)

// validHash is a 64-char lowercase hex string accepted by validatePasswordHash.
const validHash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

var errMock = errors.New("mock storage failure")

// --- mockSecretStore ---

type mockSecret struct {
	payload   []byte
	ttl       *int64
	viewCount *int
}

type mockSecretStore struct {
	mu      sync.Mutex
	secrets map[string]*mockSecret
	// failOp forces the named operation to fail: store, get, consume, delete.
	failOp string
	calls  []string
}

func newMockSecretStore() *mockSecretStore {
	return &mockSecretStore{secrets: make(map[string]*mockSecret)}
}

func (m *mockSecretStore) record(op string) bool {
	m.calls = append(m.calls, op)
	return m.failOp == op
}

func (m *mockSecretStore) called(op string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.calls, op)
}

func (m *mockSecretStore) has(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.secrets[id]
	return ok
}

func (m *mockSecretStore) StoreSecret(ctx context.Context, id string, payload []byte, ttl *int64, viewCount *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record("store") {
		return errMock
	}
	m.secrets[id] = &mockSecret{payload: payload, ttl: ttl, viewCount: viewCount}
	return nil
}

func (m *mockSecretStore) GetSecret(ctx context.Context, id string) ([]byte, *int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record("get") {
		return nil, nil, errMock
	}
	s, ok := m.secrets[id]
	if !ok {
		return nil, nil, types.ErrNotFound
	}
	return s.payload, s.ttl, nil
}

func (m *mockSecretStore) ConsumeView(ctx context.Context, id string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record("consume") {
		return 0, errMock
	}
	s, ok := m.secrets[id]
	if !ok {
		return 0, types.ErrNotFound
	}
	if s.viewCount == nil || *s.viewCount == 0 {
		return types.UnlimitedViews, nil
	}
	remaining := *s.viewCount - 1
	if remaining == 0 {
		delete(m.secrets, id)
		return 0, nil
	}
	s.viewCount = &remaining
	return remaining, nil
}

func (m *mockSecretStore) DeleteSecret(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.record("delete") {
		return errMock
	}
	delete(m.secrets, id)
	return nil
}

// --- mockFileStore ---

type mockFileStore struct {
	mu    sync.Mutex
	files map[string][]byte
	// failOp forces the named operation to fail: store, get, delete.
	failOp string
	calls  []string
}

func newMockFileStore() *mockFileStore {
	return &mockFileStore{files: make(map[string][]byte)}
}

func (m *mockFileStore) has(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.files[id]
	return ok
}

func (m *mockFileStore) put(id string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[id] = data
}

func (m *mockFileStore) StoreEncryptedFile(ctx context.Context, id string, r io.Reader) error {
	data, readErr := io.ReadAll(r)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "store")
	if readErr != nil {
		return readErr
	}
	if m.failOp == "store" {
		return errMock
	}
	m.files[id] = data
	return nil
}

func (m *mockFileStore) GetEncryptedFile(ctx context.Context, id string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "get")
	if m.failOp == "get" {
		return nil, errMock
	}
	data, ok := m.files[id]
	if !ok {
		return nil, types.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *mockFileStore) DeleteEncryptedFile(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, "delete")
	if m.failOp == "delete" {
		return errMock
	}
	delete(m.files, id)
	return nil
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

// Parts go out in the order given, so tests can send malformed uploads.
func newMultipartContext(parts [][2]string) (echo.Context, *httptest.ResponseRecorder) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, part := range parts {
		field, err := w.CreateFormField(part[0])
		if err != nil {
			panic(err)
		}
		field.Write([]byte(part[1]))
	}
	w.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/encrypt_file", &body)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func filePayloadJSON(extra map[string]any) string {
	m := map[string]any{
		"passwordHash":      validHash,
		"encryptedMetadata": "bWV0YQ==",
		"nonce":             "bm9uY2U=",
		"header":            "aGVhZGVy",
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// decodeResponse unmarshals the response body into a map.
func decodeResponse(rec *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		return nil
	}
	return m
}
