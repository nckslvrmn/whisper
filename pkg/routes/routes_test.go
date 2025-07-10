package routes

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/nckslvrmn/secure_secret_share/pkg/simple_crypt"
	"github.com/nckslvrmn/secure_secret_share/pkg/storage"
	"github.com/nckslvrmn/secure_secret_share/pkg/storage/mock"
)

func setupTest() (*echo.Echo, *mock.MockSecretStore, *mock.MockFileStore) {
	e := echo.New()
	mockSecretStore := mock.NewMockSecretStore()
	mockFileStore := mock.NewMockFileStore()

	// Override the global storage with mocks
	storage.SetSecretStore(mockSecretStore)
	storage.SetFileStore(mockFileStore)

	return e, mockSecretStore, mockFileStore
}

func TestEncryptString(t *testing.T) {
	e, _, _ := setupTest()

	tests := []struct {
		name         string
		requestBody  map[string]string
		wantStatus   int
		wantResponse bool
	}{
		{
			name: "Valid request",
			requestBody: map[string]string{
				"secret":     "test secret",
				"view_count": "1",
				"ttl_days":   "7",
			},
			wantStatus:   http.StatusOK,
			wantResponse: true,
		},
		{
			name: "Invalid view count",
			requestBody: map[string]string{
				"secret":     "test secret",
				"view_count": "invalid",
				"ttl_days":   "7",
			},
			wantStatus:   http.StatusOK,
			wantResponse: true,
		},
		{
			name:         "Empty request",
			requestBody:  map[string]string{},
			wantStatus:   http.StatusBadRequest,
			wantResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/encrypt", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := EncryptString(c)
			if err != nil {
				t.Errorf("EncryptString() error = %v", err)
				return
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("EncryptString() status = %v, want %v", rec.Code, tt.wantStatus)
			}

			var response map[string]string
			json.Unmarshal(rec.Body.Bytes(), &response)

			if tt.wantResponse {
				if response["secret_id"] == "" {
					t.Error("EncryptString() secret_id is empty")
				}
				if response["passphrase"] == "" {
					t.Error("EncryptString() passphrase is empty")
				}
			}
		})
	}
}

func TestEncryptFile(t *testing.T) {
	e, _, _ := setupTest()

	tests := []struct {
		name       string
		fileData   string
		wantStatus int
	}{
		{
			name:       "Valid file",
			fileData:   "test file content",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := new(bytes.Buffer)
			writer := multipart.NewWriter(body)
			part, _ := writer.CreateFormFile("file", "test.txt")
			part.Write([]byte(tt.fileData))
			writer.Close()

			req := httptest.NewRequest(http.MethodPost, "/encrypt-file", body)
			req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := EncryptFile(c)
			if err != nil {
				t.Errorf("EncryptFile() error = %v", err)
				return
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("EncryptFile() status = %v, want %v", rec.Code, tt.wantStatus)
			}

			var response map[string]string
			json.Unmarshal(rec.Body.Bytes(), &response)

			if response["secret_id"] == "" {
				t.Error("EncryptFile() secret_id is empty")
			}
			if response["passphrase"] == "" {
				t.Error("EncryptFile() passphrase is empty")
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	e, mockSecretStore, mockFileStore := setupTest()

	// Create a test secret
	secret := simple_crypt.NewSecret()
	secret.Data, _ = secret.Encrypt([]byte("test secret"))
	mockSecretStore.StoreSecret(secret)

	// Create a test file secret
	fileSecret := simple_crypt.NewSecret()
	fileSecret.IsFile = true
	fileMetadata, _ := json.Marshal(map[string]string{
		"file_name": "test.txt",
		"file_type": "text/plain",
	})
	fileSecret.Data, _ = fileSecret.Encrypt(fileMetadata)
	mockSecretStore.StoreSecret(fileSecret)

	// Store encrypted file content
	fileContent := []byte("test file content")
	encryptedContent, _ := fileSecret.Encrypt(fileContent)
	mockFileStore.StoreEncryptedFile(fileSecret.SecretId, encryptedContent)

	tests := []struct {
		name         string
		requestBody  map[string]string
		wantStatus   int
		wantResponse bool
	}{
		{
			name: "Valid secret",
			requestBody: map[string]string{
				"secret_id":  secret.SecretId,
				"passphrase": secret.Passphrase,
			},
			wantStatus:   http.StatusOK,
			wantResponse: true,
		},
		{
			name: "Valid file secret",
			requestBody: map[string]string{
				"secret_id":  fileSecret.SecretId,
				"passphrase": fileSecret.Passphrase,
			},
			wantStatus:   http.StatusOK,
			wantResponse: true,
		},
		{
			name: "Invalid secret ID",
			requestBody: map[string]string{
				"secret_id":  "invalid",
				"passphrase": "invalid",
			},
			wantStatus:   http.StatusNotFound,
			wantResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/decrypt", bytes.NewBuffer(jsonBody))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := Decrypt(c)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("Decrypt() status = %v, want %v", rec.Code, tt.wantStatus)
			}

			if tt.wantResponse {
				if strings.Contains(rec.Header().Get(echo.HeaderContentType), echo.MIMEApplicationJSON) {
					var response map[string]interface{}
					json.Unmarshal(rec.Body.Bytes(), &response)
					if response["data"] == nil {
						t.Error("Decrypt() data is nil")
					}
				} else {
					if rec.Body.Len() == 0 {
						t.Error("Decrypt() file content is empty")
					}
				}
			}
		})
	}
}
