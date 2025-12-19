package handlers

import (
	"encoding/json"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/config"
	"github.com/nckslvrmn/whisper/internal/storage"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

type E2EData struct {
	PasswordHash      string `json:"passwordHash"`
	EncryptedData     string `json:"encryptedData"`
	EncryptedFile     string `json:"encryptedFile,omitempty"`
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	Nonce             string `json:"nonce"`
	Salt              string `json:"salt"`
	Header            string `json:"header"`
	ViewCount         *int   `json:"viewCount,omitempty"`
	TTL               *int64 `json:"ttl,omitempty"`
	IsFile            bool   `json:"isFile"`
}

func EncryptString(c echo.Context) error {
	var data E2EData

	err := c.Bind(&data)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "invalid request")
	}

	if data.PasswordHash == "" || data.EncryptedData == "" {
		return errorResponse(c, http.StatusBadRequest, "missing required fields")
	}

	if !validatePasswordHash(data.PasswordHash) {
		return errorResponse(c, http.StatusBadRequest, "invalid password hash format")
	}

	if len(data.EncryptedData) > MaxTextSize {
		return errorResponse(c, http.StatusBadRequest, "text size exceeds limit")
	}

	return storeEncryptedData(c, &data, false)
}

func EncryptFile(c echo.Context) error {
	var data E2EData

	err := c.Bind(&data)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, "invalid request")
	}

	if data.PasswordHash == "" {
		return errorResponse(c, http.StatusBadRequest, "missing required fields")
	}

	if !validatePasswordHash(data.PasswordHash) {
		return errorResponse(c, http.StatusBadRequest, "invalid password hash format")
	}

	if data.EncryptedFile != "" {
		if len(data.EncryptedFile) > MaxFileSize {
			return errorResponse(c, http.StatusBadRequest, "file size exceeds limit")
		}

		secretId := utils.RandString(16, true)
		fileStore := storage.GetFileStore()
		if err := fileStore.StoreEncryptedFile(secretId, []byte(data.EncryptedFile)); err != nil {
			return errorResponse(c, http.StatusInternalServerError, "error storing file")
		}
		return storeEncryptedDataWithId(c, &data, true, secretId)
	}

	return storeEncryptedData(c, &data, true)
}

func storeEncryptedData(c echo.Context, data *E2EData, isFile bool) error {
	return storeEncryptedDataWithId(c, data, isFile, utils.RandString(16, true))
}

func storeEncryptedDataWithId(c echo.Context, data *E2EData, isFile bool, secretId string) error {
	if !config.AdvancedFeatures {
		if data.TTL == nil || data.ViewCount == nil {
			return errorResponse(c, http.StatusBadRequest, "advanced features are disabled")
		}
	}

	secretData := map[string]any{
		"passwordHash":      data.PasswordHash,
		"encryptedData":     data.EncryptedData,
		"encryptedMetadata": data.EncryptedMetadata,
		"nonce":             data.Nonce,
		"salt":              data.Salt,
		"header":            data.Header,
		"isFile":            isFile,
	}

	if data.ViewCount != nil {
		secretData["viewCount"] = *data.ViewCount
	}
	if data.TTL != nil {
		secretData["ttl"] = *data.TTL
	}

	secretStore := storage.GetSecretStore()
	secretDataJson, err := json.Marshal(secretData)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, "error serializing secret data")
	}

	if err := secretStore.StoreSecretRaw(secretId, secretDataJson, data.TTL, data.ViewCount); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "error storing secret")
	}

	return successResponse(c, map[string]string{"status": "success", "secretId": secretId})
}
