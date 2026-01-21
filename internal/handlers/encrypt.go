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

// Validate checks if the E2EData is valid for the given operation
func (e *E2EData) Validate(isFile bool) error {
	if e.PasswordHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing password hash")
	}

	if !validatePasswordHash(e.PasswordHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid password hash format")
	}

	if isFile {
		if e.EncryptedFile != "" && len(e.EncryptedFile) > MaxFileSize {
			return echo.NewHTTPError(http.StatusBadRequest, "file size exceeds limit")
		}
	} else {
		if e.EncryptedData == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "missing encrypted data")
		}
		if len(e.EncryptedData) > MaxTextSize {
			return echo.NewHTTPError(http.StatusBadRequest, "text size exceeds limit")
		}
	}

	return nil
}

func EncryptString(c echo.Context) error {
	var data E2EData

	if err := c.Bind(&data); err != nil {
		return errorResponse(c, http.StatusBadRequest, "invalid request")
	}

	if err := data.Validate(false); err != nil {
		return err
	}

	return storeEncryptedData(c, &data, false)
}

func EncryptFile(c echo.Context) error {
	var data E2EData

	if err := c.Bind(&data); err != nil {
		return errorResponse(c, http.StatusBadRequest, "invalid request")
	}

	if err := data.Validate(true); err != nil {
		return err
	}

	if data.EncryptedFile != "" {
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
