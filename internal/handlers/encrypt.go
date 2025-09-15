package handlers

import (
	"encoding/json"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/secure_secret_share/internal/storage"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

// E2E encrypted data structure
type E2EData struct {
	PasswordHash      string `json:"passwordHash"`
	EncryptedData     string `json:"encryptedData"`
	EncryptedFile     string `json:"encryptedFile,omitempty"`
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	Nonce             string `json:"nonce"`
	Salt              string `json:"salt"`
	Header            string `json:"header"`
	ViewCount         int    `json:"viewCount"`
	TTL               int64  `json:"ttl"`
	IsFile            bool   `json:"isFile"`
}

func EncryptString(c echo.Context) error {
	var data E2EData
	
	err := c.Bind(&data)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	if data.PasswordHash == "" || data.EncryptedData == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing required fields"})
	}
	
	// Generate secret ID on the backend
	secretId := utils.RandString(16, true)

	secretData := map[string]interface{}{
		"passwordHash":      data.PasswordHash,
		"encryptedData":     data.EncryptedData,
		"encryptedMetadata": data.EncryptedMetadata,
		"nonce":             data.Nonce,
		"salt":              data.Salt,
		"header":            data.Header,
		"viewCount":         data.ViewCount,
		"ttl":               data.TTL,
		"isFile":            data.IsFile,
	}

	secretStore := storage.GetSecretStore()
	secretDataJson, _ := json.Marshal(secretData)
	
	if err := secretStore.StoreSecretRaw(secretId, secretDataJson, data.TTL, data.ViewCount); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "secretId": secretId})
}

func EncryptFile(c echo.Context) error {
	var data E2EData
	
	err := c.Bind(&data)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	if data.PasswordHash == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing required fields"})
	}
	
	// Generate secret ID on the backend
	secretId := utils.RandString(16, true)

	secretData := map[string]interface{}{
		"passwordHash":      data.PasswordHash,
		"encryptedData":     data.EncryptedData,
		"encryptedMetadata": data.EncryptedMetadata,
		"nonce":             data.Nonce,
		"salt":              data.Salt,
		"header":            data.Header,
		"viewCount":         data.ViewCount,
		"ttl":               data.TTL,
		"isFile":            true,
	}

	secretStore := storage.GetSecretStore()
	
	if data.EncryptedFile != "" {
		fileStore := storage.GetFileStore()
		if err := fileStore.StoreEncryptedFile(secretId, []byte(data.EncryptedFile)); err != nil {
			c.Logger().Error(err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing file"})
		}
	}

	secretDataJson, _ := json.Marshal(secretData)
	if err := secretStore.StoreSecretRaw(secretId, secretDataJson, data.TTL, data.ViewCount); err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "error storing secret"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "secretId": secretId})
}

