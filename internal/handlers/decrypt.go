package handlers

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/secure_secret_share/internal/storage"
)

func Decrypt(c echo.Context) error {
	var requestData struct {
		SecretId     string `json:"secret_id"`
		PasswordHash string `json:"passwordHash"`
		GetSalt      bool   `json:"getSalt,omitempty"`
	}

	err := c.Bind(&requestData)
	if err != nil {
		c.Logger().Error(err)
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	if requestData.SecretId == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "missing secret_id"})
	}

	secretStore := storage.GetSecretStore()
	secretDataJson, err := secretStore.GetSecretRaw(requestData.SecretId)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "secret not found"})
	}

	var secretData map[string]any
	if err := json.Unmarshal(secretDataJson, &secretData); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "invalid secret data"})
	}

	// If only requesting salt for password hashing
	if requestData.GetSalt {
		return c.JSON(http.StatusOK, map[string]any{
			"salt": secretData["salt"],
		})
	}

	// Verify password hash
	if requestData.PasswordHash == "" {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "secret not found"})
	}

	storedHash, ok := secretData["passwordHash"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(storedHash), []byte(requestData.PasswordHash)) != 1 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "secret not found"})
	}

	isFile, _ := secretData["isFile"].(bool)
	response := map[string]any{
		"encryptedData":     secretData["encryptedData"],
		"encryptedMetadata": secretData["encryptedMetadata"],
		"nonce":             secretData["nonce"],
		"salt":              secretData["salt"],
		"header":            secretData["header"],
		"isFile":            isFile,
	}

	if isFile {
		fileStore := storage.GetFileStore()
		encryptedFile, err := fileStore.GetEncryptedFile(requestData.SecretId)
		if err == nil {
			response["encryptedFile"] = string(encryptedFile)
		}
	}

	// Handle view count
	viewCount, _ := secretData["viewCount"].(float64)
	if viewCount > 0 {
		viewCount--
		if viewCount == 0 {
			secretStore.DeleteSecret(requestData.SecretId)
			if isFile {
				fileStore := storage.GetFileStore()
				fileStore.DeleteFile(requestData.SecretId)
			}
		} else {
			secretData["viewCount"] = viewCount
			updatedJson, _ := json.Marshal(secretData)
			secretStore.UpdateSecretRaw(requestData.SecretId, updatedJson)
		}
	}

	return c.JSON(http.StatusOK, response)
}
