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
		return errorResponse(c, http.StatusBadRequest, "invalid request")
	}

	if requestData.SecretId == "" {
		return errorResponse(c, http.StatusBadRequest, "missing secret_id")
	}

	if !validateSecretID(requestData.SecretId) {
		return errorResponse(c, http.StatusBadRequest, "invalid secret_id format")
	}

	secretStore := storage.GetSecretStore()
	secretDataJson, err := secretStore.GetSecretRaw(requestData.SecretId)
	if err != nil {
		return errorResponse(c, http.StatusNotFound, "Secret not found or already viewed")
	}

	var secretData map[string]any
	if err := json.Unmarshal(secretDataJson, &secretData); err != nil {
		return errorResponse(c, http.StatusInternalServerError, "invalid secret data")
	}

	if requestData.GetSalt {
		return c.JSON(http.StatusOK, map[string]any{
			"salt": secretData["salt"],
		})
	}

	if requestData.PasswordHash == "" {
		return errorResponse(c, http.StatusNotFound, "Secret not found or already viewed")
	}

	if !validatePasswordHash(requestData.PasswordHash) {
		return errorResponse(c, http.StatusBadRequest, "invalid password hash format")
	}

	storedHash, ok := secretData["passwordHash"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(storedHash), []byte(requestData.PasswordHash)) != 1 {
		return errorResponse(c, http.StatusNotFound, "Secret not found or already viewed")
	}

	isFile, ok := secretData["isFile"].(bool)
	if !ok {
		isFile = false
	}
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

	viewCount, ok := secretData["viewCount"].(float64)
	if !ok {
		viewCount = 1
	}
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
			updatedJson, err := json.Marshal(secretData)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, "error updating secret")
			}
			secretStore.UpdateSecretRaw(requestData.SecretId, updatedJson)
		}
	}

	return c.JSON(http.StatusOK, response)
}
