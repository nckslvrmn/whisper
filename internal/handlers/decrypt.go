package handlers

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/storage"
	"github.com/nckslvrmn/whisper/internal/storage/types"
)

const notFoundMessage = "Secret not found or already viewed"

type DecryptRequest struct {
	SecretId     string `json:"secret_id"`
	PasswordHash string `json:"passwordHash"`
}

func (r *DecryptRequest) validate() error {
	if r.SecretId == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing secret_id")
	}
	if !validateSecretID(r.SecretId) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid secret_id format")
	}
	if r.PasswordHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing password hash")
	}
	if !validatePasswordHash(r.PasswordHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid password hash format")
	}
	return nil
}

type TextResponse struct {
	EncryptedData string `json:"encryptedData"`
	Nonce         string `json:"nonce"`
	Header        string `json:"header"`
	IsFile        bool   `json:"isFile"`
}

func Decrypt(c echo.Context) error {
	ctx := c.Request().Context()

	var req DecryptRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}
	if err := req.validate(); err != nil {
		return err
	}

	secretStore := storage.GetSecretStore()
	encoded, ttl, err := secretStore.GetSecret(ctx, req.SecretId)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, notFoundMessage)
		}
		c.Logger().Error("error reading secret: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error reading secret")
	}

	var payload SecretPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		c.Logger().Error("error parsing secret data: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid secret data")
	}

	// Storage-layer cleanup is async and may lag, so expiry is enforced here too.
	if ttl != nil && *ttl > 0 && time.Now().Unix() > *ttl {
		purge(c, req.SecretId, payload.IsFile)
		return echo.NewHTTPError(http.StatusNotFound, notFoundMessage)
	}

	if subtle.ConstantTimeCompare([]byte(payload.PasswordHash), []byte(req.PasswordHash)) != 1 {
		return echo.NewHTTPError(http.StatusNotFound, notFoundMessage)
	}

	// The file reader is opened before the view is consumed so a storage
	// failure cannot burn a view without delivering anything.
	var file io.ReadCloser
	if payload.IsFile {
		file, err = storage.GetFileStore().GetEncryptedFile(ctx, req.SecretId)
		if err != nil {
			c.Logger().Error("error reading encrypted file: ", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "error reading encrypted file")
		}
		defer file.Close()
	}

	remaining, err := secretStore.ConsumeView(ctx, req.SecretId)
	if err != nil {
		if errors.Is(err, types.ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, notFoundMessage)
		}
		c.Logger().Error("error consuming view: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error consuming view")
	}

	if !payload.IsFile {
		return c.JSON(http.StatusOK, TextResponse{
			EncryptedData: payload.EncryptedData,
			Nonce:         payload.Nonce,
			Header:        payload.Header,
		})
	}

	header := c.Response().Header()
	header.Set("X-Whisper-Nonce", payload.Nonce)
	header.Set("X-Whisper-Header", payload.Header)
	header.Set("X-Whisper-Encrypted-Metadata", payload.EncryptedMetadata)
	header.Set("X-Whisper-Is-File", "true")

	streamErr := c.Stream(http.StatusOK, echo.MIMEOctetStream, file)

	// The view is spent either way, so a mid-stream client disconnect still
	// deletes the file rather than leaving it orphaned.
	if remaining == 0 {
		deleteFile(c, req.SecretId)
	}

	return streamErr
}

func purge(c echo.Context, secretId string, isFile bool) {
	if err := storage.GetSecretStore().DeleteSecret(c.Request().Context(), secretId); err != nil {
		c.Logger().Error("error deleting expired secret: ", err)
	}
	if isFile {
		deleteFile(c, secretId)
	}
}

func deleteFile(c echo.Context, secretId string) {
	fileStore := storage.GetFileStore()
	if fileStore == nil {
		return
	}
	// The request context may already be cancelled by a finished response.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request().Context()), 10*time.Second)
	defer cancel()

	if err := fileStore.DeleteEncryptedFile(ctx, secretId); err != nil {
		c.Logger().Error("error deleting encrypted file: ", err)
	}
}
