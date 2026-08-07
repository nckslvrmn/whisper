package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/storage"
	"github.com/nckslvrmn/whisper/pkg/utils"
)

// The JSON part of an /encrypt_file upload only carries the metadata blob,
// which is a few hundred bytes.
const maxPayloadPart = 64 * 1024

type TextRequest struct {
	PasswordHash  string `json:"passwordHash"`
	EncryptedData string `json:"encryptedData"`
	Nonce         string `json:"nonce"`
	Header        string `json:"header"`
	ViewCount     *int   `json:"viewCount,omitempty"`
	TTL           *int64 `json:"ttl,omitempty"`
}

func (r *TextRequest) validate() error {
	if r.PasswordHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing password hash")
	}
	if !validatePasswordHash(r.PasswordHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid password hash format")
	}
	if r.EncryptedData == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing encrypted data")
	}
	if len(r.EncryptedData) > MaxTextSize() {
		return echo.NewHTTPError(http.StatusBadRequest, "text size exceeds limit")
	}
	if r.Nonce == "" || r.Header == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing nonce or header")
	}
	return validateLimits(r.ViewCount, r.TTL)
}

// FileRequest is the JSON "payload" part of a multipart /encrypt_file upload.
// The ciphertext itself is the separate "file" part.
type FileRequest struct {
	PasswordHash      string `json:"passwordHash"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	Nonce             string `json:"nonce"`
	Header            string `json:"header"`
	ViewCount         *int   `json:"viewCount,omitempty"`
	TTL               *int64 `json:"ttl,omitempty"`
}

func (r *FileRequest) validate() error {
	if r.PasswordHash == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing password hash")
	}
	if !validatePasswordHash(r.PasswordHash) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid password hash format")
	}
	if r.EncryptedMetadata == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing encrypted metadata")
	}
	if r.Nonce == "" || r.Header == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing nonce or header")
	}
	return validateLimits(r.ViewCount, r.TTL)
}

func EncryptString(c echo.Context) error {
	var req TextRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}
	if err := req.validate(); err != nil {
		return err
	}

	payload := SecretPayload{
		PasswordHash:  req.PasswordHash,
		EncryptedData: req.EncryptedData,
		Nonce:         req.Nonce,
		Header:        req.Header,
	}

	secretId := utils.RandString(16, true)
	if err := storeSecret(c, secretId, payload, req.TTL, req.ViewCount); err != nil {
		return err
	}

	return respondStored(c, secretId)
}

func EncryptFile(c echo.Context) error {
	ctx := c.Request().Context()

	parts, err := c.Request().MultipartReader()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "expected multipart/form-data")
	}

	req, err := readPayloadPart(parts)
	if err != nil {
		return err
	}
	if err := req.validate(); err != nil {
		return err
	}

	filePart, err := parts.NextPart()
	if err != nil || filePart.FormName() != "file" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing file part")
	}

	secretId := utils.RandString(16, true)
	fileStore := storage.GetFileStore()
	body := &limitedReader{r: filePart, limit: int64(MaxFileSize())}

	if err := fileStore.StoreEncryptedFile(ctx, secretId, body); err != nil {
		discardFile(c, secretId)
		if errors.Is(err, errFileTooLarge) {
			return echo.NewHTTPError(http.StatusBadRequest, "file size exceeds limit")
		}
		c.Logger().Error("error storing file: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error storing file")
	}

	if body.read == 0 {
		discardFile(c, secretId)
		return echo.NewHTTPError(http.StatusBadRequest, "empty file part")
	}

	if _, err := parts.NextPart(); !errors.Is(err, io.EOF) {
		discardFile(c, secretId)
		return echo.NewHTTPError(http.StatusBadRequest, "unexpected extra multipart part")
	}

	payload := SecretPayload{
		PasswordHash:      req.PasswordHash,
		EncryptedMetadata: req.EncryptedMetadata,
		Nonce:             req.Nonce,
		Header:            req.Header,
		IsFile:            true,
	}

	if err := storeSecret(c, secretId, payload, req.TTL, req.ViewCount); err != nil {
		discardFile(c, secretId)
		return err
	}

	return respondStored(c, secretId)
}

func readPayloadPart(parts *multipart.Reader) (*FileRequest, error) {
	part, err := parts.NextPart()
	if err != nil || part.FormName() != "payload" {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "missing payload part")
	}
	defer part.Close()

	raw, err := io.ReadAll(io.LimitReader(part, maxPayloadPart))
	if err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid payload part")
	}

	var req FileRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, echo.NewHTTPError(http.StatusBadRequest, "invalid payload part")
	}
	return &req, nil
}

func storeSecret(c echo.Context, secretId string, payload SecretPayload, ttl *int64, viewCount *int) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		c.Logger().Error("error serializing secret data: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error serializing secret data")
	}

	if err := storage.GetSecretStore().StoreSecret(c.Request().Context(), secretId, encoded, ttl, viewCount); err != nil {
		c.Logger().Error("error storing secret: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error storing secret")
	}

	return nil
}

// discardFile keeps a failed upload from leaving an object behind forever.
func discardFile(c echo.Context, secretId string) {
	if err := storage.GetFileStore().DeleteEncryptedFile(c.Request().Context(), secretId); err != nil {
		c.Logger().Error("error deleting orphaned file: ", err)
	}
}

func respondStored(c echo.Context, secretId string) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "success", "secretId": secretId})
}
