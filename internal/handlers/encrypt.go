package handlers

import (
	"encoding/json"
	"net/http"
	"time"

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
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	if err := data.Validate(false); err != nil {
		return err
	}

	return storeEncryptedData(c, &data, false)
}

func EncryptFile(c echo.Context) error {
	var data E2EData

	if err := c.Bind(&data); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	if err := data.Validate(true); err != nil {
		return err
	}

	if data.EncryptedFile != "" {
		secretId := utils.RandString(16, true)
		fileStore := storage.GetFileStore()
		if err := fileStore.StoreEncryptedFile(secretId, []byte(data.EncryptedFile)); err != nil {
			c.Logger().Error("error storing file: ", err)
			return echo.NewHTTPError(http.StatusInternalServerError, "error storing file")
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
			return echo.NewHTTPError(http.StatusBadRequest, "advanced features are disabled")
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
		vc := *data.ViewCount
		if vc < 0 || vc > 10 {
			return echo.NewHTTPError(http.StatusBadRequest, "view count must be between 1 and 10")
		}
		if vc > 0 {
			// 0 means unlimited — don't store viewCount, no expiry-by-view.
			secretData["viewCount"] = vc
		}
	}
	if data.TTL != nil {
		now := time.Now().Unix()
		maxTTL := time.Now().Add(30 * 24 * time.Hour).Unix()
		if *data.TTL <= now {
			return echo.NewHTTPError(http.StatusBadRequest, "TTL must be in the future")
		}
		if *data.TTL > maxTTL {
			return echo.NewHTTPError(http.StatusBadRequest, "TTL cannot exceed 30 days")
		}
		secretData["ttl"] = *data.TTL
	}

	secretStore := storage.GetSecretStore()
	secretDataJson, err := json.Marshal(secretData)
	if err != nil {
		c.Logger().Error("error serializing secret data: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error serializing secret data")
	}

	if err := secretStore.StoreSecretRaw(secretId, secretDataJson, data.TTL, data.ViewCount); err != nil {
		c.Logger().Error("error storing secret: ", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "error storing secret")
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "success", "secretId": secretId})
}
