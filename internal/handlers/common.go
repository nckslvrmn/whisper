package handlers

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"time"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/whisper/internal/config"
)

func MaxFileSize() int {
	return config.MaxFileSizeMB * 1024 * 1024
}

func MaxTextSize() int {
	return config.MaxTextSizeMB * 1024 * 1024
}

const maxTTLWindow = 30 * 24 * time.Hour

// SecretPayload is the JSON blob stored for a secret. View count and TTL are
// storage-native columns, not payload fields, so the payload is immutable
// after creation.
type SecretPayload struct {
	PasswordHash      string `json:"passwordHash"`
	EncryptedData     string `json:"encryptedData,omitempty"`
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	Nonce             string `json:"nonce"`
	Header            string `json:"header"`
	IsFile            bool   `json:"isFile"`
}

var (
	secretIDRegex     = regexp.MustCompile(`^[a-zA-Z0-9]{16}$`)
	passwordHashRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func validateSecretID(id string) bool {
	return secretIDRegex.MatchString(id)
}

func validatePasswordHash(hash string) bool {
	return passwordHashRegex.MatchString(hash)
}

// validateLimits runs before any storage write, so a rejected request never
// reaches a backend.
func validateLimits(viewCount *int, ttl *int64) error {
	if !config.AdvancedFeatures && (ttl == nil || viewCount == nil) {
		return echo.NewHTTPError(http.StatusBadRequest, "advanced features are disabled")
	}

	if viewCount != nil && (*viewCount < 0 || *viewCount > 10) {
		return echo.NewHTTPError(http.StatusBadRequest, "view count must be between 0 and 10, where 0 means unlimited")
	}

	if ttl != nil {
		now := time.Now()
		if *ttl <= now.Unix() {
			return echo.NewHTTPError(http.StatusBadRequest, "TTL must be in the future")
		}
		if *ttl > now.Add(maxTTLWindow).Unix() {
			return echo.NewHTTPError(http.StatusBadRequest, "TTL cannot exceed 30 days")
		}
	}

	return nil
}

// errFileTooLarge aborts an in-flight upload once it passes the size limit.
// It travels back out of the file store, which wraps it.
var errFileTooLarge = errors.New("file size exceeds limit")

type limitedReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		return n, errFileTooLarge
	}
	return n, err
}
