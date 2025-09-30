package handlers

import (
	"net/http"
	"regexp"

	echo "github.com/labstack/echo/v4"
	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
)

const (
	MaxFileSize = 10 * 1024 * 1024
	MaxTextSize = 1 * 1024 * 1024
)

var (
	secretIDRegex     = regexp.MustCompile(`^[a-zA-Z0-9]{16}$`)
	passwordHashRegex = regexp.MustCompile(`^[a-f0-9]{64}$`)
	SanitizeViewCount = utils.SanitizeViewCount
	SanitizeTTL       = utils.SanitizeTTL
)

func errorResponse(c echo.Context, code int, message string) error {
	if code >= 500 {
		c.Logger().Error(message)
	}

	genericMessage := message
	if code == http.StatusInternalServerError {
		genericMessage = "An internal error occurred"
	}

	return c.JSON(code, map[string]string{"error": genericMessage})
}

func successResponse(c echo.Context, data map[string]string) error {
	return c.JSON(http.StatusOK, data)
}

func validateSecretID(id string) bool {
	return secretIDRegex.MatchString(id)
}

func validatePasswordHash(hash string) bool {
	return passwordHashRegex.MatchString(hash)
}
