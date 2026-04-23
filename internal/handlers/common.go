package handlers

import (
	"regexp"

	"github.com/nckslvrmn/whisper/internal/config"
)

func MaxFileSize() int {
	return config.MaxFileSizeMB * 1024 * 1024
}

func MaxTextSize() int {
	return config.MaxTextSizeMB * 1024 * 1024
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
