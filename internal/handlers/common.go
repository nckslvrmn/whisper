package handlers

import (
	"regexp"
)

const (
	MaxFileSize = 10 * 1024 * 1024
	MaxTextSize = 1 * 1024 * 1024
)

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
