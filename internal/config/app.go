package config

import (
	"os"
	"strconv"
)

var (
	ProjectName      string
	AdvancedFeatures bool
)

func LoadAppConfig() error {
	ProjectName = os.Getenv("PROJECT_NAME")
	if ProjectName == "" {
		ProjectName = "Whisper"
	}

	AdvancedFeatures = false
	if advFeaturesStr := os.Getenv("ADVANCED_FEATURES"); advFeaturesStr != "" {
		if parsed, err := strconv.ParseBool(advFeaturesStr); err == nil {
			AdvancedFeatures = parsed
		}
	}

	return nil
}
