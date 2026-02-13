package config

import (
	"os"
	"strconv"
)

var (
	ProjectName      string
	AdvancedFeatures bool
	Port             string
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

	Port = os.Getenv("PORT")
	if Port == "" {
		Port = "8081"
	}

	return nil
}
