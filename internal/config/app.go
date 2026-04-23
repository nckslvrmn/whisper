package config

import (
	"os"
	"strconv"
)

var (
	ProjectName      string
	AdvancedFeatures bool
	Port             string
	MaxFileSizeMB    = 256
	MaxTextSizeMB    = 1
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

	MaxFileSizeMB = 256
	if sizeStr := os.Getenv("MAX_FILE_SIZE_MB"); sizeStr != "" {
		if parsed, err := strconv.Atoi(sizeStr); err == nil && parsed > 0 {
			MaxFileSizeMB = parsed
		}
	}

	MaxTextSizeMB = 1
	if sizeStr := os.Getenv("MAX_TEXT_SIZE_MB"); sizeStr != "" {
		if parsed, err := strconv.Atoi(sizeStr); err == nil && parsed > 0 {
			MaxTextSizeMB = parsed
		}
	}

	return nil
}
