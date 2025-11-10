package config

import "os"

var (
	ProjectName string
)

func LoadAppConfig() error {
	ProjectName = os.Getenv("PROJECT_NAME")
	if ProjectName == "" {
		ProjectName = "Whisper"
	}

	return nil
}
