package storage

import (
	"os"
	"testing"

	"github.com/nckslvrmn/go_ots/pkg/utils"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name      string
		envVars   map[string]string
		wantError bool
	}{
		{
			name: "AWS configuration",
			envVars: map[string]string{
				"DYNAMO_TABLE": "test-table",
				"S3_BUCKET":    "test-bucket",
				"AWS_REGION":   "us-west-2",
			},
			wantError: false,
		},
		{
			name: "GCP configuration",
			envVars: map[string]string{
				"FIRESTORE_DATABASE": "test-db",
				"GCP_PROJECT_ID":     "test-project",
				"GCS_BUCKET":         "test-bucket",
			},
			wantError: false,
		},
		{
			name:      "No configuration",
			envVars:   map[string]string{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment variables
			os.Clearenv()

			// Set test environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			// Load environment variables
			utils.LoadEnv()

			// Initialize storage
			err := Initialize()
			if (err != nil) != tt.wantError {
				t.Errorf("Initialize() error = %v, wantError %v", err, tt.wantError)
			}

			if !tt.wantError {
				// Check if stores are initialized
				if GetSecretStore() == nil {
					t.Error("GetSecretStore() returned nil")
				}
				if GetFileStore() == nil {
					t.Error("GetFileStore() returned nil")
				}
			}
		})
	}
}
