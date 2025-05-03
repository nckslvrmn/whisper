package utils

import (
	"os"
	"testing"
	"time"
)

func TestLoadEnv(t *testing.T) {
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

			err := LoadEnv()
			if (err != nil) != tt.wantError {
				t.Errorf("LoadEnv() error = %v, wantError %v", err, tt.wantError)
			}

			if !tt.wantError {
				if tt.envVars["AWS_REGION"] != "" && AWSRegion != tt.envVars["AWS_REGION"] {
					t.Errorf("LoadEnv() AWSRegion = %v, want %v", AWSRegion, tt.envVars["AWS_REGION"])
				}
			}
		})
	}
}

func TestSanitizeViewCount(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Valid number 1", "1", 1},
		{"Valid number 5", "5", 5},
		{"Invalid number 0", "0", 1},
		{"Invalid number 10", "10", 1},
		{"Invalid string", "invalid", 1},
		{"Empty string", "", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeViewCount(tt.input); got != tt.expected {
				t.Errorf("SanitizeViewCount() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSanitizeTTL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"Valid TTL 1", "1", 1},
		{"Valid TTL 3", "3", 3},
		{"Valid TTL 7", "7", 7},
		{"Valid TTL 14", "14", 14},
		{"Valid TTL 30", "30", 30},
		{"Invalid TTL", "8", 7},
		{"Invalid string", "invalid", 7},
		{"Empty string", "", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeTTL(tt.input)
			// Convert the Unix timestamp back to days, accounting for partial days
			days := int((time.Unix(got, 0).Sub(time.Now()).Hours() + 12) / 24)
			if days != tt.expected {
				t.Errorf("SanitizeTTL() = %v days, want %v days", days, tt.expected)
			}
		})
	}
}

func TestRandString(t *testing.T) {
	tests := []struct {
		name     string
		length   int
		urlSafe  bool
		wantLen  int
		wantSafe bool
	}{
		{"URL safe string 10", 10, true, 10, true},
		{"Non-URL safe string 20", 20, false, 20, false},
		{"Empty string", 0, true, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RandString(tt.length, tt.urlSafe)
			if len(got) != tt.wantLen {
				t.Errorf("RandString() length = %v, want %v", len(got), tt.wantLen)
			}

			if tt.urlSafe {
				for _, c := range got {
					if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
						t.Errorf("RandString() contains non-URL safe character: %c", c)
					}
				}
			}
		})
	}
}

func TestRandBytes(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantLen int
	}{
		{"10 bytes", 10, 10},
		{"32 bytes", 32, 32},
		{"Empty bytes", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RandBytes(tt.length)
			if len(got) != tt.wantLen {
				t.Errorf("RandBytes() length = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}

func TestB64E_B64D(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty string", []byte("")},
		{"Simple string", []byte("Hello, World!")},
		{"Binary data", []byte{0x00, 0xFF, 0x42, 0x13, 0x37}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := B64E(tt.input)
			decoded, err := B64D(encoded)
			if err != nil {
				t.Errorf("B64D() error = %v", err)
				return
			}
			if string(decoded) != string(tt.input) {
				t.Errorf("B64D(B64E()) = %v, want %v", decoded, tt.input)
			}
		})
	}
}
