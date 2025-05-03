package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/nckslvrmn/go_ots/pkg/utils"
)

func generateFakePEMKey() (string, error) {
	// Generate a new RSA private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	// Marshal to PKCS8 ASN.1 DER
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

func TestInitialize(t *testing.T) {
	// Generate a real PEM key
	pemKey, err := generateFakePEMKey()
	if err != nil {
		t.Fatalf("failed to generate fake PEM key: %v", err)
	}

	fakeCreds := map[string]string{
		"type":                        "service_account",
		"project_id":                  "test-project",
		"private_key_id":              "fakekeyid",
		"private_key":                 pemKey,
		"client_email":                "test@test-project.iam.gserviceaccount.com",
		"client_id":                   "fakeclientid",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/test@test-project.iam.gserviceaccount.com",
	}
	credsBytes, _ := json.Marshal(fakeCreds)
	os.WriteFile("/tmp/fake_creds.json", credsBytes, 0644)

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
				"FIRESTORE_DATABASE":             "test-db",
				"GCP_PROJECT_ID":                 "test-project",
				"GCS_BUCKET":                     "test-bucket",
				"GOOGLE_APPLICATION_CREDENTIALS": "/tmp/fake_creds.json",
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
