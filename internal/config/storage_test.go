package config_test

import (
	"os"
	"testing"

	"github.com/nckslvrmn/whisper/internal/config"
)

func clearStorageEnv() {
	for _, k := range []string{
		"DYNAMO_TABLE", "S3_BUCKET",
		"FIRESTORE_DATABASE", "GCP_PROJECT_ID", "GCS_BUCKET",
		"AWS_REGION", "DATA_DIR",
	} {
		os.Unsetenv(k)
	}
}

func TestLoadStorageConfig_Defaults(t *testing.T) {
	clearStorageEnv()

	if err := config.LoadStorageConfig(); err != nil {
		t.Fatalf("LoadStorageConfig: %v", err)
	}

	if config.UsesAWS {
		t.Error("UsesAWS should be false with no env vars")
	}
	if config.UsesGCP {
		t.Error("UsesGCP should be false with no env vars")
	}
	if config.AWSRegion != "us-east-1" {
		t.Errorf("AWSRegion = %q, want us-east-1", config.AWSRegion)
	}
	if config.DataDir != "/data" {
		t.Errorf("DataDir = %q, want /data", config.DataDir)
	}
}

func TestLoadStorageConfig_AWSEnabled(t *testing.T) {
	clearStorageEnv()
	os.Setenv("DYNAMO_TABLE", "my-table")
	os.Setenv("S3_BUCKET", "my-bucket")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if !config.UsesAWS {
		t.Error("UsesAWS should be true when DYNAMO_TABLE and S3_BUCKET are set")
	}
	if config.DynamoTable != "my-table" {
		t.Errorf("DynamoTable = %q, want my-table", config.DynamoTable)
	}
	if config.S3Bucket != "my-bucket" {
		t.Errorf("S3Bucket = %q, want my-bucket", config.S3Bucket)
	}
}

func TestLoadStorageConfig_AWSPartial_OnlyDynamo(t *testing.T) {
	clearStorageEnv()
	os.Setenv("DYNAMO_TABLE", "my-table")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if config.UsesAWS {
		t.Error("UsesAWS should be false when only DYNAMO_TABLE is set")
	}
}

func TestLoadStorageConfig_AWSPartial_OnlyS3(t *testing.T) {
	clearStorageEnv()
	os.Setenv("S3_BUCKET", "my-bucket")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if config.UsesAWS {
		t.Error("UsesAWS should be false when only S3_BUCKET is set")
	}
}

func TestLoadStorageConfig_GCPEnabled(t *testing.T) {
	clearStorageEnv()
	os.Setenv("GCP_PROJECT_ID", "my-project")
	os.Setenv("FIRESTORE_DATABASE", "my-db")
	os.Setenv("GCS_BUCKET", "my-gcs")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if !config.UsesGCP {
		t.Error("UsesGCP should be true when all GCP vars are set")
	}
	if config.GCPProjectID != "my-project" {
		t.Errorf("GCPProjectID = %q, want my-project", config.GCPProjectID)
	}
	if config.FirestoreDatabase != "my-db" {
		t.Errorf("FirestoreDatabase = %q, want my-db", config.FirestoreDatabase)
	}
	if config.GCSBucket != "my-gcs" {
		t.Errorf("GCSBucket = %q, want my-gcs", config.GCSBucket)
	}
}

func TestLoadStorageConfig_GCPPartial_MissingBucket(t *testing.T) {
	clearStorageEnv()
	os.Setenv("GCP_PROJECT_ID", "my-project")
	os.Setenv("FIRESTORE_DATABASE", "my-db")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if config.UsesGCP {
		t.Error("UsesGCP should be false when GCS_BUCKET is missing")
	}
}

func TestLoadStorageConfig_DataDirOverride(t *testing.T) {
	clearStorageEnv()
	os.Setenv("DATA_DIR", "/tmp/testdata")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if config.DataDir != "/tmp/testdata" {
		t.Errorf("DataDir = %q, want /tmp/testdata", config.DataDir)
	}
}

func TestLoadStorageConfig_AWSRegionOverride(t *testing.T) {
	clearStorageEnv()
	os.Setenv("AWS_REGION", "eu-west-1")
	defer clearStorageEnv()

	config.LoadStorageConfig()

	if config.AWSRegion != "eu-west-1" {
		t.Errorf("AWSRegion = %q, want eu-west-1", config.AWSRegion)
	}
}

func TestLoadStorageConfig_ReturnsNilError(t *testing.T) {
	err := config.LoadStorageConfig()
	if err != nil {
		t.Errorf("LoadStorageConfig returned non-nil error: %v", err)
	}
}
