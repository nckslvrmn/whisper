package config

import "os"

var (
	AWSRegion         string
	DynamoTable       string
	FirestoreDatabase string
	GCPProjectID      string
	GCSBucket         string
	S3Bucket          string
	UsesAWS           bool
	UsesGCP           bool
)

func LoadStorageConfig() error {
	DynamoTable = os.Getenv("DYNAMO_TABLE")
	S3Bucket = os.Getenv("S3_BUCKET")
	UsesAWS = S3Bucket != "" && DynamoTable != ""

	FirestoreDatabase = os.Getenv("FIRESTORE_DATABASE")
	GCPProjectID = os.Getenv("GCP_PROJECT_ID")
	GCSBucket = os.Getenv("GCS_BUCKET")
	UsesGCP = GCPProjectID != "" && FirestoreDatabase != "" && GCSBucket != ""

	// optional ENV vars
	AWSRegion = "us-east-1"
	if regionValue, regionExists := os.LookupEnv("AWS_REGION"); regionExists {
		AWSRegion = regionValue
	}

	return nil
}
