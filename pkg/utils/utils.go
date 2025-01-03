package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strconv"
)

var AWSRegion string
var DynamoTable string
var FirestoreDatabase string
var GCPProjectID string
var GCSBucket string
var S3Bucket string
var TTLDays int
var UsesAWS bool
var UsesGCP bool

func LoadEnv() error {
	DynamoTable = os.Getenv("DYNAMO_TABLE")
	S3Bucket = os.Getenv("S3_BUCKET")
	UsesAWS = S3Bucket != "" && DynamoTable != ""

	FirestoreDatabase = os.Getenv("FIRESTORE_DATABASE")
	GCPProjectID = os.Getenv("GCP_PROJECT_ID")
	GCSBucket = os.Getenv("GCS_BUCKET")
	UsesGCP = GCPProjectID != "" && FirestoreDatabase != "" && GCSBucket != ""

	if !UsesAWS && !UsesGCP {
		return fmt.Errorf("missing required ENV vars - must provide either AWS (S3_BUCKET + DYNAMO_TABLE) or Google Cloud (GCP_PROJECT_ID + FIRESTORE_DATABASE + GCS_BUCKET) configuration")
	}

	// optional ENV vars
	AWSRegion = "us-east-1"
	if regionValue, regionExists := os.LookupEnv("AWS_REGION"); regionExists {
		AWSRegion = regionValue
	}

	TTLDays = 7
	if ttlValue, ttlExists := os.LookupEnv("TTL_DAYS"); ttlExists {
		TTLDays, _ = strconv.Atoi(ttlValue)
	}
	return nil
}

func SanitizeViewCount(view_count string) int {
	vc, err := strconv.ParseFloat(view_count, 64)
	if err != nil || vc <= 0 || vc >= 10 {
		return 1
	}
	return int(vc)
}

func RandString(length int, url_safe bool) string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if !url_safe {
		chars = chars + "!#$%&*+-=?@_~"
	}
	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		result[i] = chars[num.Int64()]
	}
	return string(result)
}

func RandBytes(length int) []byte {
	randomBytes := make([]byte, length)
	rand.Read(randomBytes)
	return randomBytes
}

func B64E(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func B64D(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}
