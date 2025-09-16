package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"slices"
	"strconv"
	"time"
)

var AWSRegion string
var DynamoTable string
var FirestoreDatabase string
var GCPProjectID string
var GCSBucket string
var S3Bucket string
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

	return nil
}

func SanitizeViewCount(view_count string) int {
	vc, err := strconv.Atoi(view_count)
	if err != nil || vc <= 0 || vc >= 10 {
		return 1
	}
	return vc
}

func SanitizeTTL(ttl_in string) int64 {
	ttl, _ := strconv.Atoi(ttl_in)
	if !slices.Contains([]int{1, 3, 7, 14, 30}, ttl) {
		ttl = 7
	}
	return time.Now().AddDate(0, 0, ttl).Unix()
}

func RandString(length int, urlSafe bool) string {
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const special = "!#$%&*+-=?@_~"

	chars := alphaNum
	if !urlSafe {
		chars += special
	}

	result := make([]byte, length)
	charLen := big.NewInt(int64(len(chars)))
	for i := range result {
		num, _ := rand.Int(rand.Reader, charLen)
		result[i] = chars[num.Int64()]
	}
	return string(result)
}

func RandBytes(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func B64E(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func B64D(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}
