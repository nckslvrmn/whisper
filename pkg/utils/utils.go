package utils

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"slices"
	"strconv"
	"time"
)

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

func SanitizeViewCount(viewCount string) int {
	vc, err := strconv.Atoi(viewCount)
	if err != nil || vc <= 0 || vc >= 10 {
		return 1
	}
	return vc
}

func SanitizeTTL(ttlIn string) int64 {
	ttl, _ := strconv.Atoi(ttlIn)
	if !slices.Contains([]int{1, 3, 7, 14, 30}, ttl) {
		ttl = 7
	}
	return time.Now().AddDate(0, 0, ttl).Unix()
}
