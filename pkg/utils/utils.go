package utils

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
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

func B64E(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func B64D(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data)
}
