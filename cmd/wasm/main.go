//go:build wasm
// +build wasm

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"syscall/js"

	"github.com/nckslvrmn/secure_secret_share/pkg/utils"
	"golang.org/x/crypto/scrypt"
)

func main() {
	js.Global().Set("wasmCrypto", map[string]interface{}{
		"encryptText":  js.FuncOf(encryptTextFunc),
		"encryptFile":  js.FuncOf(encryptFileFunc),
		"decryptText":  js.FuncOf(decryptTextFunc),
		"decryptFile":  js.FuncOf(decryptFileFunc),
		"hashPassword": js.FuncOf(hashPasswordFunc),
	})

	// Keep the program running for standard Go WASM
	select {}
}

func encryptTextFunc(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return map[string]interface{}{
			"error": "Missing arguments: text, viewCount, ttlDays",
		}
	}

	text := args[0].String()
	viewCount := args[1].String()
	ttlDays := args[2].String()

	secret := NewSecret()
	secret.ViewCount = utils.SanitizeViewCount(viewCount)
	secret.TTL = utils.SanitizeTTL(ttlDays)

	encryptedData, err := secret.Encrypt([]byte(text))
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	passwordHash := hashPasswordString(secret.Passphrase, secret.Salt)

	return map[string]interface{}{
		"passphrase":    secret.Passphrase,
		"encryptedData": utils.B64E(encryptedData),
		"nonce":         utils.B64E(secret.Nonce),
		"salt":          utils.B64E(secret.Salt),
		"header":        utils.B64E(secret.Header),
		"passwordHash":  passwordHash,
		"viewCount":     secret.ViewCount,
		"ttl":           secret.TTL,
	}
}

func encryptFileFunc(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return map[string]interface{}{
			"error": "Missing arguments: fileData, fileName, fileType",
		}
	}

	fileDataStr := args[0].String()
	fileName := args[1].String()
	fileType := args[2].String()

	fileData, err := base64.StdEncoding.DecodeString(fileDataStr)
	if err != nil {
		return map[string]interface{}{"error": "Invalid file data: " + err.Error()}
	}

	secret := NewSecret()
	secret.ViewCount = 1
	secret.IsFile = true

	encryptedFile, err := secret.Encrypt(fileData)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	metadata := map[string]string{
		"file_name": fileName,
		"file_type": fileType,
	}
	metadataJson, _ := json.Marshal(metadata)
	encryptedMetadata, err := secret.Encrypt(metadataJson)
	if err != nil {
		return map[string]interface{}{"error": err.Error()}
	}

	passwordHash := hashPasswordString(secret.Passphrase, secret.Salt)

	return map[string]interface{}{
		"passphrase":        secret.Passphrase,
		"encryptedFile":     utils.B64E(encryptedFile),
		"encryptedMetadata": utils.B64E(encryptedMetadata),
		"nonce":             utils.B64E(secret.Nonce),
		"salt":              utils.B64E(secret.Salt),
		"header":            utils.B64E(secret.Header),
		"passwordHash":      passwordHash,
		"viewCount":         secret.ViewCount,
		"ttl":               secret.TTL,
	}
}

func decryptTextFunc(this js.Value, args []js.Value) interface{} {
	if len(args) < 5 {
		return map[string]interface{}{
			"error": "Missing arguments: encryptedData, passphrase, nonce, salt, header",
		}
	}

	encryptedData, err := utils.B64D(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "Invalid encrypted data"}
	}

	passphrase := args[1].String()
	nonce, _ := utils.B64D(args[2].String())
	salt, _ := utils.B64D(args[3].String())
	header, _ := utils.B64D(args[4].String())

	secret := &Secret{
		Data:       encryptedData,
		Passphrase: passphrase,
		Nonce:      nonce,
		Salt:       salt,
		Header:     header,
	}

	decryptedData, err := secret.Decrypt()
	if err != nil {
		return map[string]interface{}{"error": "Decryption failed: " + err.Error()}
	}

	return map[string]interface{}{
		"data": string(decryptedData),
	}
}

func decryptFileFunc(this js.Value, args []js.Value) interface{} {
	if len(args) < 6 {
		return map[string]interface{}{
			"error": "Missing arguments: encryptedFile, encryptedMetadata, passphrase, nonce, salt, header",
		}
	}

	encryptedFile, err := utils.B64D(args[0].String())
	if err != nil {
		return map[string]interface{}{"error": "Invalid encrypted file"}
	}

	encryptedMetadata, err := utils.B64D(args[1].String())
	if err != nil {
		return map[string]interface{}{"error": "Invalid encrypted metadata"}
	}

	passphrase := args[2].String()
	nonce, _ := utils.B64D(args[3].String())
	salt, _ := utils.B64D(args[4].String())
	header, _ := utils.B64D(args[5].String())

	secret := &Secret{
		Data:       encryptedMetadata,
		Passphrase: passphrase,
		Nonce:      nonce,
		Salt:       salt,
		Header:     header,
	}

	metadataBytes, err := secret.Decrypt()
	if err != nil {
		return map[string]interface{}{"error": "Metadata decryption failed: " + err.Error()}
	}

	var metadata map[string]string
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return map[string]interface{}{"error": "Invalid metadata"}
	}

	secret.Data = encryptedFile
	fileData, err := secret.Decrypt()
	if err != nil {
		return map[string]interface{}{"error": "File decryption failed: " + err.Error()}
	}

	return map[string]interface{}{
		"fileData": base64.StdEncoding.EncodeToString(fileData),
		"fileName": metadata["file_name"],
		"fileType": metadata["file_type"],
	}
}

func hashPasswordFunc(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return map[string]interface{}{
			"error": "Missing arguments: password, salt",
		}
	}

	password := args[0].String()
	saltStr := args[1].String()

	salt, err := utils.B64D(saltStr)
	if err != nil {
		return map[string]interface{}{"error": "Invalid salt"}
	}

	return hashPasswordString(password, salt)
}

func hashPasswordString(password string, salt []byte) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	hash.Write(salt)
	return hex.EncodeToString(hash.Sum(nil))
}

type Secret struct {
	Header     []byte
	IsFile     bool
	Nonce      []byte
	Passphrase string
	Salt       []byte
	TTL        int64
	ViewCount  int
	Data       []byte
}

func NewSecret() *Secret {
	return &Secret{
		Passphrase: utils.RandString(32, false),
		Nonce:      utils.RandBytes(12),
		Salt:       utils.RandBytes(16),
		Header:     utils.RandBytes(16),
		IsFile:     false,
		TTL:        utils.SanitizeTTL("7"),
		Data:       nil,
	}
}

func (s *Secret) Encrypt(input_data []byte) ([]byte, error) {
	var ciphertext []byte
	aesGCM, err := s.setupCipher()
	ciphertext = aesGCM.Seal(ciphertext, s.Nonce, input_data, s.Header)
	return ciphertext, err
}

func (s *Secret) Decrypt() ([]byte, error) {
	var plaintext []byte
	aesGCM, err := s.setupCipher()
	if err != nil {
		return nil, err
	}
	plaintext, err = aesGCM.Open(plaintext, s.Nonce, s.Data, s.Header)
	return plaintext, err
}

func (s *Secret) setupCipher() (cipher.AEAD, error) {
	key, err := s.deriveKey()
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGCM, nil
}

func (s *Secret) deriveKey() ([]byte, error) {
	key, err := scrypt.Key([]byte(s.Passphrase), s.Salt, 2<<14, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return key, nil
}
