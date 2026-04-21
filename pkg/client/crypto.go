package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize     = 24
	SaltSize      = 16
	HeaderSize    = 16
	PassphraseLen = 32
	KeySize       = 32
	SaltB64Len    = 24

	argon2Memory  uint32 = 64 * 1024
	argon2Time    uint32 = 2
	argon2Threads uint8  = 1

	infoEnc  = "whisper-encryption-v1"
	infoAuth = "whisper-auth-v1"
)

const passphraseAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_~"

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Errorf("crypto/rand failed: %w", err))
	}
	return b
}

func randPassphrase(n int) string {
	charLen := len(passphraseAlphabet)
	acceptBelow := (256 / charLen) * charLen

	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			panic(fmt.Errorf("crypto/rand failed: %w", err))
		}
		for _, x := range buf {
			if int(x) < acceptBelow {
				out = append(out, passphraseAlphabet[int(x)%charLen])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}

func deriveKeys(passphrase string, salt []byte) (encKey, authKey []byte) {
	root := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, KeySize)
	prk := hkdf.Extract(sha256.New, root, salt)

	encKey = make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(infoEnc)), encKey); err != nil {
		panic(err)
	}

	authKey = make([]byte, KeySize)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte(infoAuth)), authKey); err != nil {
		panic(err)
	}
	return encKey, authKey
}

func xchachaSeal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func xchachaOpen(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// HashPassword derives the server-side auth hash from a passphrase + raw salt.
// Mirrors the hashPassword export of the WASM module.
func HashPassword(passphrase string, salt []byte) (string, error) {
	if len(salt) != SaltSize {
		return "", fmt.Errorf("invalid salt length: got %d, want %d", len(salt), SaltSize)
	}
	_, authKey := deriveKeys(passphrase, salt)
	return hex.EncodeToString(authKey), nil
}

// splitDisplayPassphrase decomposes the 56-char display passphrase returned by
// Encrypt{Text,File} into its embedded URL-safe base64 salt and the random
// passphrase suffix. Same split the JS frontend performs before decrypting.
func splitDisplayPassphrase(display string) (salt []byte, passphrase string, err error) {
	if len(display) < SaltB64Len+1 {
		return nil, "", errors.New("passphrase too short")
	}
	saltB64 := display[:SaltB64Len]
	passphrase = display[SaltB64Len:]
	salt, err = base64.URLEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid salt in passphrase: %w", err)
	}
	if len(salt) != SaltSize {
		return nil, "", fmt.Errorf("invalid salt length: got %d, want %d", len(salt), SaltSize)
	}
	return salt, passphrase, nil
}

// TextPayload is the wire payload for a text secret as sent to POST /encrypt.
// All byte-valued fields are URL-safe base64 (padded). PasswordHash is 64-char
// lowercase hex. ViewCount/TTL are omitted from the JSON when nil.
type TextPayload struct {
	PasswordHash  string `json:"passwordHash"`
	EncryptedData string `json:"encryptedData"`
	Nonce         string `json:"nonce"`
	Header        string `json:"header"`
	ViewCount     *int   `json:"viewCount,omitempty"`
	TTL           *int64 `json:"ttl,omitempty"`
	IsFile        bool   `json:"isFile"`
}

// FilePayload is the wire payload for a file secret as sent to POST /encrypt_file.
type FilePayload struct {
	PasswordHash      string `json:"passwordHash"`
	EncryptedFile     string `json:"encryptedFile"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	Nonce             string `json:"nonce"`
	Header            string `json:"header"`
	ViewCount         *int   `json:"viewCount,omitempty"`
	TTL               *int64 `json:"ttl,omitempty"`
	IsFile            bool   `json:"isFile"`
}

// DecryptResponse mirrors the JSON body returned by POST /decrypt.
type DecryptResponse struct {
	EncryptedData     string `json:"encryptedData"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	EncryptedFile     string `json:"encryptedFile,omitempty"`
	Nonce             string `json:"nonce"`
	Header            string `json:"header"`
	IsFile            bool   `json:"isFile"`
}

// EncryptText encrypts plaintext and produces a ready-to-POST payload plus the
// display passphrase the recipient needs to decrypt it. The salt is embedded
// in the passphrase and never leaves the caller — the server cannot assist an
// offline attack on the password hash.
func EncryptText(text string, viewCount *int, ttl *int64) (*TextPayload, string, error) {
	passphrase := randPassphrase(PassphraseLen)
	nonce := randBytes(NonceSize)
	salt := randBytes(SaltSize)
	header := randBytes(HeaderSize)

	encKey, authKey := deriveKeys(passphrase, salt)
	ct, err := xchachaSeal(encKey, nonce, header, []byte(text))
	if err != nil {
		return nil, "", fmt.Errorf("encrypt text: %w", err)
	}

	return &TextPayload{
		PasswordHash:  hex.EncodeToString(authKey),
		EncryptedData: base64.URLEncoding.EncodeToString(ct),
		Nonce:         base64.URLEncoding.EncodeToString(nonce),
		Header:        base64.URLEncoding.EncodeToString(header),
		ViewCount:     viewCount,
		TTL:           ttl,
		IsFile:        false,
	}, base64.URLEncoding.EncodeToString(salt) + passphrase, nil
}

// EncryptFile encrypts file data plus its filename/content-type metadata and
// produces a ready-to-POST payload plus the display passphrase.
func EncryptFile(name, contentType string, data []byte, viewCount *int, ttl *int64) (*FilePayload, string, error) {
	passphrase := randPassphrase(PassphraseLen)
	fileNonce := randBytes(NonceSize)
	salt := randBytes(SaltSize)
	header := randBytes(HeaderSize)

	encKey, authKey := deriveKeys(passphrase, salt)

	encFile, err := xchachaSeal(encKey, fileNonce, header, data)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt file: %w", err)
	}

	metaJSON, err := json.Marshal(map[string]string{
		"file_name": name,
		"file_type": contentType,
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal metadata: %w", err)
	}

	metaNonce := randBytes(NonceSize)
	encMetaRaw, err := xchachaSeal(encKey, metaNonce, header, metaJSON)
	if err != nil {
		return nil, "", fmt.Errorf("encrypt metadata: %w", err)
	}

	encMetaBlob := make([]byte, 0, len(metaNonce)+len(encMetaRaw))
	encMetaBlob = append(encMetaBlob, metaNonce...)
	encMetaBlob = append(encMetaBlob, encMetaRaw...)

	return &FilePayload{
		PasswordHash:      hex.EncodeToString(authKey),
		EncryptedFile:     base64.URLEncoding.EncodeToString(encFile),
		EncryptedMetadata: base64.URLEncoding.EncodeToString(encMetaBlob),
		Nonce:             base64.URLEncoding.EncodeToString(fileNonce),
		Header:            base64.URLEncoding.EncodeToString(header),
		ViewCount:         viewCount,
		TTL:               ttl,
		IsFile:            true,
	}, base64.URLEncoding.EncodeToString(salt) + passphrase, nil
}

// DecryptText decodes a DecryptResponse for a text secret using the display
// passphrase returned from EncryptText.
func DecryptText(resp *DecryptResponse, displayPassphrase string) (string, error) {
	if resp.IsFile {
		return "", errors.New("response is for a file secret; use DecryptFile")
	}
	salt, passphrase, err := splitDisplayPassphrase(displayPassphrase)
	if err != nil {
		return "", err
	}

	ct, err := base64.URLEncoding.DecodeString(resp.EncryptedData)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := decodeFixed(resp.Nonce, NonceSize, "nonce")
	if err != nil {
		return "", err
	}
	header, err := decodeFixed(resp.Header, HeaderSize, "header")
	if err != nil {
		return "", err
	}

	encKey, _ := deriveKeys(passphrase, salt)
	pt, err := xchachaOpen(encKey, nonce, header, ct)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(pt), nil
}

// DecryptedFile is the plaintext result of decrypting a file secret.
type DecryptedFile struct {
	Name        string
	ContentType string
	Data        []byte
}

// DecryptFile decodes a DecryptResponse for a file secret.
func DecryptFile(resp *DecryptResponse, displayPassphrase string) (*DecryptedFile, error) {
	if !resp.IsFile {
		return nil, errors.New("response is for a text secret; use DecryptText")
	}
	salt, passphrase, err := splitDisplayPassphrase(displayPassphrase)
	if err != nil {
		return nil, err
	}

	encFile, err := base64.URLEncoding.DecodeString(resp.EncryptedFile)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted file: %w", err)
	}
	encMetaBlob, err := base64.URLEncoding.DecodeString(resp.EncryptedMetadata)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted metadata: %w", err)
	}
	if len(encMetaBlob) <= NonceSize {
		return nil, errors.New("encrypted metadata too short")
	}
	nonce, err := decodeFixed(resp.Nonce, NonceSize, "nonce")
	if err != nil {
		return nil, err
	}
	header, err := decodeFixed(resp.Header, HeaderSize, "header")
	if err != nil {
		return nil, err
	}

	encKey, _ := deriveKeys(passphrase, salt)

	metaNonce := encMetaBlob[:NonceSize]
	encMeta := encMetaBlob[NonceSize:]

	metaBytes, err := xchachaOpen(encKey, metaNonce, header, encMeta)
	if err != nil {
		return nil, fmt.Errorf("decrypt metadata: %w", err)
	}
	var meta struct {
		FileName string `json:"file_name"`
		FileType string `json:"file_type"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}

	data, err := xchachaOpen(encKey, nonce, header, encFile)
	if err != nil {
		return nil, fmt.Errorf("decrypt file: %w", err)
	}

	return &DecryptedFile{
		Name:        meta.FileName,
		ContentType: meta.FileType,
		Data:        data,
	}, nil
}

func decodeFixed(s string, want int, field string) ([]byte, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("invalid %s length: got %d, want %d", field, len(b), want)
	}
	return b, nil
}
