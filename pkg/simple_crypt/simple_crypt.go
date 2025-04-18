package simple_crypt

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/nckslvrmn/go_ots/pkg/utils"
	"golang.org/x/crypto/scrypt"
)

type Secret struct {
	Data       []byte
	Header     []byte
	IsFile     bool
	Nonce      []byte
	Passphrase string
	Salt       []byte
	SecretId   string
	TTL        int64
	ViewCount  int
}

func NewSecret() *Secret {
	return &Secret{
		SecretId:   utils.RandString(16, true),
		Passphrase: utils.RandString(32, false),
		Nonce:      utils.RandBytes(12),
		Salt:       utils.RandBytes(16),
		Header:     utils.RandBytes(16),
		IsFile:     false,
		TTL:        utils.SanitizeTTL("7"),
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
