package simple_crypt

import (
	"bytes"
	"testing"
)

func TestNewSecret(t *testing.T) {
	secret := NewSecret()

	if secret.SecretId == "" {
		t.Error("NewSecret() SecretId is empty")
	}
	if len(secret.SecretId) != 16 {
		t.Errorf("NewSecret() SecretId length = %v, want 16", len(secret.SecretId))
	}

	if secret.Passphrase == "" {
		t.Error("NewSecret() Passphrase is empty")
	}
	if len(secret.Passphrase) != 32 {
		t.Errorf("NewSecret() Passphrase length = %v, want 32", len(secret.Passphrase))
	}

	if len(secret.Nonce) != 12 {
		t.Errorf("NewSecret() Nonce length = %v, want 12", len(secret.Nonce))
	}

	if len(secret.Salt) != 16 {
		t.Errorf("NewSecret() Salt length = %v, want 16", len(secret.Salt))
	}

	if len(secret.Header) != 16 {
		t.Errorf("NewSecret() Header length = %v, want 16", len(secret.Header))
	}

	if secret.IsFile {
		t.Error("NewSecret() IsFile = true, want false")
	}
}

func TestSecret_EncryptDecrypt(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantErr  bool
		password string
	}{
		{
			name:     "Simple string",
			data:     []byte("Hello, World!"),
			wantErr:  false,
			password: "test-password",
		},
		{
			name:     "Empty string",
			data:     []byte(""),
			wantErr:  false,
			password: "test-password",
		},
		{
			name:     "Binary data",
			data:     []byte{0x00, 0xFF, 0x42, 0x13, 0x37},
			wantErr:  false,
			password: "test-password",
		},
		{
			name:     "Long string",
			data:     bytes.Repeat([]byte("a"), 1000),
			wantErr:  false,
			password: "test-password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecret()
			s.Passphrase = tt.password

			// Test encryption
			encrypted, err := s.Encrypt(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && encrypted == nil {
				t.Error("Secret.Encrypt() returned nil, want encrypted data")
				return
			}

			// Store encrypted data
			s.Data = encrypted

			// Test decryption
			decrypted, err := s.Decrypt()
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Compare original and decrypted data
			if !tt.wantErr && !bytes.Equal(decrypted, tt.data) {
				t.Errorf("Secret.Decrypt() = %v, want %v", decrypted, tt.data)
			}
		})
	}
}

func TestSecret_DecryptWithWrongPassword(t *testing.T) {
	original := []byte("Hello, World!")
	s := NewSecret()
	s.Passphrase = "correct-password"

	// Encrypt with correct password
	encrypted, err := s.Encrypt(original)
	if err != nil {
		t.Fatalf("Secret.Encrypt() error = %v", err)
	}
	s.Data = encrypted

	// Try to decrypt with wrong password
	s.Passphrase = "wrong-password"
	_, err = s.Decrypt()
	if err == nil {
		t.Error("Secret.Decrypt() with wrong password succeeded, want error")
	}
}

func TestSecret_EncryptDecryptWithDifferentNonce(t *testing.T) {
	original := []byte("Hello, World!")
	s := NewSecret()

	// Encrypt data
	encrypted, err := s.Encrypt(original)
	if err != nil {
		t.Fatalf("Secret.Encrypt() error = %v", err)
	}
	s.Data = encrypted

	// Change nonce
	originalNonce := make([]byte, len(s.Nonce))
	copy(originalNonce, s.Nonce)
	s.Nonce = make([]byte, len(originalNonce))

	// Try to decrypt with different nonce
	_, err = s.Decrypt()
	if err == nil {
		t.Error("Secret.Decrypt() with different nonce succeeded, want error")
	}
}
