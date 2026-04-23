package handlers

import (
	"net/http"
	"testing"

	echo "github.com/labstack/echo/v4"

	"github.com/nckslvrmn/whisper/internal/config"
)

// --- validateSecretID ---

func TestValidateSecretID_Valid(t *testing.T) {
	cases := []string{
		"abcdefghijklmnop",
		"ABCDEFGHIJKLMNOP",
		"1234567890abcdef",
		"aBcDeFgHiJkLmNoP",
		"0000000000000000",
	}
	for _, s := range cases {
		if !validateSecretID(s) {
			t.Errorf("validateSecretID(%q) = false, want true", s)
		}
	}
}

func TestValidateSecretID_Invalid(t *testing.T) {
	cases := []string{
		"",
		"tooshort",
		"toolongabcdefghij",       // 17 chars
		"abcdef!hijklmnop",        // special char
		"abcdef hijklmnop",        // space
		"abcdef/hijklmnop",        // slash
		"abcdef.hijklmnop",        // dot
		"../etc/passwd/foo",
		"abcdef\thijklmnop",       // tab
	}
	for _, s := range cases {
		if validateSecretID(s) {
			t.Errorf("validateSecretID(%q) = true, want false", s)
		}
	}
}

// --- validatePasswordHash ---

func TestValidatePasswordHash_Valid(t *testing.T) {
	cases := []string{
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	for _, s := range cases {
		if !validatePasswordHash(s) {
			t.Errorf("validatePasswordHash(%q) = false, want true", s)
		}
	}
}

func TestValidatePasswordHash_Invalid(t *testing.T) {
	cases := []string{
		"",
		"short",
		// uppercase — not allowed (must be lowercase hex)
		"ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
		// 63 chars (too short)
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789",
		// 65 chars (too long)
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678900",
		// 'g' is not a valid hex digit
		"abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789g",
	}
	for _, s := range cases {
		if validatePasswordHash(s) {
			t.Errorf("validatePasswordHash(%q) = true, want false", s)
		}
	}
}

// --- E2EData.Validate ---

func TestE2EDataValidate_MissingPasswordHash(t *testing.T) {
	d := &E2EData{EncryptedData: "somedata"}
	err := d.Validate(false)
	if err == nil {
		t.Fatal("expected error for missing passwordHash")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestE2EDataValidate_InvalidPasswordHashFormat(t *testing.T) {
	d := &E2EData{PasswordHash: "tooshort", EncryptedData: "somedata"}
	err := d.Validate(false)
	if err == nil {
		t.Fatal("expected error for invalid passwordHash")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestE2EDataValidate_Text_MissingEncryptedData(t *testing.T) {
	d := &E2EData{PasswordHash: validHash}
	err := d.Validate(false)
	if err == nil {
		t.Fatal("expected error for missing encryptedData")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestE2EDataValidate_Text_ExceedsLimit(t *testing.T) {
	d := &E2EData{
		PasswordHash:  validHash,
		EncryptedData: string(make([]byte, MaxTextSize()+1)),
	}
	err := d.Validate(false)
	if err == nil {
		t.Fatal("expected error for text size exceeding limit")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestE2EDataValidate_Text_AtExactLimit(t *testing.T) {
	d := &E2EData{
		PasswordHash:  validHash,
		EncryptedData: string(make([]byte, MaxTextSize())),
	}
	if err := d.Validate(false); err != nil {
		t.Errorf("unexpected error at exact text limit: %v", err)
	}
}

func TestE2EDataValidate_File_ExceedsLimit(t *testing.T) {
	orig := config.MaxFileSizeMB
	config.MaxFileSizeMB = 1
	defer func() { config.MaxFileSizeMB = orig }()

	d := &E2EData{
		PasswordHash:  validHash,
		EncryptedFile: string(make([]byte, MaxFileSize()+1)),
	}
	err := d.Validate(true)
	if err == nil {
		t.Fatal("expected error for file size exceeding limit")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Errorf("expected 400 HTTPError, got %v", err)
	}
}

func TestE2EDataValidate_File_AtExactLimit(t *testing.T) {
	orig := config.MaxFileSizeMB
	config.MaxFileSizeMB = 1
	defer func() { config.MaxFileSizeMB = orig }()

	d := &E2EData{
		PasswordHash:  validHash,
		EncryptedFile: string(make([]byte, MaxFileSize())),
	}
	if err := d.Validate(true); err != nil {
		t.Errorf("unexpected error at exact file limit: %v", err)
	}
}

func TestE2EDataValidate_File_NoFilePresent(t *testing.T) {
	// File with no EncryptedFile set is valid (file may be stored separately)
	d := &E2EData{PasswordHash: validHash}
	if err := d.Validate(true); err != nil {
		t.Errorf("unexpected error for valid file E2EData: %v", err)
	}
}

func TestE2EDataValidate_Text_Valid(t *testing.T) {
	d := &E2EData{
		PasswordHash:  validHash,
		EncryptedData: "dGVzdA==",
		Nonce:         "bm9uY2U=",
		Header:        "aGVhZGVy",
	}
	if err := d.Validate(false); err != nil {
		t.Errorf("unexpected error for valid text E2EData: %v", err)
	}
}
