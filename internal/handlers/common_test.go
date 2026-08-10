package handlers

import (
	"net/http"
	"testing"
	"time"

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
		"toolongabcdefghij", // 17 chars
		"abcdef!hijklmnop",  // special char
		"abcdef hijklmnop",  // space
		"abcdef/hijklmnop",  // slash
		"abcdef.hijklmnop",  // dot
		"../etc/passwd/foo",
		"abcdef\thijklmnop", // tab
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

// --- validateLimits ---

func TestValidateLimits_AdvancedOff_RequiresBoth(t *testing.T) {
	config.AdvancedFeatures = false
	defer func() { config.AdvancedFeatures = true }()

	ttl := time.Now().Add(time.Hour).Unix()
	vc := 1

	cases := map[string]struct {
		viewCount *int
		ttl       *int64
	}{
		"neither":         {nil, nil},
		"only view count": {&vc, nil},
		"only ttl":        {nil, &ttl},
	}
	for name, c := range cases {
		if err := validateLimits(c.viewCount, c.ttl); err == nil {
			t.Errorf("%s: expected an error when advanced features are disabled", name)
		}
	}

	if err := validateLimits(&vc, &ttl); err != nil {
		t.Errorf("both set: unexpected error %v", err)
	}
}

func TestValidateLimits_ViewCountRange(t *testing.T) {
	config.AdvancedFeatures = true

	for _, vc := range []int{0, 1, 5, 10} {
		if err := validateLimits(&vc, nil); err != nil {
			t.Errorf("viewCount %d: unexpected error %v", vc, err)
		}
	}
	for _, vc := range []int{-1, 11, 100} {
		err := validateLimits(&vc, nil)
		if err == nil {
			t.Errorf("viewCount %d: expected an error", vc)
		} else if he := err.(*echo.HTTPError); he.Code != http.StatusBadRequest {
			t.Errorf("viewCount %d: status = %d, want 400", vc, he.Code)
		}
	}
}

func TestValidateLimits_TTLRange(t *testing.T) {
	config.AdvancedFeatures = true

	past := time.Now().Add(-time.Minute).Unix()
	if err := validateLimits(nil, &past); err == nil {
		t.Error("expected an error for a TTL in the past")
	}

	tooFar := time.Now().Add(31 * 24 * time.Hour).Unix()
	if err := validateLimits(nil, &tooFar); err == nil {
		t.Error("expected an error for a TTL beyond 30 days")
	}

	ok := time.Now().Add(24 * time.Hour).Unix()
	if err := validateLimits(nil, &ok); err != nil {
		t.Errorf("unexpected error for a valid TTL: %v", err)
	}
}
