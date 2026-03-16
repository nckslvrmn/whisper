package utils_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/nckslvrmn/whisper/pkg/utils"
)

// --- RandString ---

func TestRandString_Length(t *testing.T) {
	for _, l := range []int{1, 8, 16, 32, 64} {
		s := utils.RandString(l, true)
		if len(s) != l {
			t.Errorf("RandString(%d, true): got length %d", l, len(s))
		}
	}
}

func TestRandString_URLSafe_NoSpecialChars(t *testing.T) {
	const special = "!#$%&*+-=?@_~"
	for i := 0; i < 20; i++ {
		s := utils.RandString(64, true)
		for _, c := range special {
			if strings.ContainsRune(s, c) {
				t.Errorf("RandString urlSafe=true contains special char %q in %q", c, s)
			}
		}
	}
}

func TestRandString_NotURLSafe_ContainsSpecialEventually(t *testing.T) {
	const special = "!#$%&*+-=?@_~"
	found := false
	for i := 0; i < 100; i++ {
		s := utils.RandString(64, false)
		for _, c := range special {
			if strings.ContainsRune(s, c) {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("RandString urlSafe=false: no special chars found in 100 tries of 64-char strings")
	}
}

func TestRandString_Uniqueness(t *testing.T) {
	a := utils.RandString(32, true)
	b := utils.RandString(32, true)
	if a == b {
		t.Error("RandString returned identical 32-char strings (astronomically unlikely)")
	}
}

func TestRandString_AlphanumericOnly(t *testing.T) {
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	set := make(map[rune]bool)
	for _, c := range alnum {
		set[c] = true
	}
	for i := 0; i < 10; i++ {
		s := utils.RandString(128, true)
		for _, c := range s {
			if !set[c] {
				t.Errorf("unexpected char %q in urlSafe RandString result", c)
			}
		}
	}
}

// --- RandBytes ---

func TestRandBytes_Length(t *testing.T) {
	for _, l := range []int{0, 1, 16, 32, 64} {
		b := utils.RandBytes(l)
		if len(b) != l {
			t.Errorf("RandBytes(%d): got %d bytes", l, len(b))
		}
	}
}

func TestRandBytes_Uniqueness(t *testing.T) {
	a := utils.RandBytes(32)
	b := utils.RandBytes(32)
	same := true
	for i := range a {
		if a[i] != b[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("RandBytes returned identical 32-byte slices (highly unlikely)")
	}
}

// --- B64E / B64D ---

func TestB64E_URLEncoding(t *testing.T) {
	data := utils.RandBytes(128)
	got := utils.B64E(data)
	want := base64.URLEncoding.EncodeToString(data)
	if got != want {
		t.Errorf("B64E does not match base64.URLEncoding: got %q, want %q", got, want)
	}
}

func TestB64RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0},
		{0, 1, 2, 255},
		[]byte("hello world"),
		utils.RandBytes(64),
		utils.RandBytes(100),
	}
	for _, in := range cases {
		encoded := utils.B64E(in)
		decoded, err := utils.B64D(encoded)
		if err != nil {
			t.Errorf("B64D(%q) error: %v", encoded, err)
			continue
		}
		if string(decoded) != string(in) {
			t.Errorf("B64 round-trip mismatch for %v", in)
		}
	}
}

func TestB64D_InvalidInput(t *testing.T) {
	cases := []string{
		"not!!valid",
		"====",
		"short!!",
	}
	for _, s := range cases {
		_, err := utils.B64D(s)
		if err == nil {
			t.Errorf("B64D(%q) expected error, got nil", s)
		}
	}
}

// --- SanitizeViewCount ---

func TestSanitizeViewCount_ValidRange(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"1", 1},
		{"5", 5},
		{"10", 10},
	}
	for _, c := range cases {
		got := utils.SanitizeViewCount(c.in)
		if got != c.want {
			t.Errorf("SanitizeViewCount(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSanitizeViewCount_OutOfRange_DefaultsToOne(t *testing.T) {
	cases := []string{"0", "11", "-1", "100", "abc", "", "-99"}
	for _, s := range cases {
		got := utils.SanitizeViewCount(s)
		if got != 1 {
			t.Errorf("SanitizeViewCount(%q) = %d, want 1 (default)", s, got)
		}
	}
}

// --- SanitizeTTL ---

func TestSanitizeTTL_ValidDays(t *testing.T) {
	for _, days := range []string{"1", "3", "7", "14", "30"} {
		before := time.Now()
		ttl := utils.SanitizeTTL(days)
		after := time.Now()
		if ttl < before.Unix() || ttl > after.AddDate(0, 0, 31).Unix() {
			t.Errorf("SanitizeTTL(%q) = %d, out of expected range", days, ttl)
		}
	}
}

func TestSanitizeTTL_InvalidFallsBackToSevenDays(t *testing.T) {
	cases := []string{"0", "2", "5", "8", "99", "abc", ""}
	for _, s := range cases {
		before := time.Now()
		ttl := utils.SanitizeTTL(s)
		sevenDaysOut := before.AddDate(0, 0, 7).Unix()
		// Allow a few seconds of clock drift around the expected 7-day value
		if ttl < sevenDaysOut-5 || ttl > sevenDaysOut+5 {
			t.Errorf("SanitizeTTL(%q) = %d, expected ~%d (7 days from now)", s, ttl, sevenDaysOut)
		}
	}
}

func TestSanitizeTTL_ReturnsFutureTimestamp(t *testing.T) {
	now := time.Now().Unix()
	for _, days := range []string{"1", "3", "7", "14", "30"} {
		ttl := utils.SanitizeTTL(days)
		if ttl <= now {
			t.Errorf("SanitizeTTL(%q) = %d is not in the future (now = %d)", days, ttl, now)
		}
	}
}
