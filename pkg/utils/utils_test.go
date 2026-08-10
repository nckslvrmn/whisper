package utils_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

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

// --- B64E / B64D ---

func TestB64E_URLEncoding(t *testing.T) {
	data := randBytes(128)
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
		randBytes(64),
		randBytes(100),
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

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
