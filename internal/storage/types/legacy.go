package types

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
)

// sniffLen is how many bytes of a stored file are inspected to tell raw
// ciphertext from the base64 text written by older versions.
const sniffLen = 512

// DecodeStoredPayload returns the secret payload for a stored column value.
// Payloads are raw JSON; values written before that change are URL-safe
// base64, and the base64 alphabet cannot produce a leading '{'.
func DecodeStoredPayload(stored string) ([]byte, error) {
	if strings.HasPrefix(stored, "{") {
		return []byte(stored), nil
	}
	return base64.URLEncoding.DecodeString(stored)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// DecodeStoredFile returns a reader over the raw ciphertext of a stored file.
// Files are stored raw; older versions stored URL-safe base64 text, so the
// first sniffLen bytes decide which one this is. Raw XChaCha ciphertext
// staying inside the base64 alphabet for that many bytes has probability near
// zero.
func DecodeStoredFile(rc io.ReadCloser) (io.ReadCloser, error) {
	prefix := make([]byte, sniffLen)
	n, err := io.ReadFull(rc, prefix)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		rc.Close()
		return nil, err
	}
	prefix = prefix[:n]

	stream := io.MultiReader(bytes.NewReader(prefix), rc)
	if n == 0 || !isBase64Text(prefix) {
		return readCloser{Reader: stream, Closer: rc}, nil
	}
	return readCloser{Reader: base64.NewDecoder(base64.URLEncoding, stream), Closer: rc}, nil
}

func isBase64Text(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '=':
		default:
			return false
		}
	}
	return true
}
