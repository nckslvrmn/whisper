package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a whisper server over HTTPS. The zero value is not usable;
// construct one with New.
type Client struct {
	// BaseURL is the origin of the whisper server, e.g. "https://whisper.example.com".
	// No trailing slash required.
	BaseURL string

	// HTTPClient is the underlying HTTP client. Defaults to a client with a
	// 30-second timeout; override to customise transport, timeouts, or auth.
	HTTPClient *http.Client
}

// New returns a Client configured to talk to baseURL.
func New(baseURL string) *Client {
	return &Client{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// StoreOptions configures TTL and view-count limits for a stored secret. Nil
// fields are omitted from the wire payload and the server applies its defaults.
// View-count 0 means "unlimited" (requires AdvancedFeatures on the server);
// an absent TTL means "never expire" (also AdvancedFeatures-only).
type StoreOptions struct {
	// ViewCount is the number of reads allowed before deletion. Valid: 1..10.
	// A pointer to 0 requests unlimited views (advanced-only).
	ViewCount *int

	// Expiry is the absolute time when the secret should be deleted. The
	// server caps this at 30 days from now.
	Expiry *time.Time
}

// StoredSecret is what the server returns after accepting a new secret.
type StoredSecret struct {
	// SecretID is the 16-character random ID issued by the server.
	SecretID string

	// DisplayPassphrase is the 56-character string the recipient needs to
	// decrypt the secret. It embeds the salt; treat it as sensitive.
	DisplayPassphrase string

	// URL is a convenience pre-rendered link of the form
	// <BaseURL>/secret/<SecretID>.
	URL string
}

// StoreText encrypts plaintext locally and stores it on the server. The
// returned StoredSecret contains the ID, display passphrase, and share URL.
func (c *Client) StoreText(ctx context.Context, text string, opts *StoreOptions) (*StoredSecret, error) {
	vc, ttl := resolveOptions(opts)
	payload, passphrase, err := EncryptText(text, vc, ttl)
	if err != nil {
		return nil, err
	}
	id, err := c.postEncrypt(ctx, "/encrypt", payload)
	if err != nil {
		return nil, err
	}
	return &StoredSecret{
		SecretID:          id,
		DisplayPassphrase: passphrase,
		URL:               c.BaseURL + "/secret/" + id,
	}, nil
}

// StoreFile encrypts the file bytes plus name and content-type metadata and
// stores them on the server.
func (c *Client) StoreFile(ctx context.Context, name, contentType string, data []byte, opts *StoreOptions) (*StoredSecret, error) {
	vc, ttl := resolveOptions(opts)
	payload, passphrase, err := EncryptFile(name, contentType, data, vc, ttl)
	if err != nil {
		return nil, err
	}
	id, err := c.postEncrypt(ctx, "/encrypt_file", payload)
	if err != nil {
		return nil, err
	}
	return &StoredSecret{
		SecretID:          id,
		DisplayPassphrase: passphrase,
		URL:               c.BaseURL + "/secret/" + id,
	}, nil
}

// Retrieved is the decrypted result of a Retrieve call. Exactly one of Text or
// File will be populated depending on IsFile.
type Retrieved struct {
	IsFile bool
	Text   string
	File   *DecryptedFile
}

// Retrieve fetches and decrypts the secret identified by secretID using the
// display passphrase returned from a previous Store call. Note that the server
// enforces view limits and TTL — calling Retrieve may delete the secret.
func (c *Client) Retrieve(ctx context.Context, secretID, displayPassphrase string) (*Retrieved, error) {
	salt, actualPassphrase, err := splitDisplayPassphrase(displayPassphrase)
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(actualPassphrase, salt)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{
		"secret_id":    secretID,
		"passwordHash": hash,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/decrypt", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}

	var decrypt DecryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&decrypt); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if decrypt.IsFile {
		f, err := DecryptFile(&decrypt, displayPassphrase)
		if err != nil {
			return nil, err
		}
		return &Retrieved{IsFile: true, File: f}, nil
	}
	text, err := DecryptText(&decrypt, displayPassphrase)
	if err != nil {
		return nil, err
	}
	return &Retrieved{Text: text}, nil
}

func (c *Client) postEncrypt(ctx context.Context, path string, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", apiError(resp)
	}

	var out struct {
		Status   string `json:"status"`
		SecretID string `json:"secretId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.SecretID == "" {
		return "", errors.New("server returned empty secretId")
	}
	return out.SecretID, nil
}

// APIError is returned for non-2xx responses from the whisper server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("whisper: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("whisper: HTTP %d: %s", e.StatusCode, e.Message)
}

func apiError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	msg := strings.TrimSpace(string(body))

	var echoErr struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &echoErr) == nil && echoErr.Message != "" {
		msg = echoErr.Message
	}
	return &APIError{StatusCode: resp.StatusCode, Message: msg}
}

func resolveOptions(opts *StoreOptions) (*int, *int64) {
	if opts == nil {
		return nil, nil
	}
	var ttl *int64
	if opts.Expiry != nil {
		ts := opts.Expiry.Unix()
		ttl = &ts
	}
	return opts.ViewCount, ttl
}

// Views is a convenience helper for building StoreOptions.
func Views(n int) *int { return &n }

// ExpireAt is a convenience helper for building StoreOptions.
func ExpireAt(t time.Time) *time.Time { return &t }

// ExpireIn is a convenience helper that returns now+d as a StoreOptions expiry.
func ExpireIn(d time.Duration) *time.Time {
	t := time.Now().Add(d)
	return &t
}
