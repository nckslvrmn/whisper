// Package client is a Go SDK for the whisper zero-knowledge secret-sharing
// service. It mirrors the Rust/WASM crypto module used by the web frontend,
// so secrets encrypted by the Go SDK can be decrypted in the browser and vice
// versa.
//
// # Quick start
//
//	c, err := client.New("https://whisper.example.com")
//	// handle err...
//	stored, err := c.StoreText(ctx, "my secret", &client.StoreOptions{
//	    ViewCount: client.Views(1),
//	    Expiry:    client.ExpireIn(24 * time.Hour),
//	})
//	// Share stored.URL and stored.DisplayPassphrase with the recipient.
//
//	got, err := c.Retrieve(ctx, stored.SecretID, stored.DisplayPassphrase)
//	fmt.Println(got.Text)
//
// # Crypto design
//
// Each secret is encrypted with XChaCha20-Poly1305 using a key derived as:
//
//	root     = Argon2id(passphrase, salt, m=64MiB, t=2, p=1, len=32)
//	enc_key  = HKDF-SHA256(root, salt, "whisper-encryption-v1", 32)
//	auth_key = HKDF-SHA256(root, salt, "whisper-auth-v1",       32)
//
// The server stores passwordHash = hex(auth_key) for authentication. The salt
// is never sent to the server — it is embedded in the display passphrase as
// its first 24 URL-safe-base64 characters. Compromising the server therefore
// does not by itself enable an offline Argon2 attack.
//
// For file secrets, the filename + content-type metadata is encrypted with a
// separate nonce (prepended to the metadata ciphertext) to avoid nonce reuse
// under the same key.
//
// A runnable end-to-end example lives at pkg/client/examples/basic; run it
// with `go run ./pkg/client/examples/basic -url https://whisper.example.com`.
//
// # Low-level API
//
// EncryptText, EncryptFile, DecryptText, DecryptFile, and HashPassword
// operate purely on bytes and can be used without the HTTP client, for
// example to encrypt payloads offline for delivery by other transport.
package client
