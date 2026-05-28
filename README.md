# Whisper

> End-to-end encrypted secret sharing with WebAssembly-powered client-side encryption. Share sensitive info with a true zero-knowledge architecture, so your secrets are encrypted in your browser before they ever leave your device.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.23-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/nckslvrmn/whisper)](LICENSE)
[![Security](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-green?logo=shield)](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-blue)](https://en.wikipedia.org/wiki/Argon2)
[![WASM](https://img.shields.io/badge/WASM-Rust-orange?logo=webassembly)](https://webassembly.org/)

## Features

- **True end-to-end encryption.** All encryption and decryption happens in your browser via a Rust-compiled WebAssembly module.
- **XChaCha20-Poly1305.** Authenticated encryption with 192-bit nonces, so there's no nonce-reuse risk.
- **Argon2id + HKDF key splitting.** A memory-hard KDF with separate encryption and authentication keys derived via HKDF-SHA256.
- **Salt-in-passphrase architecture.** The Argon2 salt is embedded in the display passphrase and never stored or transmitted to the server, so the server cannot mount an offline brute-force attack even if it's compromised.
- **Self-destructing secrets.** Configurable view limits and TTL expiry.
- **Text and file support.** Share passwords, API keys, documents, or any sensitive file. The default limit is 256 MB, configurable via `MAX_FILE_SIZE_MB`.
- **Multi-storage backend.** AWS (DynamoDB + S3), Google Cloud (Firestore + GCS), or local SQLite + filesystem.
- **Zero server trust.** The server stores only ciphertext, nonce, header, and a 64-hex-char HKDF-derived auth key. Plaintext and encryption keys never leave the browser.
- **Hardened CSP.** No `unsafe-inline` for scripts, WASM permitted via `wasm-unsafe-eval` only, and SRI hashes on all CDN resources. Inline styles are still allowed (`style-src 'unsafe-inline'`).

## Quick Start

### Docker Compose

`compose.yml` in the repo root is the canonical deployment config. It defaults to the AWS backend, and the comments inside show how to switch to Google Cloud or local storage.

```bash
docker compose up -d
```

### Build from Source

Prerequisites: Go >= 1.23, the Rust toolchain with the `wasm32-unknown-unknown` target, and `wasm-bindgen-cli` 0.2.113. `wasm-opt` (binaryen) and `brotli` are optional and used to shrink and precompress the WASM artifact if they're present.

```bash
git clone https://github.com/nckslvrmn/whisper.git
cd whisper

# Build the Rust WASM crypto module
make wasm

# Build the Go server
make server

# Or build the Docker image (handles both steps)
docker build -t whisper .
```

`make wasm` builds the crate with `cargo build --release --target wasm32-unknown-unknown`, runs `wasm-bindgen --target web` to generate `crypto.js` and `crypto_bg.wasm` into `web/static/`, then optionally optimizes with `wasm-opt` and precompresses with `gzip` and `brotli`. The Dockerfile pins `wasm-bindgen-cli` at 0.2.113 for reproducibility.

## Configuration

### Environment Variables

#### General

| Variable | Required | Description |
|----------|:--------:|-------------|
| `PROJECT_NAME` | No | Display name in the UI (default: `Whisper`) |
| `PORT` | No | HTTP listen port (default: `8081`) |
| `ADVANCED_FEATURES` | No | Enable user-configurable view count and TTL in the UI (default: `false`). When disabled, `viewCount` and `ttl` are required on every request |
| `MAX_FILE_SIZE_MB` | No | Max encrypted file size and HTTP body limit, in MB (default: `256`) |
| `MAX_TEXT_SIZE_MB` | No | Max encrypted text payload, in MB (default: `1`) |

#### AWS

| Variable | Required | Description |
|----------|:--------:|-------------|
| `DYNAMO_TABLE` | Yes | DynamoDB table name |
| `S3_BUCKET` | Yes | S3 bucket name for encrypted files |
| `AWS_REGION` | No | AWS region (default: `us-east-1`) |

#### Google Cloud

| Variable | Required | Description |
|----------|:--------:|-------------|
| `GCP_PROJECT_ID` | Yes | Google Cloud project ID |
| `FIRESTORE_DATABASE` | Yes | Firestore database name |
| `GCS_BUCKET` | Yes | Cloud Storage bucket name |

#### Local Storage (default fallback)

| Variable | Required | Description |
|----------|:--------:|-------------|
| `DATA_DIR` | No | Directory for the SQLite database and encrypted files (default: `/data`) |

Mount a volume at `DATA_DIR` to persist the SQLite database and encrypted files. Storage priority is AWS, then Google Cloud, then Local.

## Authentication

### AWS

Use IAM roles (recommended), environment variables (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`), or the default credential chain.

Required IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/YOUR_TABLE_NAME"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/*"
    }
  ]
}
```

### Google Cloud

Set `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file, or rely on Application Default Credentials in GCP environments.

Required roles: `roles/datastore.user`, `roles/storage.objectAdmin`.

## Cryptographic Design

### WASM Module (Rust)

The crypto module lives in `wasm/src/lib.rs` and is compiled to WASM via `wasm-bindgen`. It exports five functions to JavaScript:

| Export | Purpose |
|--------|---------|
| `encryptText(text, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a text secret |
| `encryptFile(fileDataB64, fileName, fileType, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a file plus metadata |
| `decryptText(encryptedDataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a text secret |
| `decryptFile(encryptedFileB64, encryptedMetadataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a file plus metadata |
| `hashPassword(password, saltB64)` | Derive the auth key for a given passphrase and salt |

### Key Derivation

```
passphrase (32 random chars)
    │
    ▼
Argon2id(passphrase, salt, m=64MB, t=2, p=1) ──► root_key (32 bytes)
    │
    ▼
HKDF-SHA256(root_key, salt)
    ├──► enc_key  (label "whisper-encryption-v1")   used for XChaCha20-Poly1305
    └──► auth_key (label "whisper-auth-v1")          hex-encoded and stored as passwordHash
```

**Why two keys?** The original Go implementation derived one key from scrypt and used it for both encryption *and* as the server-side authentication hash. That meant the server effectively held the encryption key. HKDF splits the root into two independent 32-byte keys, so the server's `passwordHash` reveals nothing about `enc_key`.

### Encryption

- **Algorithm**: XChaCha20-Poly1305 (192-bit nonce, 128-bit Poly1305 tag)
- **Nonce**: 24 random bytes per secret, stored alongside the ciphertext
- **Header**: 16 random bytes used as Additional Authenticated Data (AAD). It's stored alongside the ciphertext and prevents cross-context ciphertext reuse.
- **File metadata**: Encrypted separately with its *own* random nonce (`meta_nonce`) prepended to the metadata ciphertext blob. This eliminates the nonce-reuse vulnerability present in the original Go implementation, which used the same nonce for both file data and metadata under AES-GCM.

### Salt-in-Passphrase Architecture

The Argon2 salt (16 random bytes) is **never stored or transmitted to the server**. Instead, it's embedded directly in the display passphrase that users share:

```
display_passphrase = URL_SAFE_BASE64(salt) [24 chars] + random_chars [32 chars]
                     └─────────────────────────────────────────────────────────┘
                                         56 chars total
```

When decrypting, the browser splits the display passphrase at character 24 to recover the salt and the actual Argon2 passphrase. No pre-flight request to the server is needed, so decryption is a single round-trip.

**Security consequence**: An attacker who compromises the server's database gets `passwordHash`, `encryptedData`, `nonce`, and `header`, but not the salt. Without the salt they cannot run Argon2 at all, which makes offline brute-force attacks impossible even from a fully compromised database. The attacker also needs the user's display passphrase, which is what contains the salt.

### What the Server Stores

```
{
  "passwordHash":      "<64-char lowercase hex, the HKDF auth_key>",
  "encryptedData":     "<URL-safe base64 ciphertext>",
  "nonce":             "<URL-safe base64, 24 bytes>",
  "header":            "<URL-safe base64, 16 bytes>",
  "encryptedMetadata": "<base64, for file secrets only>",
  "isFile":            true | false,
  "viewCount":         1 to 10   (optional),
  "ttl":               <unix timestamp> (optional)
}
```

The server never stores or returns the salt, the passphrase, or any key material.

## API Reference

All endpoints accept and return JSON. Rate limit: 100 requests/IP. Body limit: `MAX_FILE_SIZE_MB` (default 256 MB). Note that base64-encoded payloads are about 1.33x the raw byte size, so the effective plaintext limit is lower.

### POST /encrypt

Store an encrypted text secret.

**Request**

```json
{
  "passwordHash":  "<64-char hex>",
  "encryptedData": "<url-safe base64 ciphertext>",
  "nonce":         "<url-safe base64, 24 bytes>",
  "header":        "<url-safe base64, 16 bytes>",
  "viewCount":     1,
  "ttl":           1735689600
}
```

`viewCount` (0 to 10, where `0` means unlimited views) and `ttl` (Unix timestamp, max 30 days out) are optional when `ADVANCED_FEATURES` is enabled. When advanced features are disabled they're required.

**Response**

```json
{ "status": "success", "secretId": "<16-char alphanumeric ID>" }
```

### POST /encrypt_file

Store an encrypted file secret. Same fields as `/encrypt`, plus:

```json
{
  "encryptedFile":     "<standard base64 encrypted file bytes>",
  "encryptedMetadata": "<standard base64, meta_nonce || encrypted JSON metadata>"
}
```

### POST /decrypt

Retrieve and consume an encrypted secret.

**Request**

```json
{
  "secret_id":    "<16-char alphanumeric ID>",
  "passwordHash": "<64-char hex>"
}
```

**Response** (text secret)

```json
{
  "encryptedData": "<url-safe base64 ciphertext>",
  "nonce":         "<url-safe base64>",
  "header":        "<url-safe base64>",
  "isFile":        false
}
```

**Response** (file secret)

```json
{
  "encryptedData":     "<url-safe base64>",
  "encryptedFile":     "<standard base64 encrypted file bytes>",
  "encryptedMetadata": "<standard base64, meta_nonce || encrypted metadata>",
  "nonce":             "<url-safe base64>",
  "header":            "<url-safe base64>",
  "isFile":            true
}
```

The server validates `passwordHash` with a constant-time comparison. Each successful `/decrypt` call decrements the view counter, and when it reaches zero the secret is deleted. If `ttl` has expired the secret is also deleted and `404` is returned.

## Using the API with an SDK

If you want to create and retrieve secrets programmatically, for scripting, CLI tools, or server-to-server use, the Whisper SDK handles the cryptographic details for you:

- **Go SDK**: [`pkg/client`](pkg/client) in this repo is a type-safe client with full support for text and file secrets, key derivation, and encryption/decryption. There's a runnable example at [`pkg/client/examples/basic`](pkg/client/examples/basic).

The SDK encapsulates the salt-in-passphrase architecture, key derivation, and authenticated encryption so you don't have to.

## Security Architecture

### Content Security Policy

The server sets a strict CSP. Scripts disallow `unsafe-inline` (WASM is permitted via `wasm-unsafe-eval` only), while `style-src` still allows `unsafe-inline` for inline styles:

```
default-src 'self';
script-src  'self' 'wasm-unsafe-eval' https://cdnjs.cloudflare.com;
style-src   'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com;
font-src    'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com;
img-src     'self' data:;
connect-src 'self' https://cdnjs.cloudflare.com;
frame-ancestors 'none';
base-uri    'self';
object-src  'none';
```

`wasm-unsafe-eval` is required for `WebAssembly.instantiateStreaming()`. It permits WASM bytecode compilation only and does not enable `eval()` for JavaScript.

### Other Security Controls

- **HSTS**: `max-age=31536000`
- **X-Frame-Options**: `DENY`
- **X-Content-Type-Options**: `nosniff`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Rate limiting**: 100 requests/IP (in-memory)
- **Body limit**: `MAX_FILE_SIZE_MB` per request (default 256 MB)
- **Request timeout**: 30 seconds
- **Constant-time comparison**: `passwordHash` comparison uses `crypto/subtle`
- **SRI hashes**: All Bootstrap and Font Awesome CDN resources are pinned with `integrity=` hashes

### Known Limitations

- Argon2 runs synchronously on the browser's main thread, so there's a ~1 to 2 second UI pause during key derivation.
- View-count decrement has a TOCTOU race. There's no atomic CAS in the storage layer yet, so concurrent reads of a one-view secret can over-consume it.
- The whole file is held in browser memory and base64-encoded before encryption, so a very large file under the 256 MB default can use several times that in browser memory and request size.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Open a Pull Request

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Go backend: [Echo Framework](https://echo.labstack.com/)
- Rust crypto: [RustCrypto](https://github.com/RustCrypto) crates (chacha20poly1305, argon2, hkdf, sha2)
- WASM toolchain: [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen)
- Cloud storage: [AWS SDK Go v2](https://github.com/aws/aws-sdk-go-v2), [Google Cloud Go SDK](https://github.com/googleapis/google-cloud-go)
- UI: [Bootstrap 5.3.8](https://getbootstrap.com/), [Font Awesome 7](https://fontawesome.com/)
