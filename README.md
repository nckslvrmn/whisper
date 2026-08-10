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
- **Text and file support.** Share passwords, API keys, documents, or any sensitive file. The default limit is 256 MB, configurable via `MAX_FILE_SIZE_MB`. Files stream as raw ciphertext in both directions, so the limit is the real file size and server memory does not scale with it.
- **Multi-storage backend.** AWS (DynamoDB + S3), Google Cloud (Firestore + GCS), or local SQLite + filesystem.
- **Zero server trust.** The server stores only ciphertext, nonce, header, and a 64-hex-char HKDF-derived auth key. Plaintext and encryption keys never leave the browser.
- **Off-thread crypto.** Argon2id and XChaCha20 run in a module Web Worker, so the UI stays responsive during key derivation.
- **Hardened CSP.** No `unsafe-inline` for scripts, WASM permitted via `wasm-unsafe-eval` only, and SRI hashes on all CDN resources. Inline styles are still allowed (`style-src 'unsafe-inline'`).

## Quick Start

### Docker Compose

`compose.yml` in the repo root is the canonical deployment config. It defaults to the AWS backend, and the comments inside show how to switch to Google Cloud or local storage.

```bash
docker compose up -d
```

### Build from Source

Prerequisites: Go >= 1.23, the Rust toolchain with the `wasm32-unknown-unknown` target, and `wasm-bindgen-cli` 0.2.126. `wasm-opt` (binaryen) and `brotli` are optional and used to shrink and precompress the WASM artifact if they're present.

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

`make wasm` builds the crate with `cargo build --release --target wasm32-unknown-unknown`, runs `wasm-bindgen --target web --force-enable-abort-handler` to generate `crypto.js` and `crypto_bg.wasm` into `web/static/`, then optionally optimizes with `wasm-opt --enable-exception-handling` and precompresses with `gzip` and `brotli`. The Dockerfile pins `wasm-bindgen-cli` at 0.2.126 for reproducibility.

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
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::YOUR_BUCKET_NAME/*"
    }
  ]
}
```

Files are uploaded as a stream, so anything over the 5 MB part size goes up as a multipart upload. `s3:PutObject` covers the upload parts themselves, and `s3:AbortMultipartUpload` lets a failed upload clean up after itself instead of leaving parts to be billed.

### Google Cloud

Set `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file, or rely on Application Default Credentials in GCP environments.

Required roles: `roles/datastore.user`, `roles/storage.objectAdmin`.

## Cryptographic Design

### WASM Module (Rust)

The crypto module lives in `wasm/src/lib.rs` and is compiled to WASM via `wasm-bindgen`. It exports five functions to JavaScript, all called from `web/static/worker.js` rather than the main thread:

| Export | Purpose |
|--------|---------|
| `encryptText(text, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a text secret |
| `encryptFile(fileData, fileName, fileType, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a file plus metadata. `fileData` is a `Uint8Array` and `encryptedFile` comes back as one |
| `decryptText(encryptedDataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a text secret |
| `decryptFile(encryptedFile, encryptedMetadataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a file plus metadata. `encryptedFile` and the returned `fileData` are `Uint8Array` |
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

The secret record is raw JSON, stored as-is:

```
{
  "passwordHash":      "<64-char lowercase hex, the HKDF auth_key>",
  "encryptedData":     "<URL-safe base64 ciphertext, text secrets only>",
  "nonce":             "<URL-safe base64, 24 bytes>",
  "header":            "<URL-safe base64, 16 bytes>",
  "encryptedMetadata": "<URL-safe base64, file secrets only>",
  "isFile":            true | false
}
```

`viewCount` and `ttl` live only as native columns, attributes, or fields (`view_count` and `ttl`), never inside the JSON. An absent or zero `view_count` means unlimited views. The payload is immutable after creation: view consumption only touches the native counter, atomically, and the record is deleted when the counter hits zero.

Encrypted files are stored as raw ciphertext bytes in S3, GCS, or the local filesystem. Records and files written by older versions are base64 and are still read transparently.

The server never stores or returns the salt, the passphrase, or any key material.

## API Reference

Text endpoints accept and return JSON. File upload is `multipart/form-data` and file download is `application/octet-stream`, so ciphertext is never base64 on the wire and `MAX_FILE_SIZE_MB` is the effective file size limit. Rate limit: 100 requests/IP. Body limit: `MAX_FILE_SIZE_MB` (default 256 MB).

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

Store an encrypted file secret. `Content-Type: multipart/form-data` with exactly two parts, in this order:

| Part | Content |
|------|---------|
| `payload` | JSON: `passwordHash`, `encryptedMetadata` (URL-safe base64, `meta_nonce \|\| encrypted JSON metadata`), `nonce`, `header`, and optionally `viewCount` and `ttl` |
| `file` | Raw encrypted file bytes, streamed straight to storage |

Missing parts, parts out of order, extra parts, an empty `file` part, or a `file` part over the size limit are all rejected with `400`. The response matches `/encrypt`.

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

`Content-Type: application/octet-stream`. The body is the raw encrypted file, streamed from storage. The small fields travel in headers:

| Header | Content |
|--------|---------|
| `X-Whisper-Is-File` | `true` |
| `X-Whisper-Nonce` | URL-safe base64, 24 bytes |
| `X-Whisper-Header` | URL-safe base64, 16 bytes |
| `X-Whisper-Encrypted-Metadata` | URL-safe base64, `meta_nonce \|\| encrypted metadata` |

The server validates `passwordHash` with a constant-time comparison. Each successful `/decrypt` call atomically decrements the view counter, and when it reaches zero the record and any encrypted file are deleted. If `ttl` has expired the secret is also deleted and `404` is returned.

The view is only consumed after validation passes and, for file secrets, after the file reader is open, so a storage failure returns `500` without burning a view.

### GET /healthz

Liveness probe. Returns `200 {"status":"ok"}` without touching storage. The container `HEALTHCHECK` runs `/whisper -healthcheck`, which probes this endpoint on `$PORT` and exits non-zero when it fails.

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
worker-src  'self';
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
- **Request timeout**: 30 seconds, propagated into every storage call
- **Constant-time comparison**: `passwordHash` comparison uses `crypto/subtle`
- **SRI hashes**: All Bootstrap and Font Awesome CDN resources are pinned with `integrity=` hashes

### Known Limitations

- The whole file is held in browser memory during encryption, so a very large file under the 256 MB default needs a couple of multiples of that in browser memory. Chunked client-side encryption would fix it and is not implemented.
- A client that disconnects mid-download still spends its view. Opening the file reader before consuming the view covers the storage-failure case, but not a dead connection.
- Rate limiting is in-memory per instance, so it does not coordinate across replicas.

## Contributing

Run the suites before opening a PR:

```bash
CGO_ENABLED=1 go test -race ./...   # server, storage, SDK, end-to-end
cd wasm && cargo test --lib          # Rust crypto module
```

`crypto_vectors.json` in the repo root holds known-answer vectors shared by the Go SDK and the Rust module, so protocol drift between them fails one of the two suites. Regenerate it with `go test ./pkg/client -run TestCryptoVectors -update` when the crypto changes on purpose.

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
