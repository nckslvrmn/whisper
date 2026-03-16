# Whisper

> End-to-end encrypted secret sharing service with WebAssembly-powered client-side encryption. Share sensitive information with true zero-knowledge architecture — your secrets are encrypted in your browser before ever leaving your device.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.23-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/github/license/nckslvrmn/whisper)](LICENSE)
[![Security](https://img.shields.io/badge/encryption-XChaCha20--Poly1305-green?logo=shield)](https://en.wikipedia.org/wiki/ChaCha20-Poly1305)
[![KDF](https://img.shields.io/badge/KDF-Argon2id-blue)](https://en.wikipedia.org/wiki/Argon2)
[![WASM](https://img.shields.io/badge/WASM-Rust-orange?logo=webassembly)](https://webassembly.org/)

## Features

- **True End-to-End Encryption** — All encryption/decryption happens in your browser via a Rust-compiled WebAssembly module
- **XChaCha20-Poly1305** — Authenticated encryption with 192-bit nonces; no nonce-reuse risk
- **Argon2id + HKDF key splitting** — Memory-hard KDF with separate encryption and authentication keys derived via HKDF-SHA256
- **Salt-in-passphrase architecture** — The Argon2 salt is embedded in the display passphrase and never stored or transmitted to the server; the server cannot mount an offline brute-force attack even if compromised
- **Self-destructing secrets** — Configurable view limits and TTL expiry
- **Text and file support** — Share passwords, API keys, documents, or any sensitive file up to 10 MB
- **Multi-storage backend** — AWS (DynamoDB + S3), Google Cloud (Firestore + GCS), or local SQLite + filesystem
- **Zero server trust** — Server stores only ciphertext, nonce, header, and a 64-hex-char HKDF-derived auth key; plaintext and encryption keys never leave the browser
- **Hardened CSP** — No `unsafe-inline`; WASM permitted via `wasm-unsafe-eval` only; SRI hashes on all CDN resources

## Quick Start

### Docker Compose

`compose.yml` in the repo root is the canonical deployment configuration. It defaults to the AWS backend; comments inside show how to switch to Google Cloud or local storage.

```bash
docker compose up -d
```

### Build from Source

Prerequisites: Go >= 1.23, Rust toolchain, `wasm-pack` 0.14.0.

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

`make wasm` invokes `wasm-pack build --target web` inside `wasm/` and copies the
resulting `crypto.js` and `crypto_bg.wasm` into `web/static/`. The Dockerfile pins
`wasm-pack` at version 0.14.0 for reproducibility.

## Configuration

### Environment Variables

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

Mount a volume at `/data` to persist the SQLite database and encrypted files.
Storage priority: AWS → Google Cloud → Local.

## Authentication

### AWS

Use IAM roles (recommended), environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`), or the default credential chain.

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

The crypto module lives in `wasm/src/lib.rs` and is compiled to WASM via `wasm-pack`. It exports four functions to JavaScript:

| Export | Purpose |
|--------|---------|
| `encryptText(text, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a text secret |
| `encryptFile(fileDataB64, fileName, fileType, viewCount?, ttlDays?, ttlTimestamp?)` | Encrypt a file + metadata |
| `decryptText(encryptedDataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a text secret |
| `decryptFile(encryptedFileB64, encryptedMetadataB64, passphrase, nonceB64, saltB64, headerB64)` | Decrypt a file + metadata |
| `hashPassword(password, saltB64)` | Derive the auth key for a given passphrase + salt |

### Key Derivation

```
passphrase (32 random chars)
    │
    ▼
Argon2id(passphrase, salt, m=64MB, t=2, p=1) ──► root_key (32 bytes)
    │
    ▼
HKDF-SHA256(root_key, salt)
    ├──► enc_key  (label "whisper-encryption-v1")  — used for XChaCha20-Poly1305
    └──► auth_key (label "whisper-auth-v1")         — hex-encoded and stored as passwordHash
```

**Why two keys?** The original Go implementation derived one key from scrypt and used it for both encryption *and* as the server-side authentication hash. This meant the server effectively held the encryption key. HKDF splits the root into two independent 32-byte keys so the server's `passwordHash` reveals nothing about `enc_key`.

### Encryption

- **Algorithm**: XChaCha20-Poly1305 (192-bit nonce, 128-bit Poly1305 tag)
- **Nonce**: 24 random bytes per secret, stored alongside the ciphertext
- **Header**: 16 random bytes used as Additional Authenticated Data (AAD); stored alongside the ciphertext; prevents cross-context ciphertext reuse
- **File metadata**: Encrypted separately with its *own* random nonce (`meta_nonce`) prepended to the metadata ciphertext blob — eliminating the nonce-reuse vulnerability present in the original Go implementation (which used the same nonce for both file data and metadata under AES-GCM)

### Salt-in-Passphrase Architecture

The Argon2 salt (16 random bytes) is **never stored or transmitted to the server**. Instead, it is embedded directly in the display passphrase that users share:

```
display_passphrase = URL_SAFE_BASE64(salt) [24 chars] + random_chars [32 chars]
                     └─────────────────────────────────────────────────────────┘
                                         56 chars total
```

When decrypting, the browser splits the display passphrase at character 24 to recover the salt and the actual Argon2 passphrase. No pre-flight request to the server is needed; decryption is a single round-trip.

**Security consequence**: An attacker who compromises the server's database obtains `passwordHash`, `encryptedData`, `nonce`, and `header` — but not the salt. Without the salt they cannot run Argon2 at all, making offline brute-force attacks impossible even from a fully compromised database. The attacker also needs the user's display passphrase (which contains the salt).

### What the Server Stores

```
{
  "passwordHash":      "<64-char lowercase hex — HKDF auth_key>",
  "encryptedData":     "<URL-safe base64 ciphertext>",
  "nonce":             "<URL-safe base64, 24 bytes>",
  "header":            "<URL-safe base64, 16 bytes>",
  "encryptedMetadata": "<base64, for file secrets only>",
  "isFile":            true | false,
  "viewCount":         1–10   (optional),
  "ttl":               <unix timestamp> (optional)
}
```

The server never stores or returns the salt, the passphrase, or any key material.

## API Reference

All endpoints accept and return JSON. Rate limit: 100 requests/IP. Body limit: 10 MB.

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

`viewCount` (1–10) and `ttl` (Unix timestamp, max 30 days out) are optional when advanced features are enabled. When advanced features are disabled they are required.

**Response**

```json
{ "status": "success", "secretId": "<16-char alphanumeric ID>" }
```

### POST /encrypt_file

Store an encrypted file secret. Same fields as `/encrypt`, plus:

```json
{
  "encryptedFile":     "<standard base64 encrypted file bytes>",
  "encryptedMetadata": "<standard base64 — meta_nonce || encrypted JSON metadata>"
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
  "encryptedMetadata": "<standard base64 — meta_nonce || encrypted metadata>",
  "nonce":             "<url-safe base64>",
  "header":            "<url-safe base64>",
  "isFile":            true
}
```

The server validates `passwordHash` with a constant-time comparison. Each successful `/decrypt` call decrements the view counter; when it reaches zero, the secret is deleted. If `ttl` has expired the secret is also deleted and `404` is returned.

## Using the API Directly (No Frontend)

If you want to create secret bundles without the browser UI — for scripting, CLI tools, or server-to-server use — you need to replicate the client-side crypto. The following pseudocode shows the full flow.

### Storing a Text Secret

```
# 1. Generate random material
salt        = random_bytes(16)
passphrase  = random_printable_chars(32)   # from charset a-z A-Z 0-9 !#$%&*+-=?@_~
nonce       = random_bytes(24)
header      = random_bytes(16)

# 2. Derive keys
root_key    = Argon2id(password=passphrase, salt=salt,
                       m=65536, t=2, p=1, keylen=32)
enc_key     = HKDF-SHA256(ikm=root_key, salt=salt,
                           info="whisper-encryption-v1", length=32)
auth_key    = HKDF-SHA256(ikm=root_key, salt=salt,
                           info="whisper-auth-v1",       length=32)

# 3. Encrypt
ciphertext  = XChaCha20-Poly1305.Encrypt(key=enc_key, nonce=nonce,
                                          plaintext=secret_text,
                                          aad=header)

# 4. Encode for transport
passwordHash    = hex_encode(auth_key)           # 64 lowercase hex chars
encryptedData   = url_safe_base64(ciphertext)
nonceB64        = url_safe_base64(nonce)
headerB64       = url_safe_base64(header)

# 5. POST to server
response = POST /encrypt {
  "passwordHash":  passwordHash,
  "encryptedData": encryptedData,
  "nonce":         nonceB64,
  "header":        headerB64,
  "viewCount":     1,
  "ttl":           unix_timestamp(now + 7 days)
}
secretId = response["secretId"]

# 6. Build the display passphrase to share with the recipient
#    The first 24 chars are URL-safe base64 of the salt (ceil(16/3)*4 = 24).
#    The next 32 chars are the raw passphrase.
display_passphrase = url_safe_base64(salt) + passphrase   # 56 chars total

# Share secretId + display_passphrase with the recipient through a secure channel.
# The salt never touches the server at any point.
```

### Retrieving a Text Secret

```
# The recipient has: secretId, display_passphrase (56 chars)

# 1. Split the display passphrase
salt_b64    = display_passphrase[0:24]      # first 24 chars
passphrase  = display_passphrase[24:]       # remaining 32 chars
salt        = url_safe_base64_decode(salt_b64)

# 2. Derive auth key to authenticate with the server
root_key    = Argon2id(password=passphrase, salt=salt,
                       m=65536, t=2, p=1, keylen=32)
auth_key    = HKDF-SHA256(ikm=root_key, salt=salt,
                           info="whisper-auth-v1", length=32)
passwordHash = hex_encode(auth_key)

# 3. Fetch from server
response = POST /decrypt {
  "secret_id":    secretId,
  "passwordHash": passwordHash
}

# 4. Derive encryption key and decrypt locally
enc_key     = HKDF-SHA256(ikm=root_key, salt=salt,
                           info="whisper-encryption-v1", length=32)
nonce       = url_safe_base64_decode(response["nonce"])
header      = url_safe_base64_decode(response["header"])
ciphertext  = url_safe_base64_decode(response["encryptedData"])

plaintext   = XChaCha20-Poly1305.Decrypt(key=enc_key, nonce=nonce,
                                          ciphertext=ciphertext,
                                          aad=header)
```

### Storing a File Secret

```
# Same key derivation as text. Additionally:

file_bytes       = read_file("secret.pdf")
meta_nonce       = random_bytes(24)           # separate nonce for metadata!
file_nonce       = random_bytes(24)

encrypted_file   = XChaCha20-Poly1305.Encrypt(key=enc_key, nonce=file_nonce,
                                               plaintext=file_bytes, aad=header)

metadata_json    = json({"file_name": "secret.pdf", "file_type": "application/pdf"})
encrypted_meta   = XChaCha20-Poly1305.Encrypt(key=enc_key, nonce=meta_nonce,
                                               plaintext=metadata_json, aad=header)

# Prepend meta_nonce to the metadata ciphertext blob
encrypted_metadata_blob = meta_nonce + encrypted_meta

response = POST /encrypt_file {
  "passwordHash":      hex_encode(auth_key),
  "nonce":             url_safe_base64(file_nonce),
  "header":            url_safe_base64(header),
  "encryptedFile":     standard_base64(encrypted_file),
  "encryptedMetadata": standard_base64(encrypted_metadata_blob),
  "viewCount":         1,
  "ttl":               unix_timestamp(now + 7 days)
}
```

**Important**: File data uses `standard_base64` (with `+`, `/`, and `=` padding).
Nonces and headers use `url_safe_base64` (with `-`, `_`). Match the encoding exactly
or the server will reject the request or clients will fail to decode.

## Security Architecture

### Content Security Policy

The server sets a strict CSP with no `unsafe-inline`:

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

`wasm-unsafe-eval` is required for `WebAssembly.instantiateStreaming()` and permits
WASM bytecode compilation only — it does not enable `eval()` for JavaScript.

### Other Security Controls

- **HSTS**: `max-age=31536000`
- **X-Frame-Options**: `DENY`
- **X-Content-Type-Options**: `nosniff`
- **Referrer-Policy**: `strict-origin-when-cross-origin`
- **Rate limiting**: 100 requests/IP (in-memory)
- **Body limit**: 10 MB per request
- **Request timeout**: 30 seconds
- **Constant-time comparison**: `passwordHash` comparison uses `crypto/subtle`
- **SRI hashes**: All Bootstrap and Font Awesome CDN resources are pinned with `integrity=` hashes

### Known Limitations

- Argon2 runs synchronously on the browser's main thread (~1–2 s UI pause during key derivation)
- View-count decrement has a TOCTOU race; no atomic CAS is implemented in the storage layer
- `wasm-pack` was archived in July 2025; 0.14.0 is the last release

## Production Deployment

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name secrets.yourdomain.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

- Go backend: [Echo Framework](https://echo.labstack.com/)
- Rust crypto: [RustCrypto](https://github.com/RustCrypto) crates (chacha20poly1305, argon2, hkdf, sha2)
- WASM toolchain: [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) / [wasm-pack](https://github.com/rustwasm/wasm-pack)
- Cloud storage: [AWS SDK Go v2](https://github.com/aws/aws-sdk-go-v2), [Google Cloud Go SDK](https://github.com/googleapis/google-cloud-go)
- UI: [Bootstrap 5.3.8](https://getbootstrap.com/), [Font Awesome 7](https://fontawesome.com/)
