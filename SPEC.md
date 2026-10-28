# Whisper protocol specification

Version: **1**, implicit. See [format versioning](#12-format-versioning).
Status: describes the current implementation.

This document specifies the Whisper secret-sharing format precisely enough to build an interoperable implementation without reading the Rust or Go source. Two implementations exist, and [`crypto_vectors.json`](crypto_vectors.json) pins them to each other:

| Implementation | Location | Role |
|----------------|----------|------|
| Rust → WASM | `wasm/src/lib.rs` | Browser client, called from `web/static/worker.js` |
| Go | `pkg/client/` | Server-side and CLI SDK |

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as in RFC 2119.

---

## 1. Overview

Whisper is a zero-knowledge, one-shot secret delivery format. A sender encrypts a payload in their own process, uploads only ciphertext plus non-secret framing to a server, and receives back a secret ID and a display passphrase. A recipient presents the ID and passphrase to the server, which returns the ciphertext if an authentication value derived from the passphrase matches, then decrements a view counter.

The server never has the plaintext, the passphrase, the encryption key, or the KDF salt. It stores, returns, expires, and deletes records.

```
sender                              server                          recipient
──────                              ──────                          ─────────
passphrase = random(32)
salt       = random(16)
keys       = KDF(passphrase, salt)
ct         = AEAD(enc_key, ...)
             ── POST /encrypt {auth, ct, nonce, header} ──►
             ◄── secretId ──
display = b64(salt) || passphrase
             ─────────── out of band ───────────────────────────────►
                                    ◄── POST /decrypt {id, auth} ──
                                    ── ct, nonce, header ──►
                                                        plaintext = AEAD⁻¹(...)
```

---

## 2. Notation and primitives

| Symbol | Meaning |
|--------|---------|
| `‖` | byte-string concatenation |
| `b64(x)` | URL-safe base64 with padding: RFC 4648 §5, `-`/`_` alphabet, `=` padding. Padding is **not** optional. |
| `hex(x)` | lowercase hexadecimal |
| `random(n)` | `n` bytes from a cryptographically secure RNG |

Primitives, all fixed for version 1:

| Purpose | Algorithm |
|---------|-----------|
| Password hashing | Argon2id, version `0x13` (19) |
| Key separation | HKDF-SHA256, RFC 5869 extract-then-expand |
| AEAD | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag |

---

## 3. Constants

Every value below is normative. Changing any of them produces a different, incompatible format.

| Constant | Value | Notes |
|----------|-------|-------|
| `NONCE_SIZE` | 24 bytes | XChaCha20 nonce |
| `SALT_SIZE` | 16 bytes | Argon2id salt and HKDF salt |
| `HEADER_SIZE` | 16 bytes | AEAD associated data |
| `KEY_SIZE` | 32 bytes | Argon2 output, and each HKDF output |
| `PASSPHRASE_LENGTH` | 32 chars | random passphrase |
| `SALT_B64_LEN` | 24 chars | `len(b64(16 bytes))`, the display-passphrase split point |
| `ARGON2_M_COST` | 65536 KiB | 64 MiB |
| `ARGON2_T_COST` | 2 | iterations |
| `ARGON2_P_COST` | 1 | lanes |
| `SECRET_ID_LEN` | 16 chars | `[a-zA-Z0-9]` |
| Auth label | `whisper-auth-v1` | HKDF `info` |
| Encryption label | `whisper-encryption-v1` | HKDF `info` |

`SALT_B64_LEN` **MUST** equal the encoded length of `SALT_SIZE` bytes. The Rust tests assert this, and the display-passphrase vectors pin the split for both implementations. The constant is duplicated in `wasm/src/lib.rs`, `pkg/client/crypto.go`, and `web/static/main.js`, and all three must change together.

---

## 4. Key derivation

Given the passphrase `P` as UTF-8 bytes and the 16-byte salt `S`:

```
root      = Argon2id(password = P, salt = S,
                     m = 65536 KiB, t = 2, p = 1, outlen = 32)

prk       = HKDF-Extract(salt = S, ikm = root)
enc_key   = HKDF-Expand(prk, info = "whisper-encryption-v1", L = 32)
auth_key  = HKDF-Expand(prk, info = "whisper-auth-v1",       L = 32)

passwordHash = hex(auth_key)          # 64 lowercase hex characters
```

Notes:

- The salt is used twice, as the Argon2 salt and as the HKDF extract salt. Both uses are required for vector compatibility.
- HKDF `info` labels are ASCII, with no trailing NUL.
- `enc_key` is the only key that touches the AEAD. `auth_key` is a bearer credential presented to the server and **MUST NOT** be used for encryption.
- An implementation **MUST NOT** derive `passwordHash` by any route other than the HKDF split. Deriving it from `root` directly, or reusing `enc_key`, hands the server the encryption key.

### 4.1 Two-secret key derivation, the 1Password model

Whisper's salt handling follows the principle 1Password calls two-secret key derivation, or 2SKD. The key that unlocks the data comes from two independent inputs, and the server never receives one of them, so a full server compromise leaves the attacker unable to start an offline attack.

| | 1Password | Whisper |
|---|---|---|
| Secret 1 | Account password, human-chosen, low entropy | Passphrase, 32 random chars, ~199 bits |
| Secret 2 | Secret Key, 128 bits, generated on device | Salt, 128 bits, generated on device |
| Server holds | SRP verifier | `passwordHash` = `hex(auth_key)` |
| Server sees secret 2? | Never | Never |
| Combination | `PBKDF2(password)` XOR `HKDF(secret key)` | `Argon2id(passphrase, salt)`, salt also HKDF-extract salt |
| Scope of secret 2 | Per account, long-lived | Per secret, single-use |

In both systems the stored value can't be ground offline, because 128 bits of the derivation input were never transmitted. In 1Password this is what lets a weak human password survive a breach of their vaults. Whisper's passphrase is already random and high-entropy, so 2SKD is defense in depth here. It matters if a deployment ever accepts user-chosen passphrases, or if a passphrase is partially disclosed, such as truncated in a log or half-visible over a shoulder.

The analogy stops at transport. 1Password users hold and transmit their two secrets separately, so learning one still leaves the attacker with nothing. Whisper's two secrets travel together inside one display passphrase, so 2SKD does nothing against an adversary who intercepts that string. See [THREAT_MODEL.md](THREAT_MODEL.md) §4.

---

## 5. Passphrase generation

The passphrase alphabet is exactly these 75 characters, in this order:

```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_~
```

Characters **MUST** be sampled uniformly. Both implementations use rejection sampling over random bytes:

```
ACCEPT_BELOW = (256 / 75) * 75 = 225        # integer division
for each random byte b:
    if b < ACCEPT_BELOW:
        emit ALPHABET[b mod 75]
```

Bytes ≥ 225 are discarded. Any uniform sampler conforms. The output distribution doesn't depend on this particular rule.

A 32-character passphrase carries `32 × log₂(75) ≈ 199` bits of entropy.

### 5.1 Display passphrase

The display passphrase carries the salt, so the server never stores it:

```
display_passphrase = b64(salt) ‖ passphrase
                     └ 24 chars ┘└ 32 chars ┘
                     total: 56 characters
```

To decompose it, split at exactly `SALT_B64_LEN`, 24 characters. A decoder **MUST**:

1. reject inputs shorter than 25 characters;
2. base64-decode the first 24 characters with the URL-safe padded alphabet;
3. reject the result if it is not exactly 16 bytes;
4. treat the entire remainder as the passphrase, without trimming or normalization.

The remainder is not required to be 32 characters. Decoders don't validate its length, so the passphrase length can change without breaking existing secrets. A wrong passphrase fails at the AEAD tag check, not at parse time.

The salt **MUST NOT** be sent to the server in any request, header, or query parameter.

---

## 6. Text secret format

Encryption, given plaintext `M`:

```
passphrase = random passphrase (§5)
nonce      = random(24)
salt       = random(16)
header     = random(16)

enc_key, auth_key = derive(passphrase, salt)          # §4
ciphertext        = XChaCha20-Poly1305-Seal(
                        key   = enc_key,
                        nonce = nonce,
                        aad   = header,
                        msg   = M)
```

The resulting wire fields:

| Field | Encoding |
|-------|----------|
| `passwordHash` | `hex(auth_key)`, 64 chars |
| `encryptedData` | `b64(ciphertext)` |
| `nonce` | `b64(nonce)`, always 32 chars |
| `header` | `b64(header)`, always 24 chars |

`header` is random associated data with no internal structure. It is authenticated but not secret. The server stores it next to the ciphertext, so it adds no binding beyond the per-record key: a ciphertext moved into another record fails because that record's key differs, and a whole record copied to a new ID still decrypts under the original passphrase.

Plaintext is UTF-8. A decoder that yields invalid UTF-8 for a text secret **MUST** report an error rather than returning replacement characters.

---

## 7. File secret format

A file secret encrypts two payloads under the same `enc_key` with two distinct nonces. Reusing one nonce for both would leak the XOR of the two plaintexts and allow forgeries, so the metadata carries its own nonce inline.

```
passphrase = random passphrase (§5)
salt       = random(16)
header     = random(16)
file_nonce = random(24)
meta_nonce = random(24)

enc_key, auth_key = derive(passphrase, salt)

encryptedFile = Seal(enc_key, file_nonce, aad = header, msg = file_bytes)

metadata_json = {"file_name":"<name>","file_type":"<mime>"}      # §7.1
meta_ct       = Seal(enc_key, meta_nonce, aad = header, msg = metadata_json)
encryptedMetadata_blob = meta_nonce ‖ meta_ct                    # 24-byte prefix
```

| Field | Encoding |
|-------|----------|
| `passwordHash` | `hex(auth_key)`, 64 chars |
| `nonce` | `b64(file_nonce)`, the file nonce |
| `header` | `b64(header)` |
| `encryptedMetadata` | `b64(meta_nonce ‖ meta_ct)` |
| `encryptedFile` | raw bytes, never base64, see §8.2 |

A decoder **MUST** reject an `encryptedMetadata` blob of 24 bytes or fewer before splitting it.

### 7.1 Metadata plaintext

The metadata plaintext is a compact JSON object with exactly two string keys, in this order, with no insignificant whitespace:

```json
{"file_name":"notes.bin","file_type":"application/octet-stream"}
```

Decoders **MUST** parse this as JSON and **MUST NOT** rely on byte-for-byte reproduction, for two reasons:

- Go's `encoding/json` escapes `<`, `>`, and `&` as `<`, `>`, and `&` by default, and `serde_json` emits them literally. A filename containing those characters produces different but equivalent metadata plaintext in the Go and Rust encoders. Decoders parse the field and never compare it, so interoperability holds, but the file conformance vectors are only byte-reproducible for filenames without those characters.
- A missing or non-string `file_name` or `file_type` **MUST** be treated as an empty string, not an error.

Filenames are attacker-controlled from the recipient's side. A client that writes the decrypted file to disk **MUST** sanitize the name, because the format places no constraint on it and permits path separators.

---

## 8. Wire protocol

All endpoints are on the Whisper server origin. There are no accounts and no sessions, and `passwordHash` is the only authentication.

### 8.1 `POST /encrypt`: store a text secret

Request, `application/json`:

```json
{
  "passwordHash":  "<64 lowercase hex>",
  "encryptedData": "<url-safe base64>",
  "nonce":         "<url-safe base64, 24 bytes>",
  "header":        "<url-safe base64, 16 bytes>",
  "viewCount":     1,
  "ttl":           1735689600
}
```

`viewCount` and `ttl`, in absolute Unix seconds, are optional in the schema, but §8.5 governs when the server accepts them. Response `200`:

```json
{"status": "success", "secretId": "<16 alphanumeric chars>"}
```

### 8.2 `POST /encrypt_file`: store a file secret

`multipart/form-data` with exactly two parts, in this order:

1. part name `payload`: a JSON object with `passwordHash`, `encryptedMetadata`, `nonce`, `header`, and optional `viewCount` and `ttl`. Capped at 64 KiB.
2. part name `file`: the raw ciphertext bytes.

Order matters. The server streams the request and reads the payload part before the file part, so it can reject an invalid request without buffering the upload. A third part, a missing part, an out-of-order part, or an empty file part **MUST** be rejected. The response is identical to §8.1.

Ciphertext on this path is raw, never base64, so `MAX_FILE_SIZE_MB` is the true limit rather than 3/4 of it.

### 8.3 `POST /decrypt`: retrieve and consume

Request, `application/json`:

```json
{"secret_id": "<16 alphanumeric>", "passwordHash": "<64 lowercase hex>"}
```

Response for a text secret, `200 application/json`:

```json
{
  "encryptedData": "<url-safe base64>",
  "nonce":         "<url-safe base64>",
  "header":        "<url-safe base64>",
  "isFile":        false
}
```

Response for a file secret, `200 application/octet-stream`. The body is the raw ciphertext, and the framing is in response headers:

| Header | Value |
|--------|-------|
| `X-Whisper-Nonce` | `b64(file_nonce)` |
| `X-Whisper-Header` | `b64(header)` |
| `X-Whisper-Encrypted-Metadata` | `b64(meta_nonce ‖ meta_ct)` |
| `X-Whisper-Is-File` | `true` |

A successful `/decrypt` consumes one view. When the remaining count reaches zero the server deletes the secret record, and for file secrets the stored ciphertext too, including when the client disconnects mid-download.

### 8.4 `GET /secret/:secret_id` and `GET /healthz`

`/secret/:secret_id` returns the decrypt page. The server does not check whether the ID exists, so this endpoint is not an existence oracle. `/healthz` returns `{"status":"ok"}`.

### 8.5 Server validation

A conforming server **MUST** enforce:

| Rule | Failure |
|------|---------|
| `secret_id` matches `^[a-zA-Z0-9]{16}$` | `400` |
| `passwordHash` matches `^[a-f0-9]{64}$` | `400` |
| `encryptedData` or `encryptedMetadata` present and non-empty | `400` |
| `nonce` and `header` present and non-empty | `400` |
| `encryptedData` length ≤ `MAX_TEXT_SIZE_MB` | `400` |
| file part length ≤ `MAX_FILE_SIZE_MB`, aborted mid-stream | `400` |
| `viewCount` in `0..=10`, where 0 is unlimited | `400` |
| `ttl` strictly in the future and at most 30 days out | `400` |
| when advanced features are disabled, both `viewCount` and `ttl` present | `400` |

The reference server does **not** check that `nonce` and `header` decode to 24 and 16 bytes. Clients enforce that at decrypt time. A server **MAY** check it too, since both are non-secret framing.

### 8.6 Uniform failure

A missing secret, an expired secret, an exhausted secret, and a wrong `passwordHash` **MUST** all produce the same response:

```
404  "Secret not found or already viewed"
```

The `passwordHash` comparison **MUST** be constant-time. Together these stop the server from revealing whether an ID exists or a passphrase is wrong. Clients therefore can't report a `404` to the user as specifically "wrong passphrase".

---

## 9. Server-side storage model

The stored secret record is compact JSON:

```json
{
  "passwordHash":      "<64 hex>",
  "encryptedData":     "<b64>",
  "encryptedMetadata": "<b64>",
  "nonce":             "<b64>",
  "header":            "<b64>",
  "isFile":            false
}
```

`encryptedData` is present only for text secrets and `encryptedMetadata` only for file secrets.

`viewCount` and `ttl` **MUST NOT** live inside this JSON. They are native columns, attributes, or fields named `view_count` and `ttl` in the backing store, which keeps the payload immutable after creation and lets view consumption be a single atomic operation. A `view_count` of 0 or absent means unlimited.

View consumption **MUST** be atomic: a conditional decrement that returns the remaining count and deletes the record at zero, in one transaction or one conditional write. All three reference providers, SQLite, DynamoDB, and Firestore, do this. A read-modify-write would let concurrent readers exceed the view limit.

The server enforces TTL at read time, and the storage backend also expires records, because backend cleanup is asynchronous and can lag.

Encrypted files are stored as raw ciphertext bytes in S3, GCS, or on the local filesystem, keyed by secret ID.

### 9.1 Legacy records

Older versions wrote records as URL-safe base64 instead of raw bytes. Readers tell them apart by sniffing, since records carry no version marker:

- Payloads: a leading `{` means raw JSON, and anything else is base64. The base64 alphabet cannot produce `{`.
- Files: the reader inspects the first 512 bytes. If every byte is in the URL-safe base64 alphabet, it decodes the stream, and otherwise treats it as raw. Random ciphertext staying inside that alphabet for 512 bytes has probability ≈ 2⁻²⁰⁰.

New implementations **MUST** write the raw form. Reading the legacy form is only needed to migrate existing data.

---

## 10. Optional link modes

The display passphrase **MAY** be appended to the share URL as a fragment:

```
https://whisper.example.com/secret/aB3dE5fG7hJ9kL2m#p=<url-encoded passphrase>
```

Browsers don't send fragments to the server, so they stay out of access logs and the `Referer` header. A client that consumes such a link **SHOULD** strip the fragment from the address bar with `history.replaceState` after reading it.

This mode collapses the two-channel design into one: the link alone is enough to read the secret. It **MUST** be opt-in per secret, never the default.

---

## 11. Conformance

An implementation conforms if it reproduces every vector in [`crypto_vectors.json`](crypto_vectors.json). That file fixes:

- the Argon2 parameters, as an explicit object;
- three text vectors, for ASCII, empty, and non-BMP Unicode plaintext, each pinning `ciphertext` and `passwordHash` for a fixed passphrase, salt, nonce, and header;
- one file vector, pinning `encryptedFile`, `encryptedMetadata` with its `metaNonce` prefix, and `passwordHash` over a 512-byte binary payload;
- two display-passphrase vectors covering the 24-character split, one built from the punctuation end of the alphabet.

Encryption is randomized, so the tests supply the fixed salt, nonce, and header rather than generating them. Implementations need an internal seam that accepts these values. The reference implementations expose it to tests only.

Regenerate with:

```
go test ./pkg/client -run TestCryptoVectors -update
```

Run the Rust side with `cd wasm && cargo test`.

A conforming implementation **MUST** also:

- treat all base64 as URL-safe **with** padding, on both encode and decode;
- reject a nonce that is not 24 bytes and a salt that is not 16 bytes;
- fail closed on an AEAD tag mismatch, with an error indistinguishable from a wrong passphrase;
- never transmit the salt or passphrase to the server;
- never log the display passphrase.

---

## 12. Format versioning

Version 1 carries no version marker. There is no version byte, no suite identifier, and no algorithm agility. This document alone implies the KDF parameters and cipher, and a parser has no way to tell from a record that it is a format it doesn't understand.

Every deployment is currently run by the format's author, so a format change can migrate all records forward at once. That stops working as soon as records exist that this project cannot migrate.

Any future format change **SHOULD** start by adding an explicit version discriminant with these properties:

- a leading version byte on the record, parsed before anything else;
- strict rejection of unrecognized versions, with no best-effort tolerance;
- a suite identifier covering the KDF parameters and the AEAD together, so raising the Argon2 cost shows up in the record;
- a canonical, non-extensible encoding. Schema formats built for tolerant evolution, such as Protobuf, let two encoders emit different bytes for the same message, and their unknown-field tolerance defeats a version discriminant. A fixed-layout header like `age` and PASETO use, or deterministic CBOR if structure is needed, fits.

Until then, only deployment context answers "which format is this?", and the sniffing in §9.1 exists for migration, not versioning.

---

## 13. Non-goals

The format does not provide:

- Sender authentication. A secret carries no identity, and anyone holding the link and passphrase looks the same as the intended recipient.
- Recipient targeting. There is no public key, no enrollment, and no directory. Encrypting to a specific person needs a different construction.
- Forward secrecy or key rotation. A secret is single-use and short-lived, and its key exists for the life of the record.
- Metadata privacy at the storage layer. The server operator sees record existence, ciphertext length, creation time, and access time.
- Deniability or anonymity.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the consequences.
