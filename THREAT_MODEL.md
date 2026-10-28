# Whisper threat model

Companion to [SPEC.md](SPEC.md), which defines the format. This document defines who Whisper defends against, what it guarantees, and what it does not.

Status: describes the current implementation. Whisper has not been independently audited.

---

## 1. System model

```
┌─ sender's browser / process ──────────┐
│  plaintext, passphrase, salt,         │   trust boundary
│  enc_key, auth_key                    │        │
└───────────────┬───────────────────────┘        │
                │ ciphertext + framing only      ▼
┌───────────────▼───────────────────────────────────────┐
│ whisper server                                        │
│  · secret record: passwordHash, ciphertext, nonce,    │
│    header, isFile, view_count, ttl                    │
│  · encrypted file bytes (S3 / GCS / local fs)         │
│  · serves the HTML, JS, and WASM that do the crypto ◄─┼── the trust
└───────────────┬───────────────────────────────────────┘   assumption
                │ ciphertext + framing only
┌───────────────▼───────────────────────┐
│ recipient's browser / process         │
└───────────────────────────────────────┘

        display passphrase (salt ‖ passphrase)
        travels sender → recipient out of band,
        over a channel Whisper does not control
```

Two facts follow from this picture and shape everything below:

1. Whisper doesn't trust the server with data at rest, and trusts it with almost nothing else, except that the server also ships the code that does the encryption. Whisper can't resolve that. Every browser-delivered end-to-end encryption system has the same limit.
2. The out-of-band channel, whether Slack, email, a password manager, or a phone call, is outside the system, and in practice it is where secrets leak.

---

## 2. Assets

| Asset | Where it lives | Consequence of disclosure |
|-------|----------------|---------------------------|
| Plaintext secret | Sender and recipient endpoints only | Total |
| Display passphrase, salt ‖ passphrase | Endpoints and the out-of-band channel | Total, if paired with the link |
| Salt, 128 bits | Inside the display passphrase | Lets an offline attack start |
| `enc_key` | Derived in memory, never stored | Total for that secret |
| `auth_key` / `passwordHash` | Server DB, and on the wire at decrypt | Lets the holder fetch ciphertext and burn a view, but **not** decrypt |
| Secret ID | Server, share link | Nothing on its own |
| Filename and MIME type | Encrypted metadata blob | Often sensitive, and encrypted |
| Ciphertext length | Server, network | Approximate plaintext size |
| Record existence, create and access time | Server | Traffic analysis |

---

## 3. Adversaries

### T1: passive network observer

**Capability:** reads traffic between endpoints and server.

**Result:** TLS blocks this. Even without TLS, ciphertext and framing carry no plaintext, and the display passphrase never crosses this wire in either direction. A deployment served over plain HTTP still doesn't leak plaintext to a sniffer.

### T2: active network attacker, TLS-terminating proxy, or CDN

**Capability:** reads and modifies traffic inside the TLS boundary.

**Blocked:** plaintext recovery. The AEAD tag makes ciphertext tampering detectable, and modified ciphertext fails to decrypt instead of decrypting to attacker-chosen data.

**Not blocked:** this attacker sees `passwordHash` on the `/decrypt` request, and it is a bearer credential. They can replay it to fetch the ciphertext and burn a view, which denies the legitimate recipient their read and leaves the attacker with ciphertext they still can't decrypt. They can also drop the response after the view is consumed.

**Not blocked at all:** an attacker in this position can modify the served JavaScript and WASM. See T5.

### T3: honest-but-curious server operator

**Capability:** reads the database, object store, and logs, but does not modify served code.

**Blocked:** plaintext, filename, MIME type, passphrase, salt, and encryption key. `passwordHash` is HKDF-separated from `enc_key`, so holding it reveals nothing about the encryption key.

**Not blocked:** existence of secrets, ciphertext size, which is plaintext length plus 16 bytes for a text secret, creation and access timestamps, view counts, TTLs, and the requesting IP. Whisper is not an anonymity system.

### T4: full server compromise, database dump, or bucket exfiltration

**Capability:** everything in T3, plus arbitrary code on the server, plus the ability to keep data past its TTL and ignore deletion.

**Blocked:** offline attack on the stored `passwordHash`. The attacker holds `hex(auth_key)` and every ciphertext but not the salt, so they can't run Argon2id even once against a candidate passphrase. This is the 2SKD property from §4.

**Not blocked:** deletion is unverifiable. A compromised or malicious server can keep every ciphertext forever regardless of view count or TTL, so those only limit exposure when the server is honest. If the passphrase leaks later, retained ciphertext decrypts.

**Not blocked:** the attacker can serve hostile code to future visitors. See T5.

### T5: malicious or compromised server code delivery

**Capability:** modifies the HTML, JS, or WASM the browser runs.

**Not blocked. This caps every guarantee in this document.** A server that serves altered client code can exfiltrate the passphrase and plaintext straight from the sender's or recipient's browser, and no client-side cryptography detects it. CSP, SRI, and `wasm-unsafe-eval` scoping raise the cost of third-party injection, and do nothing against the origin itself.

The practical mitigations are outside the format:

- self-host, so the operator and the data owner are the same party, which is how Whisper is deployed;
- use the Go SDK in `pkg/client` instead of the browser, which takes code delivery out of the trust boundary;
- pin and review the deployed build.

### T6: attacker holding only the share link

**Capability:** has `https://…/secret/<id>` but not the passphrase.

**Blocked:** everything. `/decrypt` requires `passwordHash`, which requires the passphrase and the salt inside it. Without it the attacker can't fetch the ciphertext or burn a view, and because `GET /secret/:id` renders the page without checking the ID, they can't confirm the secret exists.

**Exception:** if the sender opted into the `#p=` fragment link from SPEC §10, the link alone is enough. That mode drops to a single channel on purpose and is chosen per secret.

### T7: attacker holding the out-of-band channel

**Capability:** reads the Slack DM, mailbox, or ticket where the link and passphrase were sent.

**Not blocked, and this is the most likely real-world risk.** Whisper assumes the link and passphrase travel separately. In practice people paste both into the same message, and then the only remaining protection is that the ciphertext lives somewhere else, with the view counter and TTL limiting exposure.

Whisper's one defense here is time-bounded. With a view count of 1, a secret the intended recipient already read is gone, and an attacker who reads the channel later gets a 404. An attacker who reads it first consumes the view, so the recipient gets "already viewed". A recipient who sees that should treat it as a compromise, not a bug, and operator documentation should say so.

### T8: attacker at the recipient's endpoint

**Capability:** browser extensions, clipboard monitors, shoulder-surfing, malware, a shared machine, browser history.

**Not blocked.** The browser renders decrypted text in the DOM, saves decrypted files to the downloads directory, and the passphrase passes through the clipboard. Fragment-mode links also put the passphrase in browser history unless the client strips it, and the reference client strips it with `history.replaceState`.

For PNG, JPEG, GIF, WebP, and AVIF files the reference client also offers an inline preview through a `blob:` URL in an `<img>`. That runs sender-supplied bytes through the browser's image decoder. The allowlist uses the `file_type` from the encrypted metadata, which the sender controls, and leaves out SVG because it can carry script.

### T9: offline attacker holding ciphertext and salt

**Capability:** the ciphertext plus the salt half of the display passphrase, but not the passphrase half. The realistic route is a partially disclosed passphrase, truncated in a log or half-visible over a shoulder.

**Blocked by margin.** The passphrase carries ~199 bits of entropy, and each guess costs a 64 MiB, 2-pass Argon2id run. Even with the salt, this is not attackable.

### T10: denial of service

**Capability:** floods endpoints, uploads large files, exhausts storage.

**Partially blocked:** a 100 requests/IP rate limit, the `MAX_FILE_SIZE_MB` body limit enforced mid-stream, a 30-second request timeout, a 30-day TTL ceiling, and a view-count ceiling of 10.

**Not blocked:** the rate limiter is in-memory and per instance, so replicas don't share it. Deployments behind a load balancer should rate limit upstream. Client-side Argon2 at 64 MiB costs the client, not the server. The server does no key derivation at all, which makes it cheap to defend.

---

## 4. What 2SKD buys, and what it doesn't

Whisper derives its keys from two inputs and never sends one of them to the server. 1Password calls this two-secret key derivation and uses it so a breach of its own vaults doesn't become an offline attack on customers' account passwords. The comparison table is in [SPEC.md §4.1](SPEC.md#41-two-secret-key-derivation-the-1password-model).

**What it provides against T4:** a full database dump is inert. The attacker has `passwordHash` and ciphertext, and can't make even the first Argon2 call, because the salt was never transmitted. There is no work factor to grind against, no rainbow table to build, and no incremental progress. In the usual design the salt sits beside the hash, and a breach hands the attacker a complete offline oracle.

**What it doesn't provide:** 1Password users hold their two secrets differently, one memorized and one on a device and in an Emergency Kit, so an attacker who learns one still faces the other. Whisper concatenates its two secrets into a single 56-character string that travels over a single channel. Against T7, 2SKD contributes nothing. The salt is 128 bits of key material that the server never sees, and it can't act as a second factor.

**How much it matters today:** the passphrase is already 199 random bits, so a stored salt wouldn't have made an offline attack feasible either. The passphrase's entropy is what stops offline attacks today. 2SKD is defense in depth, and it matters in two cases: a deployment that lets users choose their own passphrases, and a partial disclosure of a passphrase. Docs that oversell it invite the wrong conclusion.

**Naming hazard for reimplementers:** the code and the spec call the 16-byte value a "salt", but it doesn't behave like one. It is never public, never stored, and its secrecy matters. Someone implementing from a document that says "salt" may conclude that truncating, reusing, or logging it is fine. It is not. Treat it as key material.

---

## 5. Security properties

These hold under the model above:

1. Confidentiality against the server at rest. The server can't decrypt what it stores, per T3 and T4.
2. Key separation. `passwordHash` and `enc_key` are independent HKDF outputs of the same root, and the server's copy of one reveals nothing about the other.
3. No offline attack from a server breach. The salt is never transmitted, see §4.
4. Ciphertext integrity. XChaCha20-Poly1305 authenticates the ciphertext and its random 16-byte `header`, and tampering fails closed.
5. No nonce reuse. File data and file metadata use the same key with two independent 24-byte random nonces. The metadata nonce is a prefix of the metadata blob, so the pairing can't drift.
6. Uniform failure. Missing, expired, exhausted, and wrong-passphrase all return the same 404, and the server compares `passwordHash` in constant time. The server reveals neither whether an ID exists nor whether a passphrase is wrong.
7. Atomic view consumption. All three storage providers decrement conditionally and delete at zero in a single operation, so concurrent readers can't exceed the limit.
8. Expiry enforced at read. The server checks TTL on read as well as relying on backend cleanup, so a lagging async sweep never serves an expired secret.
9. Fail-safe file delivery. The server opens the file reader before consuming the view, so a storage failure can't burn a view without delivering anything. A mid-stream disconnect still deletes the file instead of orphaning it.
10. No passphrase transmission. Neither the passphrase nor the salt appears in any request body, header, query parameter, or log line.

---

## 6. Explicit non-guarantees

- No defense against a malicious server, per T5. Browser-delivered end-to-end encryption can't provide one.
- No sender or recipient authentication. Holding the link and passphrase is the authorization. There are no accounts and no identities.
- No verifiable deletion. Only an honest server enforces view counts and TTL. A dishonest one keeps everything.
- No protection of the out-of-band channel, per T7.
- No endpoint security, per T8.
- No metadata privacy at the storage layer. The operator sees existence, size, and timing.
- No forward secrecy. It means little for a single-use, short-lived secret, but retained ciphertext plus a later passphrase leak yields plaintext.
- No anonymity or deniability. The server sees requesting IPs.
- No plaintext length hiding. Ciphertext is plaintext length plus a 16-byte tag, with no padding.
- No independent audit. The construction uses standard primitives from RustCrypto and `x/crypto` in conventional ways, and cross-implementation vectors pin it, but no third party has reviewed it.

---

## 7. Known weaknesses and residual risk

| # | Issue | Severity | Notes |
|---|-------|----------|-------|
| 1 | No explicit format version, see SPEC §12 | Medium, latent | Records are unversioned and readers detect legacy formats by sniffing. Workable while every deployment can be migrated at once. A blocker before publishing the format for anyone else's data. |
| 2 | `passwordHash` is a replayable bearer token | Low | A TLS-terminating proxy can burn a view and take the ciphertext, per T2. No decryption risk. |
| 3 | Fragment `#p=` links collapse two channels into one | Medium, opt-in | Fragments stay out of logs and `Referer`, but the link alone is enough to read the secret. Must stay non-default. |
| 4 | Rate limiting is in-memory, per instance | Low | Replicas don't share it. Rate limit at the edge. |
| 5 | Mid-download disconnect still spends a view | Low | On purpose, since the alternative leaves orphaned files. |
| 6 | Whole file held in browser memory during encryption | Low | A 256 MB upload needs several times that in browser memory. Chunked client-side encryption would fix it. |
| 7 | `style-src 'unsafe-inline'`, CDN origins in `script-src`, and `blob:` in `img-src` | Low | SRI hashes pin the CDN assets, and `script-src` has no `unsafe-inline`. `blob:` exists only for decrypted image previews, see T8. Self-hosting the CDN assets would close the CDN part. |
| 8 | Argon2 at 64 MiB, t=2 | Low | Reasonable for a browser, but below what a server-side deployment could afford. Raising it is a breaking format change today, see #1. |
| 9 | WASM toolchain provenance | Low | The build calls `cargo` and `wasm-bindgen` directly, with `wasm-bindgen-cli` pinned at 0.2.128 in the Dockerfile. Nothing verifies that the shipped `crypto_bg.wasm` came from the reviewed source. A reproducible build plus a published hash would close it. Part of the T5 surface. |
| 10 | No security disclosure policy | Medium, process | There is no documented way to report a vulnerability and no statement about how a fix would ship. This matters much more if the crypto is ever published as a reusable library. |

---

## 8. Deployer responsibilities

Whisper's guarantees assume the following, and the format can't enforce any of it:

- Serve over TLS with HSTS. The server sets `max-age=31536000`.
- Self-host. Per T5, the operator can read secrets if they choose to. An internal instance run by the team that uses it makes the operator and the data owner the same party.
- Rate limit at the edge when running more than one replica.
- Restrict storage backend access. A leaked S3 or GCS credential is a T4 compromise. It yields ciphertext, not plaintext, but it is still an incident.
- Don't log request bodies. They contain `passwordHash`, which is a bearer token. They never contain the passphrase or salt.
- Tell users to send the link and passphrase separately, and that an unexpected "already viewed" means someone else read the secret.
- Keep `ADVANCED_FEATURES` off unless no-expiry secrets are needed. With it off the server requires a TTL of at most 30 days on every secret. The server accepts `viewCount: 0`, which means unlimited views, whether or not the flag is on.
