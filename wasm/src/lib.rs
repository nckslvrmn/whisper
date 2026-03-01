use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

// ── constants ────────────────────────────────────────────────────────────────
// Crypto constants must match across encrypt/decrypt. Changing these breaks
// all existing secrets — backwards compat is intentionally dropped here.
const NONCE_SIZE: usize = 24; // XChaCha20-Poly1305 uses 192-bit (24-byte) nonces
const SALT_SIZE: usize = 16;
const HEADER_SIZE: usize = 16;
const PASSPHRASE_LENGTH: usize = 32;
const KEY_SIZE: usize = 32;
// Argon2id — OWASP high-security profile. p=1 is correct for WASM (single-threaded).
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 2; // iterations
const ARGON2_P_COST: u32 = 1; // parallelism

// ── randomness ───────────────────────────────────────────────────────────────
// All randomness goes directly through getrandom, which calls
// crypto.getRandomValues() in the browser. We never touch rand or thread_rng.

fn rand_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

fn rand_string(length: usize) -> String {
    // Matches Go: alphaNum + special chars (urlSafe = false).
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_~";
    const CHAR_LEN: usize = CHARS.len(); // 75
    // Rejection sampling: only accept bytes < 225 (= 3 * 75) so each character
    // maps to exactly 3 raw byte values, eliminating modulo bias entirely.
    const ACCEPT_BELOW: usize = (256 / CHAR_LEN) * CHAR_LEN; // 225

    let mut result = Vec::with_capacity(length);
    while result.len() < length {
        // Over-allocate to minimise the number of getrandom calls (rejection
        // rate is ~12% so 2× the needed bytes is plenty).
        let mut buf = vec![0u8; (length - result.len()) * 2];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        for b in buf {
            if (b as usize) < ACCEPT_BELOW {
                result.push(CHARS[b as usize % CHAR_LEN] as char);
                if result.len() == length {
                    break;
                }
            }
        }
    }
    result.into_iter().collect()
}

// ── helpers ───────────────────────────────────────────────────────────────────

// Matches Go's base64.URLEncoding: URL-safe alphabet with = padding.
fn b64e(data: &[u8]) -> String {
    URL_SAFE.encode(data)
}

fn b64d(data: &str) -> Result<Vec<u8>, String> {
    URL_SAFE
        .decode(data)
        .map_err(|e| format!("base64 decode: {e}"))
}

fn sanitize_view_count(vc_str: &str) -> i32 {
    let vc: i32 = vc_str.parse().unwrap_or(1);
    if vc <= 0 || vc > 10 { 1 } else { vc }
}

fn sanitize_ttl_days(days_str: &str) -> f64 {
    let ttl: i32 = days_str.parse().unwrap_or(7);
    let ttl = if [1i32, 3, 7, 14, 30].contains(&ttl) {
        ttl
    } else {
        7
    };
    // Use integer division to guarantee a whole-second Unix timestamp.
    // Date::now() returns milliseconds; dividing as i64 truncates the ms part.
    let now_secs = js_sys::Date::now() as i64 / 1000;
    (now_secs + (ttl as i64 * 86400)) as f64
}

// Derive two independent keys from a single expensive Argon2id call.
// enc_key  → XChaCha20-Poly1305 encryption; never leaves the client.
// auth_key → stored server-side as passwordHash; cannot recover enc_key.
fn derive_keys(passphrase: &str, salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Single expensive Argon2id call produces the root key material.
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .expect("invalid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut root = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut root)
        .expect("argon2 failed");

    // Cheap HKDF expansion splits root into two domain-separated keys.
    let hk = Hkdf::<Sha256>::new(Some(salt), &root);
    let mut enc_key = vec![0u8; KEY_SIZE];
    let mut auth_key = vec![0u8; KEY_SIZE];
    hk.expand(b"whisper-encryption-v1", &mut enc_key)
        .expect("hkdf expand failed");
    hk.expand(b"whisper-auth-v1", &mut auth_key)
        .expect("hkdf expand failed");

    (enc_key, auth_key)
}

fn xchacha_encrypt(
    passphrase: &str,
    nonce: &[u8],
    salt: &[u8],
    header: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let (enc_key, _) = derive_keys(passphrase, salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&enc_key).expect("key is 32 bytes");
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: data,
                aad: header,
            },
        )
        .map_err(|e| e.to_string())
}

fn xchacha_decrypt(
    passphrase: &str,
    nonce: &[u8],
    salt: &[u8],
    header: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let (enc_key, _) = derive_keys(passphrase, salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&enc_key).expect("key is 32 bytes");
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: data,
                aad: header,
            },
        )
        .map_err(|e| e.to_string())
}

fn hash_password_internal(password: &str, salt: &[u8]) -> String {
    let (_, auth_key) = derive_keys(password, salt);
    hex::encode(auth_key)
}

// Build a JS object with a single "error" field.
fn err_js(msg: &str) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("error"), &JsValue::from_str(msg)).unwrap();
    obj.into()
}

// ── module init ───────────────────────────────────────────────────────────────

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

// ── exported functions ────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = "encryptText")]
pub fn encrypt_text(
    text: String,
    view_count: Option<String>,
    ttl_days: Option<String>,
    ttl_timestamp: Option<String>,
) -> JsValue {
    let passphrase = rand_string(PASSPHRASE_LENGTH);
    let nonce = rand_bytes(NONCE_SIZE);
    let salt = rand_bytes(SALT_SIZE);
    let header = rand_bytes(HEADER_SIZE);

    // None for both = "disable TTL" (no expiry). Otherwise resolve to a Unix timestamp.
    let ttl: Option<f64> = if let Some(ref ts) = ttl_timestamp {
        Some(ts.parse().unwrap_or_else(|_| sanitize_ttl_days("7")))
    } else if let Some(ref days) = ttl_days {
        Some(sanitize_ttl_days(days))
    } else {
        None
    };

    let encrypted = match xchacha_encrypt(&passphrase, &nonce, &salt, &header, text.as_bytes()) {
        Ok(d) => d,
        Err(e) => return err_js(&e),
    };

    let password_hash = hash_password_internal(&passphrase, &salt);

    let obj = js_sys::Object::new();
    let s = |k: &str, v: &str| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    };
    s("passphrase", &passphrase);
    s("nonce", &b64e(&nonce));
    s("salt", &b64e(&salt));
    s("header", &b64e(&header));
    s("passwordHash", &password_hash);
    s("encryptedData", &b64e(&encrypted));
    if let Some(t) = ttl {
        js_sys::Reflect::set(&obj, &JsValue::from_str("ttl"), &JsValue::from_f64(t)).unwrap();
    }
    if let Some(ref vc) = view_count {
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("viewCount"),
            &JsValue::from_f64(sanitize_view_count(vc) as f64),
        )
        .unwrap();
    }
    obj.into()
}

#[wasm_bindgen(js_name = "encryptFile")]
pub fn encrypt_file(
    file_data_b64: String,
    file_name: String,
    file_type: String,
    view_count: Option<String>,
    ttl_days: Option<String>,
    ttl_timestamp: Option<String>,
) -> JsValue {
    // File data arrives as standard (non-URL-safe) base64 from arrayBufferToBase64().
    let file_data = match STANDARD.decode(&file_data_b64) {
        Ok(d) => d,
        Err(e) => return err_js(&format!("Invalid file data: {e}")),
    };

    let passphrase = rand_string(PASSPHRASE_LENGTH);
    let file_nonce = rand_bytes(NONCE_SIZE);
    let salt = rand_bytes(SALT_SIZE);
    let header = rand_bytes(HEADER_SIZE);

    // None for both = "disable TTL" (no expiry). Otherwise resolve to a Unix timestamp.
    let ttl: Option<f64> = if let Some(ref ts) = ttl_timestamp {
        Some(ts.parse().unwrap_or_else(|_| sanitize_ttl_days("7")))
    } else if let Some(ref days) = ttl_days {
        Some(sanitize_ttl_days(days))
    } else {
        None
    };

    let encrypted_file = match xchacha_encrypt(&passphrase, &file_nonce, &salt, &header, &file_data)
    {
        Ok(d) => d,
        Err(e) => return err_js(&e),
    };

    // Use a dedicated nonce for metadata to prevent nonce reuse under the same key.
    // The meta_nonce is prepended to the ciphertext so the server stores it
    // as part of the opaque encryptedMetadata blob — no server-side changes needed.
    let meta_nonce = rand_bytes(NONCE_SIZE);
    let metadata_json = serde_json::json!({
        "file_name": file_name,
        "file_type": file_type,
    })
    .to_string();
    let encrypted_metadata_raw = match xchacha_encrypt(
        &passphrase,
        &meta_nonce,
        &salt,
        &header,
        metadata_json.as_bytes(),
    ) {
        Ok(d) => d,
        Err(e) => return err_js(&e),
    };
    // Layout: meta_nonce (24 bytes) || ciphertext
    let mut encrypted_metadata = meta_nonce;
    encrypted_metadata.extend_from_slice(&encrypted_metadata_raw);

    let password_hash = hash_password_internal(&passphrase, &salt);

    let obj = js_sys::Object::new();
    let s = |k: &str, v: &str| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    };
    s("passphrase", &passphrase);
    s("nonce", &b64e(&file_nonce));
    s("salt", &b64e(&salt));
    s("header", &b64e(&header));
    s("passwordHash", &password_hash);
    s("encryptedFile", &b64e(&encrypted_file));
    s("encryptedMetadata", &b64e(&encrypted_metadata));
    if let Some(t) = ttl {
        js_sys::Reflect::set(&obj, &JsValue::from_str("ttl"), &JsValue::from_f64(t)).unwrap();
    }
    if let Some(ref vc) = view_count {
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("viewCount"),
            &JsValue::from_f64(sanitize_view_count(vc) as f64),
        )
        .unwrap();
    }
    obj.into()
}

#[wasm_bindgen(js_name = "decryptText")]
pub fn decrypt_text(
    encrypted_data_b64: String,
    passphrase: String,
    nonce_b64: String,
    salt_b64: String,
    header_b64: String,
) -> JsValue {
    let encrypted = match b64d(&encrypted_data_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid encrypted data"),
    };
    let nonce = match b64d(&nonce_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid nonce"),
    };
    let salt = match b64d(&salt_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid salt"),
    };
    let header = match b64d(&header_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid header"),
    };

    let decrypted = match xchacha_decrypt(&passphrase, &nonce, &salt, &header, &encrypted) {
        Ok(d) => d,
        Err(e) => return err_js(&format!("Decryption failed: {e}")),
    };

    let text = match String::from_utf8(decrypted) {
        Ok(s) => s,
        Err(_) => return err_js("Decrypted data is not valid UTF-8"),
    };

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("data"), &JsValue::from_str(&text)).unwrap();
    obj.into()
}

#[wasm_bindgen(js_name = "decryptFile")]
pub fn decrypt_file(
    encrypted_file_b64: String,
    encrypted_metadata_b64: String,
    passphrase: String,
    nonce_b64: String,
    salt_b64: String,
    header_b64: String,
) -> JsValue {
    let enc_file = match b64d(&encrypted_file_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid encrypted file"),
    };
    let enc_meta_blob = match b64d(&encrypted_metadata_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid encrypted metadata"),
    };
    let nonce = match b64d(&nonce_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid nonce"),
    };
    let salt = match b64d(&salt_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid salt"),
    };
    let header = match b64d(&header_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid header"),
    };

    // Parse the embedded meta_nonce from the front of the metadata blob.
    // Layout: meta_nonce (24 bytes) || ciphertext
    if enc_meta_blob.len() <= NONCE_SIZE {
        return err_js("Encrypted metadata too short");
    }
    let (meta_nonce, enc_meta) = enc_meta_blob.split_at(NONCE_SIZE);

    let meta_bytes = match xchacha_decrypt(&passphrase, meta_nonce, &salt, &header, enc_meta) {
        Ok(d) => d,
        Err(e) => return err_js(&format!("Metadata decryption failed: {e}")),
    };

    let metadata: serde_json::Value = match serde_json::from_slice(&meta_bytes) {
        Ok(m) => m,
        Err(_) => return err_js("Invalid metadata"),
    };

    let file_data = match xchacha_decrypt(&passphrase, &nonce, &salt, &header, &enc_file) {
        Ok(d) => d,
        Err(e) => return err_js(&format!("File decryption failed: {e}")),
    };

    let file_name = metadata["file_name"].as_str().unwrap_or("").to_string();
    let file_type = metadata["file_type"].as_str().unwrap_or("").to_string();
    // Return file data as standard base64 to match what base64ToBlob() expects.
    let file_data_b64 = STANDARD.encode(&file_data);

    let obj = js_sys::Object::new();
    let s = |k: &str, v: &str| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    };
    s("fileData", &file_data_b64);
    s("fileName", &file_name);
    s("fileType", &file_type);
    obj.into()
}

#[wasm_bindgen(js_name = "hashPassword")]
pub fn hash_password(password: String, salt_b64: String) -> Result<String, JsValue> {
    let salt = b64d(&salt_b64).map_err(|e| JsValue::from_str(&e))?;
    Ok(hash_password_internal(&password, &salt))
}
