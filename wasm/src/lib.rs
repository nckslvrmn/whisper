use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 16;
const HEADER_SIZE: usize = 16;
const PASSPHRASE_LENGTH: usize = 32;
const KEY_SIZE: usize = 32;
// URL_SAFE (padded) base64 of SALT_SIZE bytes = ceil(16/3)*4 = 24 chars.
// The display passphrase is b64(salt) || random_chars, split at this boundary.
const SALT_B64_LEN: usize = 24;
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 2;
const ARGON2_P_COST: u32 = 1;

fn rand_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    bytes
}

fn rand_string(length: usize) -> String {
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_~";
    const CHAR_LEN: usize = CHARS.len(); // 75
    const ACCEPT_BELOW: usize = (256 / CHAR_LEN) * CHAR_LEN; // 225

    let mut result = Vec::with_capacity(length);
    while result.len() < length {
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

    let now_secs = js_sys::Date::now() as i64 / 1000;
    (now_secs + (ttl as i64 * 86400)) as f64
}

fn derive_keys(passphrase: &str, salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .expect("invalid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut root = vec![0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut root)
        .expect("argon2 failed");

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

fn err_js(msg: &str) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &JsValue::from_str("error"), &JsValue::from_str(msg)).unwrap();
    obj.into()
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
}

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
    } else {
        ttl_days.as_ref().map(|days| sanitize_ttl_days(days))
    };

    let encrypted = match xchacha_encrypt(&passphrase, &nonce, &salt, &header, text.as_bytes()) {
        Ok(d) => d,
        Err(e) => return err_js(&e),
    };

    let password_hash = hash_password_internal(&passphrase, &salt);

    // The display passphrase embeds the salt so it never needs to be stored or
    // returned by the server. Layout: b64(salt) || passphrase_chars.
    // The JS split boundary is SALT_B64_LEN (24) chars.
    let salt_b64 = b64e(&salt);
    debug_assert_eq!(salt_b64.len(), SALT_B64_LEN, "b64e(salt) length mismatch — SALT_B64_LEN constant is wrong");
    let display_passphrase = format!("{}{}", salt_b64, passphrase);

    let obj = js_sys::Object::new();
    let s = |k: &str, v: &str| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    };
    s("passphrase", &display_passphrase);
    s("nonce", &b64e(&nonce));
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
    let file_data = match STANDARD.decode(&file_data_b64) {
        Ok(d) => d,
        Err(e) => return err_js(&format!("Invalid file data: {e}")),
    };

    let passphrase = rand_string(PASSPHRASE_LENGTH);
    let file_nonce = rand_bytes(NONCE_SIZE);
    let salt = rand_bytes(SALT_SIZE);
    let header = rand_bytes(HEADER_SIZE);

    let ttl: Option<f64> = if let Some(ref ts) = ttl_timestamp {
        Some(ts.parse().unwrap_or_else(|_| sanitize_ttl_days("7")))
    } else {
        ttl_days.as_ref().map(|days| sanitize_ttl_days(days))
    };

    let encrypted_file = match xchacha_encrypt(&passphrase, &file_nonce, &salt, &header, &file_data)
    {
        Ok(d) => d,
        Err(e) => return err_js(&e),
    };

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

    let mut encrypted_metadata = meta_nonce;
    encrypted_metadata.extend_from_slice(&encrypted_metadata_raw);

    let password_hash = hash_password_internal(&passphrase, &salt);

    let display_passphrase = format!("{}{}", b64e(&salt), passphrase);

    let obj = js_sys::Object::new();
    let s = |k: &str, v: &str| {
        js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v)).unwrap();
    };
    s("passphrase", &display_passphrase);
    s("nonce", &b64e(&file_nonce));
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
    if nonce.len() != NONCE_SIZE {
        return err_js("Invalid nonce length");
    }
    let salt = match b64d(&salt_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid salt"),
    };
    if salt.len() != SALT_SIZE {
        return err_js("Invalid salt length");
    }
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
    if nonce.len() != NONCE_SIZE {
        return err_js("Invalid nonce length");
    }
    let salt = match b64d(&salt_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid salt"),
    };
    if salt.len() != SALT_SIZE {
        return err_js("Invalid salt length");
    }
    let header = match b64d(&header_b64) {
        Ok(d) => d,
        Err(_) => return err_js("Invalid header"),
    };

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
    if salt.len() != SALT_SIZE {
        return Err(JsValue::from_str("Invalid salt length"));
    }
    Ok(hash_password_internal(&password, &salt))
}

// ─── Unit tests ───────────────────────────────────────────────────────────────
//
// These tests exercise the pure-Rust internal functions (no JS/WASM runtime
// needed).  Run with: cargo test
//
// NOTE: sanitize_ttl_days is intentionally not tested here because it calls
// js_sys::Date::now() which is only available in a WASM context.

#[cfg(test)]
mod tests {
    use super::*;

    // ── b64e / b64d ──────────────────────────────────────────────────────────

    #[test]
    fn test_b64_roundtrip_empty() {
        let encoded = b64e(&[]);
        let decoded = b64d(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_b64_roundtrip_bytes() {
        let data: Vec<u8> = (0u8..=255).collect();
        let encoded = b64e(&data);
        let decoded = b64d(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_b64_roundtrip_text() {
        let data = b"hello world";
        let encoded = b64e(data);
        let decoded = b64d(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_b64d_invalid_returns_error() {
        assert!(b64d("not!!valid base64").is_err());
    }

    #[test]
    fn test_b64e_uses_url_safe_alphabet() {
        // Force bytes that would produce '+' and '/' in standard base64
        // (0b11111011 = 0xFB, 0b11101111 = 0xEF, 0b10111110 = 0xBE => "+/+")
        let data = vec![0xFB, 0xEF, 0xBE];
        let encoded = b64e(&data);
        assert!(!encoded.contains('+'), "URL-safe b64 must not contain '+'");
        assert!(!encoded.contains('/'), "URL-safe b64 must not contain '/'");
    }

    // ── sanitize_view_count ──────────────────────────────────────────────────

    #[test]
    fn test_sanitize_view_count_valid_range() {
        for vc in 1..=10 {
            assert_eq!(sanitize_view_count(&vc.to_string()), vc);
        }
    }

    #[test]
    fn test_sanitize_view_count_zero_defaults_to_one() {
        assert_eq!(sanitize_view_count("0"), 1);
    }

    #[test]
    fn test_sanitize_view_count_above_max_defaults_to_one() {
        assert_eq!(sanitize_view_count("11"), 1);
        assert_eq!(sanitize_view_count("100"), 1);
    }

    #[test]
    fn test_sanitize_view_count_negative_defaults_to_one() {
        assert_eq!(sanitize_view_count("-1"), 1);
        assert_eq!(sanitize_view_count("-99"), 1);
    }

    #[test]
    fn test_sanitize_view_count_invalid_str_defaults_to_one() {
        assert_eq!(sanitize_view_count("abc"), 1);
        assert_eq!(sanitize_view_count(""), 1);
        assert_eq!(sanitize_view_count("  "), 1);
    }

    // ── derive_keys ──────────────────────────────────────────────────────────

    #[test]
    fn test_derive_keys_produces_correct_lengths() {
        let salt = vec![0u8; SALT_SIZE];
        let (enc_key, auth_key) = derive_keys("testpassphrase", &salt);
        assert_eq!(enc_key.len(), KEY_SIZE);
        assert_eq!(auth_key.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let salt = vec![42u8; SALT_SIZE];
        let (enc1, auth1) = derive_keys("mypassword", &salt);
        let (enc2, auth2) = derive_keys("mypassword", &salt);
        assert_eq!(enc1, enc2);
        assert_eq!(auth1, auth2);
    }

    #[test]
    fn test_derive_keys_different_passphrase_different_keys() {
        let salt = vec![0u8; SALT_SIZE];
        let (enc1, _) = derive_keys("passphrase1", &salt);
        let (enc2, _) = derive_keys("passphrase2", &salt);
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_derive_keys_different_salt_different_keys() {
        let salt1 = vec![0u8; SALT_SIZE];
        let salt2 = vec![1u8; SALT_SIZE];
        let (enc1, _) = derive_keys("samepassword", &salt1);
        let (enc2, _) = derive_keys("samepassword", &salt2);
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_derive_keys_enc_and_auth_are_different() {
        let salt = vec![7u8; SALT_SIZE];
        let (enc_key, auth_key) = derive_keys("testpass", &salt);
        assert_ne!(enc_key, auth_key, "enc_key and auth_key must be distinct");
    }

    // ── xchacha_encrypt / xchacha_decrypt ─────────────────────────────────

    fn make_nonce() -> Vec<u8> { vec![0u8; NONCE_SIZE] }
    fn make_salt()  -> Vec<u8> { vec![1u8; SALT_SIZE]  }
    fn make_header() -> Vec<u8> { vec![2u8; HEADER_SIZE] }

    #[test]
    fn test_encrypt_decrypt_roundtrip_text() {
        let plaintext = b"hello, whisper!";
        let passphrase = "secretpass";
        let nonce = make_nonce();
        let salt = make_salt();
        let header = make_header();

        let ciphertext = xchacha_encrypt(passphrase, &nonce, &salt, &header, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = xchacha_decrypt(passphrase, &nonce, &salt, &header, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty() {
        let passphrase = "pass";
        let nonce = make_nonce();
        let salt = make_salt();
        let header = make_header();

        let ciphertext = xchacha_encrypt(passphrase, &nonce, &salt, &header, b"").unwrap();
        let decrypted = xchacha_decrypt(passphrase, &nonce, &salt, &header, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_binary() {
        let data: Vec<u8> = (0u8..=255).collect();
        let passphrase = "binarypass";
        let nonce = make_nonce();
        let salt = make_salt();
        let header = make_header();

        let ciphertext = xchacha_encrypt(passphrase, &nonce, &salt, &header, &data).unwrap();
        let decrypted = xchacha_decrypt(passphrase, &nonce, &salt, &header, &ciphertext).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_wrong_passphrase_fails() {
        let plaintext = b"secret message";
        let nonce = make_nonce();
        let salt = make_salt();
        let header = make_header();

        let ciphertext = xchacha_encrypt("correctpass", &nonce, &salt, &header, plaintext).unwrap();
        let result = xchacha_decrypt("wrongpass", &nonce, &salt, &header, &ciphertext);
        assert!(result.is_err(), "decryption with wrong passphrase must fail");
    }

    #[test]
    fn test_decrypt_wrong_nonce_fails() {
        let plaintext = b"secret message";
        let nonce1 = vec![0u8; NONCE_SIZE];
        let nonce2 = vec![1u8; NONCE_SIZE];
        let salt = make_salt();
        let header = make_header();

        let ciphertext = xchacha_encrypt("pass", &nonce1, &salt, &header, plaintext).unwrap();
        let result = xchacha_decrypt("pass", &nonce2, &salt, &header, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_header_fails() {
        let plaintext = b"secret message";
        let nonce = make_nonce();
        let salt = make_salt();
        let header1 = vec![0u8; HEADER_SIZE];
        let header2 = vec![1u8; HEADER_SIZE];

        let ciphertext = xchacha_encrypt("pass", &nonce, &salt, &header1, plaintext).unwrap();
        let result = xchacha_decrypt("pass", &nonce, &salt, &header2, &ciphertext);
        assert!(result.is_err(), "wrong AAD header must cause decryption failure");
    }

    #[test]
    fn test_decrypt_wrong_salt_fails() {
        let plaintext = b"secret";
        let nonce = make_nonce();
        let salt1 = vec![0u8; SALT_SIZE];
        let salt2 = vec![1u8; SALT_SIZE];
        let header = make_header();

        let ciphertext = xchacha_encrypt("pass", &nonce, &salt1, &header, plaintext).unwrap();
        let result = xchacha_decrypt("pass", &nonce, &salt2, &header, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let plaintext = b"integrity test";
        let nonce = make_nonce();
        let salt = make_salt();
        let header = make_header();

        let mut ciphertext = xchacha_encrypt("pass", &nonce, &salt, &header, plaintext).unwrap();
        // Flip a bit in the middle of the ciphertext
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;
        let result = xchacha_decrypt("pass", &nonce, &salt, &header, &ciphertext);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let plaintext = b"do not store in plaintext";
        let ciphertext = xchacha_encrypt("pass", &make_nonce(), &make_salt(), &make_header(), plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
    }

    #[test]
    fn test_ciphertext_length_is_plaintext_plus_tag() {
        // XChaCha20Poly1305 appends a 16-byte authentication tag
        let plaintext = b"exactly 10 bytes!";
        let ciphertext = xchacha_encrypt("pass", &make_nonce(), &make_salt(), &make_header(), plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    // ── hash_password_internal ───────────────────────────────────────────────

    #[test]
    fn test_hash_password_internal_deterministic() {
        let salt = vec![5u8; SALT_SIZE];
        let h1 = hash_password_internal("mypassphrase", &salt);
        let h2 = hash_password_internal("mypassphrase", &salt);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_password_internal_is_64_char_hex() {
        let salt = vec![0u8; SALT_SIZE];
        let hash = hash_password_internal("anypassphrase", &salt);
        assert_eq!(hash.len(), 64, "auth key must be 64 hex chars (32 bytes)");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "hash must be lowercase hex: {}", hash);
    }

    #[test]
    fn test_hash_password_different_passphrases_different_hashes() {
        let salt = vec![0u8; SALT_SIZE];
        let h1 = hash_password_internal("pass1", &salt);
        let h2 = hash_password_internal("pass2", &salt);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_password_different_salts_different_hashes() {
        let salt1 = vec![0u8; SALT_SIZE];
        let salt2 = vec![1u8; SALT_SIZE];
        let h1 = hash_password_internal("samepass", &salt1);
        let h2 = hash_password_internal("samepass", &salt2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_is_different_from_enc_key() {
        // auth_key ≠ enc_key (HKDF uses different labels)
        let salt = vec![3u8; SALT_SIZE];
        let (enc_key, auth_key) = derive_keys("samepass", &salt);
        assert_ne!(hex::encode(enc_key), hex::encode(auth_key));
    }

    // ── salt / passphrase splitting ───────────────────────────────────────────

    #[test]
    fn test_salt_b64_length_constant_matches_actual_encoding() {
        // SALT_B64_LEN must equal the length of URL_SAFE b64(SALT_SIZE bytes)
        let salt = vec![0u8; SALT_SIZE];
        let encoded = b64e(&salt);
        assert_eq!(
            encoded.len(),
            SALT_B64_LEN,
            "SALT_B64_LEN ({}) != actual b64 length ({})", SALT_B64_LEN, encoded.len()
        );
    }

    #[test]
    fn test_display_passphrase_can_be_split_to_recover_salt() {
        let salt_bytes = vec![0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        assert_eq!(salt_bytes.len(), SALT_SIZE);

        let passphrase_part = "thisIsThe32CharRandomPassphrase!";
        let salt_b64 = b64e(&salt_bytes);
        assert_eq!(salt_b64.len(), SALT_B64_LEN);

        let display_passphrase = format!("{}{}", salt_b64, passphrase_part);

        // Simulating what JS does: split at SALT_B64_LEN
        let (recovered_salt_b64, recovered_passphrase) = display_passphrase.split_at(SALT_B64_LEN);
        let recovered_salt = b64d(recovered_salt_b64).unwrap();

        assert_eq!(recovered_salt, salt_bytes);
        assert_eq!(recovered_passphrase, passphrase_part);
    }

    // ── rand_bytes / rand_string ──────────────────────────────────────────────

    #[test]
    fn test_rand_bytes_length() {
        for len in [0, 1, 16, 32, 64] {
            assert_eq!(rand_bytes(len).len(), len);
        }
    }

    #[test]
    fn test_rand_bytes_uniqueness() {
        let a = rand_bytes(32);
        let b = rand_bytes(32);
        assert_ne!(a, b, "two independent rand_bytes(32) calls returned same value");
    }

    #[test]
    fn test_rand_string_length() {
        for len in [1, 16, 32, 64] {
            assert_eq!(rand_string(len).len(), len);
        }
    }

    #[test]
    fn test_rand_string_uniqueness() {
        let a = rand_string(32);
        let b = rand_string(32);
        assert_ne!(a, b, "two rand_string(32) calls returned identical strings");
    }

    #[test]
    fn test_rand_string_chars_are_in_alphabet() {
        const ALPHABET: &str =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_~";
        for _ in 0..10 {
            let s = rand_string(128);
            for c in s.chars() {
                assert!(ALPHABET.contains(c), "unexpected char {:?} in rand_string output", c);
            }
        }
    }

    // ── file metadata round-trip (simulates encrypt_file / decrypt_file flow) ─

    #[test]
    fn test_file_metadata_encrypt_decrypt_roundtrip() {
        let passphrase = "filepass";
        let file_nonce = vec![10u8; NONCE_SIZE];
        let meta_nonce = vec![20u8; NONCE_SIZE];
        let salt = make_salt();
        let header = make_header();

        let file_data = b"binary file content here";
        let metadata_json = r#"{"file_name":"test.txt","file_type":"text/plain"}"#;

        // Encrypt file
        let enc_file = xchacha_encrypt(passphrase, &file_nonce, &salt, &header, file_data).unwrap();

        // Encrypt metadata (meta_nonce prepended)
        let enc_meta_raw = xchacha_encrypt(passphrase, &meta_nonce, &salt, &header, metadata_json.as_bytes()).unwrap();
        let mut enc_meta_blob = meta_nonce.clone();
        enc_meta_blob.extend_from_slice(&enc_meta_raw);

        // Decrypt — split enc_meta_blob
        let (recovered_meta_nonce, enc_meta) = enc_meta_blob.split_at(NONCE_SIZE);
        let dec_meta = xchacha_decrypt(passphrase, recovered_meta_nonce, &salt, &header, enc_meta).unwrap();
        let dec_file = xchacha_decrypt(passphrase, &file_nonce, &salt, &header, &enc_file).unwrap();

        assert_eq!(dec_file, file_data);
        assert_eq!(String::from_utf8(dec_meta).unwrap(), metadata_json);
    }

    #[test]
    fn test_file_and_text_use_independent_nonces() {
        // Encrypting with two different nonces produces different ciphertext for the same plaintext
        let data = b"same plaintext";
        let pass = "samepass";
        let salt = make_salt();
        let header = make_header();

        let ct1 = xchacha_encrypt(pass, &vec![0u8; NONCE_SIZE], &salt, &header, data).unwrap();
        let ct2 = xchacha_encrypt(pass, &vec![1u8; NONCE_SIZE], &salt, &header, data).unwrap();
        assert_ne!(ct1, ct2, "different nonces must produce different ciphertext");
    }
}
