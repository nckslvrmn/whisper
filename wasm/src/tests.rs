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
