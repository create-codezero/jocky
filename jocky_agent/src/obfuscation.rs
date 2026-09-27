//! JOCKY Secure Payload / Configuration Utilities
//!
//! This module provides cryptographic protection for JOCKY forensic
//! configuration, IR metadata, and locally stored evidence.
//!
//! Security properties:
//! - AES-256-GCM authenticated encryption
//! - Random 256-bit keys
//! - Random 96-bit nonces
//! - SHA-256 integrity fingerprints
//! - Explicit versioning for serialized encrypted blobs
//! - Zeroization of sensitive key material
//!
//! This module is intentionally NOT an AV/EDR evasion mechanism.
//! It does not perform:
//! - runtime API hiding
//! - import-table manipulation
//! - anti-analysis tricks
//! - process injection
//! - direct syscall execution
//! - API unhooking
//! - payload hiding inside trusted processes
//!
//! Intended architecture:
//
//!     JOCKY IR
//!        |
//!        v
//!   serialize JSON
//!        |
//!        v
//!   encrypt_ir()
//!        |
//!        v
//!   EncryptedBlob
//!        |
//!        v
//!   Rust agent
//!        |
//!        v
//!   decrypt_ir()
//!
//! Cargo dependencies required:
//
//! aes-gcm = "0.10"
//! rand = "0.8"
//! sha2 = "0.10"
//! zeroize = "1"

use aes_gcm::{
    aead::{
        Aead,
        KeyInit,
    },
    Aes256Gcm,
    Key,
    Nonce,
};

use rand::{
    rngs::OsRng,
    RngCore,
};

use sha2::{
    Digest,
    Sha256,
};

use zeroize::Zeroize;

use std::fmt;


// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

/// AES-256 key length in bytes.
pub const KEY_SIZE: usize = 32;

/// AES-GCM standard nonce size.
pub const NONCE_SIZE: usize = 12;

/// SHA-256 digest size.
pub const HASH_SIZE: usize = 32;

/// Current encrypted payload format version.
pub const FORMAT_VERSION: u8 = 1;

/// Prefix used when serializing encrypted blobs.
pub const FORMAT_MAGIC: &[u8; 4] = b"JKOB";


// ----------------------------------------------------------------------
// Error type
// ----------------------------------------------------------------------

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidHex(String),
    InvalidBlob(String),
    UnsupportedVersion(u8),
    InvalidMagic,
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for CryptoError {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        match self {
            Self::EncryptionFailed => {
                write!(f, "encryption failed")
            }

            Self::DecryptionFailed => {
                write!(f, "decryption failed")
            }

            Self::InvalidKeyLength => {
                write!(f, "invalid AES-256 key length")
            }

            Self::InvalidNonceLength => {
                write!(f, "invalid AES-GCM nonce length")
            }

            Self::InvalidHex(value) => {
                write!(f, "invalid hexadecimal data: {value}")
            }

            Self::InvalidBlob(value) => {
                write!(f, "invalid encrypted blob: {value}")
            }

            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "unsupported encrypted blob version: {version}"
                )
            }

            Self::InvalidMagic => {
                write!(f, "invalid encrypted blob magic")
            }

            Self::Utf8(err) => {
                write!(f, "UTF-8 decoding failed: {err}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(
        value: std::string::FromUtf8Error,
    ) -> Self {
        Self::Utf8(value)
    }
}


// ----------------------------------------------------------------------
// Key type
// ----------------------------------------------------------------------

/// Wrapper around a 32-byte AES-256 key.
///
/// The internal byte array is automatically zeroized when dropped.
#[derive(Clone)]
pub struct EncryptionKey {
    bytes: [u8; KEY_SIZE],
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl EncryptionKey {
    /// Generate a cryptographically secure random AES-256 key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_SIZE];

        OsRng.fill_bytes(&mut bytes);

        Self { bytes }
    }

    /// Construct a key from exactly 32 bytes.
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<Self, CryptoError> {
        if bytes.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeyLength);
        }

        let mut key = [0u8; KEY_SIZE];

        key.copy_from_slice(bytes);

        Ok(Self { bytes: key })
    }

    /// Return a copy of the raw key bytes.
    ///
    /// Callers should avoid persisting this value unnecessarily.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }

    /// Export the key as hexadecimal text.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.bytes)
    }

    /// Import an AES-256 key from hexadecimal text.
    pub fn from_hex(
        value: &str,
    ) -> Result<Self, CryptoError> {
        let decoded = decode_hex(value)?;

        Self::from_bytes(&decoded)
    }
}


// ----------------------------------------------------------------------
// Encrypted blob
// ----------------------------------------------------------------------

/// Self-contained encrypted payload.
///
/// Layout:
///
/// ```text
/// +--------+---------+-------+----------+
/// | MAGIC  | VERSION | NONCE | CIPHERTEXT
/// | 4 byte | 1 byte  | 12 B  | variable
/// +--------+---------+-------+----------+
/// ```
///
/// The AES-GCM authentication tag is included by the `aes-gcm` crate
/// at the end of the ciphertext.
#[derive(Clone, Debug)]
pub struct EncryptedBlob {
    pub version: u8,
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Encrypt arbitrary bytes using AES-256-GCM.
    pub fn encrypt(
        plaintext: &[u8],
        key: &EncryptionKey,
    ) -> Result<Self, CryptoError> {
        let cipher =
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(
                key.as_bytes(),
            ));

        let mut nonce_bytes =
            [0u8; NONCE_SIZE];

        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce =
            Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| {
                CryptoError::EncryptionFailed
            })?;

        Ok(Self {
            version: FORMAT_VERSION,
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt an encrypted blob.
    pub fn decrypt(
        &self,
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.version != FORMAT_VERSION {
            return Err(
                CryptoError::UnsupportedVersion(
                    self.version,
                ),
            );
        }

        let cipher =
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(
                key.as_bytes(),
            ));

        let nonce =
            Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|_| {
                CryptoError::DecryptionFailed
            })
    }

    /// Serialize the encrypted blob into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(
            FORMAT_MAGIC.len()
                + 1
                + NONCE_SIZE
                + self.ciphertext.len(),
        );

        output.extend_from_slice(FORMAT_MAGIC);
        output.push(self.version);
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.ciphertext);

        output
    }

    /// Deserialize an encrypted blob.
    pub fn from_bytes(
        data: &[u8],
    ) -> Result<Self, CryptoError> {
        let minimum_size =
            FORMAT_MAGIC.len()
                + 1
                + NONCE_SIZE
                + 1;

        if data.len() < minimum_size {
            return Err(CryptoError::InvalidBlob(
                "blob is too small".to_string(),
            ));
        }

        if &data[0..4] != FORMAT_MAGIC {
            return Err(CryptoError::InvalidMagic);
        }

        let version = data[4];

        if version != FORMAT_VERSION {
            return Err(
                CryptoError::UnsupportedVersion(
                    version,
                ),
            );
        }

        let nonce_start = 5;
        let nonce_end =
            nonce_start + NONCE_SIZE;

        let mut nonce =
            [0u8; NONCE_SIZE];

        nonce.copy_from_slice(
            &data[nonce_start..nonce_end],
        );

        let ciphertext =
            data[nonce_end..].to_vec();

        if ciphertext.is_empty() {
            return Err(CryptoError::InvalidBlob(
                "ciphertext is empty".to_string(),
            ));
        }

        Ok(Self {
            version,
            nonce,
            ciphertext,
        })
    }

    /// Serialize the encrypted blob as hexadecimal.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.to_bytes())
    }

    /// Deserialize an encrypted blob from hexadecimal.
    pub fn from_hex(
        value: &str,
    ) -> Result<Self, CryptoError> {
        let bytes = decode_hex(value)?;

        Self::from_bytes(&bytes)
    }

    /// Number of ciphertext bytes.
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
}


// ----------------------------------------------------------------------
// High-level encryption helpers
// ----------------------------------------------------------------------

/// Encrypt a UTF-8 string.
///
/// Returns:
///
/// `(EncryptionKey, EncryptedBlob)`
pub fn encrypt_string(
    plaintext: &str,
) -> Result<(EncryptionKey, EncryptedBlob), CryptoError> {
    let key = EncryptionKey::generate();

    let blob =
        EncryptedBlob::encrypt(
            plaintext.as_bytes(),
            &key,
        )?;

    Ok((key, blob))
}

/// Decrypt an encrypted blob into a UTF-8 string.
pub fn decrypt_string(
    blob: &EncryptedBlob,
    key: &EncryptionKey,
) -> Result<String, CryptoError> {
    let plaintext =
        blob.decrypt(key)?;

    Ok(String::from_utf8(plaintext)?)
}

/// Encrypt JSON/IR bytes.
///
/// This is the function that `main.rs` or a future IR loader can use.
pub fn encrypt_ir(
    ir: &[u8],
    key: &EncryptionKey,
) -> Result<EncryptedBlob, CryptoError> {
    EncryptedBlob::encrypt(ir, key)
}

/// Decrypt JSON/IR bytes.
pub fn decrypt_ir(
    blob: &EncryptedBlob,
    key: &EncryptionKey,
) -> Result<Vec<u8>, CryptoError> {
    blob.decrypt(key)
}


// ----------------------------------------------------------------------
// SHA-256
// ----------------------------------------------------------------------

/// Calculate the SHA-256 digest of arbitrary data.
pub fn sha256(
    data: &[u8],
) -> [u8; HASH_SIZE] {
    let digest =
        Sha256::digest(data);

    let mut output =
        [0u8; HASH_SIZE];

    output.copy_from_slice(&digest);

    output
}

/// Calculate a SHA-256 digest and return hexadecimal text.
pub fn sha256_hex(
    data: &[u8],
) -> String {
    let digest = sha256(data);

    encode_hex(&digest)
}

/// Calculate the SHA-256 fingerprint of an encrypted blob.
pub fn blob_sha256_hex(
    blob: &EncryptedBlob,
) -> String {
    sha256_hex(&blob.to_bytes())
}


// ----------------------------------------------------------------------
// Hex encoding
// ----------------------------------------------------------------------

/// Convert bytes to lowercase hexadecimal.
pub fn encode_hex(
    data: &[u8],
) -> String {
    const HEX: &[u8; 16] =
        b"0123456789abcdef";

    let mut output =
        String::with_capacity(data.len() * 2);

    for byte in data {
        output.push(
            HEX[(byte >> 4) as usize]
                as char,
        );

        output.push(
            HEX[(byte & 0x0f) as usize]
                as char,
        );
    }

    output
}

/// Decode hexadecimal text into bytes.
pub fn decode_hex(
    value: &str,
) -> Result<Vec<u8>, CryptoError> {
    let value = value.trim();

    if value.len() % 2 != 0 {
        return Err(CryptoError::InvalidHex(
            "odd number of hexadecimal characters"
                .to_string(),
        ));
    }

    let bytes = value.as_bytes();

    let mut output =
        Vec::with_capacity(bytes.len() / 2);

    let mut index = 0;

    while index < bytes.len() {
        let high =
            hex_value(bytes[index])
                .ok_or_else(|| {
                    CryptoError::InvalidHex(
                        format!(
                            "invalid character at {}",
                            index
                        ),
                    )
                })?;

        let low =
            hex_value(bytes[index + 1])
                .ok_or_else(|| {
                    CryptoError::InvalidHex(
                        format!(
                            "invalid character at {}",
                            index + 1
                        ),
                    )
                })?;

        output.push((high << 4) | low);

        index += 2;
    }

    Ok(output)
}

fn hex_value(
    byte: u8,
) -> Option<u8> {
    match byte {
        b'0'..=b'9' => {
            Some(byte - b'0')
        }

        b'a'..=b'f' => {
            Some(byte - b'a' + 10)
        }

        b'A'..=b'F' => {
            Some(byte - b'A' + 10)
        }

        _ => None,
    }
}


// ----------------------------------------------------------------------
// Build metadata helper
// ----------------------------------------------------------------------

/// Cryptographic metadata associated with a JOCKY build.
///
/// This is useful for your CI/CD prototype because the management
/// server can verify exactly which artifact/configuration was sent.
#[derive(Debug, Clone)]
pub struct CryptoMetadata {
    pub format_version: u8,
    pub payload_sha256: String,
    pub encrypted_blob_sha256: String,
    pub encrypted_size: usize,
}

impl CryptoMetadata {
    pub fn from_blob(
        plaintext: &[u8],
        blob: &EncryptedBlob,
    ) -> Self {
        Self {
            format_version: blob.version,
            payload_sha256: sha256_hex(plaintext),
            encrypted_blob_sha256:
                blob_sha256_hex(blob),
            encrypted_size:
                blob.to_bytes().len(),
        }
    }
}


// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation_produces_32_bytes() {
        let key =
            EncryptionKey::generate();

        assert_eq!(
            key.as_bytes().len(),
            KEY_SIZE
        );
    }

    #[test]
    fn generated_keys_are_random() {
        let key_a =
            EncryptionKey::generate();

        let key_b =
            EncryptionKey::generate();

        assert_ne!(
            key_a.as_bytes(),
            key_b.as_bytes()
        );
    }

    #[test]
    fn encryption_roundtrip() {
        let key =
            EncryptionKey::generate();

        let original =
            b"JOCKY forensic IR test";

        let blob =
            EncryptedBlob::encrypt(
                original,
                &key,
            )
            .unwrap();

        let decrypted =
            blob.decrypt(&key)
                .unwrap();

        assert_eq!(
            original,
            decrypted.as_slice()
        );
    }

    #[test]
    fn wrong_key_fails() {
        let key_a =
            EncryptionKey::generate();

        let key_b =
            EncryptionKey::generate();

        let blob =
            EncryptedBlob::encrypt(
                b"secret forensic configuration",
                &key_a,
            )
            .unwrap();

        let result =
            blob.decrypt(&key_b);

        assert!(
            result.is_err()
        );
    }

    #[test]
    fn modified_ciphertext_fails() {
        let key =
            EncryptionKey::generate();

        let mut blob =
            EncryptedBlob::encrypt(
                b"JOCKY evidence",
                &key,
            )
            .unwrap();

        blob.ciphertext[0] ^= 0xff;

        let result =
            blob.decrypt(&key);

        assert!(
            result.is_err()
        );
    }

    #[test]
    fn blob_serialization_roundtrip() {
        let key =
            EncryptionKey::generate();

        let blob =
            EncryptedBlob::encrypt(
                b"serialization test",
                &key,
            )
            .unwrap();

        let serialized =
            blob.to_bytes();

        let restored =
            EncryptedBlob::from_bytes(
                &serialized,
            )
            .unwrap();

        let plaintext =
            restored.decrypt(&key)
                .unwrap();

        assert_eq!(
            plaintext,
            b"serialization test"
        );
    }

    #[test]
    fn blob_hex_roundtrip() {
        let key =
            EncryptionKey::generate();

        let blob =
            EncryptedBlob::encrypt(
                b"hex test",
                &key,
            )
            .unwrap();

        let encoded =
            blob.to_hex();

        let restored =
            EncryptedBlob::from_hex(
                &encoded,
            )
            .unwrap();

        assert_eq!(
            blob.nonce,
            restored.nonce
        );

        assert_eq!(
            blob.ciphertext,
            restored.ciphertext
        );
    }

    #[test]
    fn key_hex_roundtrip() {
        let key =
            EncryptionKey::generate();

        let encoded =
            key.to_hex();

        let restored =
            EncryptionKey::from_hex(
                &encoded,
            )
            .unwrap();

        assert_eq!(
            key.as_bytes(),
            restored.as_bytes()
        );
    }

    #[test]
    fn sha256_is_deterministic() {
        let a =
            sha256_hex(b"JOCKY");

        let b =
            sha256_hex(b"JOCKY");

        assert_eq!(a, b);
    }

    #[test]
    fn sha256_changes_with_input() {
        let a =
            sha256_hex(b"JOCKY");

        let b =
            sha256_hex(b"JOCKY2");

        assert_ne!(a, b);
    }

    #[test]
    fn sha256_has_64_hex_characters() {
        let hash =
            sha256_hex(b"test");

        assert_eq!(
            hash.len(),
            64
        );
    }

    #[test]
    fn metadata_is_generated() {
        let key =
            EncryptionKey::generate();

        let plaintext =
            b"{\"version\":\"0.3\"}";

        let blob =
            EncryptedBlob::encrypt(
                plaintext,
                &key,
            )
            .unwrap();

        let metadata =
            CryptoMetadata::from_blob(
                plaintext,
                &blob,
            );

        assert_eq!(
            metadata.format_version,
            FORMAT_VERSION
        );

        assert_eq!(
            metadata.payload_sha256.len(),
            64
        );

        assert_eq!(
            metadata.encrypted_blob_sha256.len(),
            64
        );

        assert!(
            metadata.encrypted_size > 0
        );
    }

    #[test]
    fn empty_plaintext_can_be_encrypted() {
        let key =
            EncryptionKey::generate();

        let blob =
            EncryptedBlob::encrypt(
                b"",
                &key,
            )
            .unwrap();

        let decrypted =
            blob.decrypt(&key)
                .unwrap();

        assert!(
            decrypted.is_empty()
        );
    }

    #[test]
    fn invalid_hex_is_rejected() {
        let result =
            decode_hex("zz");

        assert!(
            result.is_err()
        );
    }

    #[test]
    fn odd_hex_is_rejected() {
        let result =
            decode_hex("abc");

        assert!(
            result.is_err()
        );
    }
}