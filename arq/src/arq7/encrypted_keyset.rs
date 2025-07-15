use crate::error::{Error, Result};
use crate::object_encryption::calculate_hmacsha256;
use crate::type_utils::ArqRead;
use byteorder::ReadBytesExt;
use std::fs::File;
use std::io::{BufRead, Seek};
use std::path::Path;

/// EncryptedKeySet represents the encryptedkeyset.dat file
///
/// This file contains keys for encrypting/decrypting and for creating object identifiers.
/// It is encrypted with the encryption password you chose when you created the backup plan.
///
/// The encrypted format is:
/// ```text
/// header                          41 52 51 5f 45 4e 43 52   ARQ_ENCR
///                                 59 50 54 45 44 5f 4d 41   YPTED_MA
///                                 53 54 45 52 5f 4b 45 59   STER_KEY
///                                 53                        S
/// salt                            xx xx xx xx xx xx xx xx (8 bytes)
/// HMACSHA256                      xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx (32 bytes)
/// IV                              xx xx xx xx xx xx xx xx
///                                 xx xx xx xx xx xx xx xx (16 bytes)
/// ciphertext                      xx xx xx xx xx xx xx xx
///                                 ... (variable length)
/// ```
///
/// The plaintext format contains:
/// - encryption version: 4 bytes (00 00 00 03)
/// - encryption key length: 8 bytes (00 00 00 00 00 00 00 20)
/// - encryption key: 32 bytes
/// - HMAC key length: 8 bytes (00 00 00 00 00 00 00 20)
/// - HMAC key: 32 bytes
/// - blob identifier salt length: 8 bytes (00 00 00 00 00 00 00 20)
/// - blob identifier salt: 32 bytes
#[derive(Debug, Clone)]
pub struct EncryptedKeySet {
    pub encryption_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub blob_identifier_salt: Vec<u8>,
}

const ENCRYPTED_KEYSET_HEADER: [u8; 25] = [
    65, 82, 81, 95, 69, 78, 67, 82, 89, 80, 84, 69, 68, 95, 77, 65, 83, 84, 69, 82, 95, 75, 69, 89,
    83,
]; // ARQ_ENCRYPTED_MASTER_KEYS

impl EncryptedKeySet {
    pub fn from_master_keys(master_keys: Vec<Vec<u8>>) -> Result<Self> {
        if master_keys.len() != 3 {
            return Err(Error::InvalidFormat("Expected 3 master keys".to_string()));
        }
        Ok(EncryptedKeySet {
            encryption_key: master_keys[0].clone(),
            hmac_key: master_keys[1].clone(),
            blob_identifier_salt: master_keys[2].clone(),
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let file = File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        Self::from_reader(&mut reader, password)
    }

    pub fn from_reader<R: BufRead + Seek>(mut reader: R, password: &str) -> Result<Self> {
        // Read and verify header
        let header = reader.read_bytes(25)?;
        if header != ENCRYPTED_KEYSET_HEADER {
            return Err(Error::InvalidFormat(
                "Invalid encryptedkeyset.dat header".to_string(),
            ));
        }

        // Read salt (8 bytes)
        let salt = reader.read_bytes(8)?;

        // Read HMAC-SHA256 (32 bytes)
        let hmac_sha256 = reader.read_bytes(32)?;

        // Read IV (16 bytes)
        let iv = reader.read_bytes(16)?;

        // Read ciphertext (rest of file)
        let mut ciphertext = Vec::new();
        reader.read_to_end(&mut ciphertext)?;

        // Derive 64-byte key from password using PBKDF2-SHA256
        let mut derived_key = vec![0u8; 64];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(200_000).unwrap(),
            &salt,
            password.as_bytes(),
            &mut derived_key,
        );

        // Verify HMAC-SHA256 of IV + ciphertext
        let iv_and_ciphertext = [&iv[..], &ciphertext[..]].concat();
        let calculated_hmac = calculate_hmacsha256(&derived_key[32..], &iv_and_ciphertext)?;
        if calculated_hmac != hmac_sha256 {
            return Err(Error::WrongPassword);
        }

        // Decrypt the ciphertext using AES-256-CBC
        let mut decrypted_data = ciphertext;
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        let plaintext = Aes256CbcDec::new_from_slices(&derived_key[..32], &iv)?
            .decrypt_padded_mut::<Pkcs7>(&mut decrypted_data)?;

        // Parse the plaintext structure
        let mut reader = std::io::Cursor::new(plaintext);

        // Read encryption version (4 bytes)
        let encryption_version = reader.read_u32::<byteorder::BigEndian>()?;
        if encryption_version != 3 {
            return Err(Error::InvalidFormat(format!(
                "Unsupported encryption version: {}",
                encryption_version
            )));
        }

        // Read encryption key length (8 bytes) and key
        let encryption_key_length = reader.read_u64::<byteorder::BigEndian>()?;
        if encryption_key_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid encryption key length: {}",
                encryption_key_length
            )));
        }
        let encryption_key = reader.read_bytes(32)?;

        // Read HMAC key length (8 bytes) and key
        let hmac_key_length = reader.read_u64::<byteorder::BigEndian>()?;
        if hmac_key_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid HMAC key length: {}",
                hmac_key_length
            )));
        }
        let hmac_key = reader.read_bytes(32)?;

        // Read blob identifier salt length (8 bytes) and salt
        let salt_length = reader.read_u64::<byteorder::BigEndian>()?;
        if salt_length != 32 {
            return Err(Error::InvalidFormat(format!(
                "Invalid salt length: {}",
                salt_length
            )));
        }
        let blob_identifier_salt = reader.read_bytes(32)?;

        Ok(EncryptedKeySet {
            encryption_key,
            hmac_key,
            blob_identifier_salt,
        })
    }
}
