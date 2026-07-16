use crate::arq7::EncryptedKeySet;
use crate::error::{Error, Result};
use crate::object_encryption::EncryptedObject;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Helper function to detect if a file is encrypted by checking for ARQO header
pub fn is_file_encrypted<P: AsRef<Path>>(path: P) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 4];
    match file.read_exact(&mut header) {
        Ok(()) => Ok(header == [65, 82, 81, 79]), // "ARQO"
        Err(_) => Ok(false), // File too small or other error, assume not encrypted
    }
}

/// Helper function to decrypt an encrypted JSON file
pub fn decrypt_json_file<P: AsRef<Path>>(path: P, keyset: &EncryptedKeySet) -> Result<String> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    // Load as EncryptedObject
    let encrypted_obj = EncryptedObject::new(&mut reader)?;

    // Validate and decrypt using the first master key (encryption key)
    encrypted_obj.validate(&keyset.hmac_key)?;
    let decrypted_data = encrypted_obj.decrypt(&keyset.encryption_key[..32])?;

    // Convert to string
    String::from_utf8(decrypted_data).map_err(|_| Error::ParseError)
}

/// Helper function to load JSON from either encrypted or unencrypted file
pub fn load_json_with_encryption<T, P>(path: P, keyset: Option<&EncryptedKeySet>) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
    P: AsRef<Path>,
{
    let path_ref = path.as_ref();

    if let Some(keyset) = keyset {
        // Check if file is encrypted
        if is_file_encrypted(path_ref)? {
            // Decrypt and parse
            let json_content = decrypt_json_file(path_ref, keyset)?;
            return Ok(serde_json::from_str(&json_content)?);
        }
    }

    // Load as regular unencrypted file
    let file = File::open(path_ref)?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use crate::object_encryption::calculate_hmacsha256;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    fn create_test_encrypted_object(data: &[u8], encryption_key: &[u8], hmac_key: &[u8]) -> Vec<u8> {
        // 1. Generate session key and data IV
        let session_key = [1u8; 32];
        let data_iv = [2u8; 16];

        // 2. Encrypt plaintext with session key and data IV
        let mut ciphertext_buf = vec![0u8; data.len() + 16];
        ciphertext_buf[..data.len()].copy_from_slice(data);
        let ciphertext_len = Aes256CbcEnc::new_from_slices(&session_key, &data_iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut ciphertext_buf, data.len())
            .unwrap()
            .len();
        let ciphertext = &ciphertext_buf[..ciphertext_len];

        // 3. Generate master IV
        let master_iv = [3u8; 16];

        // 4. Encrypt data IV + session key with master key and master IV
        let mut data_iv_session = Vec::new();
        data_iv_session.extend_from_slice(&data_iv);
        data_iv_session.extend_from_slice(&session_key);

        let mut enc_data_iv_session_buf = vec![0u8; data_iv_session.len() + 16];
        enc_data_iv_session_buf[..data_iv_session.len()].copy_from_slice(&data_iv_session);
        let enc_len = Aes256CbcEnc::new_from_slices(encryption_key, &master_iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut enc_data_iv_session_buf, data_iv_session.len())
            .unwrap()
            .len();
        let encrypted_data_iv_session = &enc_data_iv_session_buf[..enc_len];

        // 5. Calculate HMAC-SHA256
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(&master_iv);
        mac_data.extend_from_slice(encrypted_data_iv_session);
        mac_data.extend_from_slice(ciphertext);

        let hmac = calculate_hmacsha256(hmac_key, &mac_data).unwrap();

        // 6. Assemble
        let mut result = Vec::new();
        result.extend_from_slice(b"ARQO");
        result.extend_from_slice(&hmac);
        result.extend_from_slice(&master_iv);
        result.extend_from_slice(encrypted_data_iv_session);
        result.extend_from_slice(ciphertext);

        result
    }

    fn get_temp_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Include thread ID to avoid conflicts when tests run concurrently
        let thread_id = format!("{:?}", std::thread::current().id());
        let thread_id = thread_id.replace("ThreadId(", "").replace(")", "");
        std::env::temp_dir().join(format!("{}_{}_{}", name, thread_id, nanos))
    }

    #[test]
    fn test_is_file_encrypted_true() {
        let path = get_temp_path("encrypted");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"ARQO_and_some_data").unwrap();
        }

        let result = is_file_encrypted(&path).unwrap();
        assert!(result);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_is_file_encrypted_false_wrong_header() {
        let path = get_temp_path("unencrypted");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"NOT_ARQO_DATA").unwrap();
        }

        let result = is_file_encrypted(&path).unwrap();
        assert!(!result);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_is_file_encrypted_false_too_small() {
        let path = get_temp_path("small");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"ARQ").unwrap(); // Only 3 bytes
        }

        let result = is_file_encrypted(&path).unwrap();
        assert!(!result);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_is_file_encrypted_error_not_found() {
        let path = get_temp_path("non_existent");
        let result = is_file_encrypted(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_json_file() {
        let encryption_key = vec![4u8; 32];
        let hmac_key = vec![5u8; 32];

        let keyset = EncryptedKeySet {
            encryption_key: encryption_key.clone(),
            hmac_key: hmac_key.clone(),
            blob_identifier_salt: vec![6u8; 32],
        };

        let json_data = r#"{"hello": "world"}"#;
        let encrypted_bytes = create_test_encrypted_object(json_data.as_bytes(), &encryption_key, &hmac_key);

        let path = get_temp_path("test_decrypt_json");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(&encrypted_bytes).unwrap();
        }

        let decrypted = decrypt_json_file(&path, &keyset).unwrap();
        assert_eq!(decrypted, json_data);

        let _ = std::fs::remove_file(path);
    }
}
