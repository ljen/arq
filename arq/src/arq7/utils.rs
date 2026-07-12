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
    use crate::object_encryption::calculate_hmacsha256;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use aes::Aes256;
    use cbc::Encryptor;
    use serde::Deserialize;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Deserialize, PartialEq)]
    struct DummyData {
        test_key: String,
    }

    fn create_encrypted_object_bytes(
        encryption_key: &[u8],
        hmac_key: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        type Aes256CbcEnc = Encryptor<Aes256>;

        let master_iv: [u8; 16] = [1; 16];
        let data_iv: [u8; 16] = [2; 16];
        let session_key: [u8; 32] = [3; 32];

        let mut data_iv_session = vec![0u8; 64];
        data_iv_session[..16].copy_from_slice(&data_iv);
        data_iv_session[16..48].copy_from_slice(&session_key);

        let encrypted_data_iv_session = Aes256CbcEnc::new_from_slices(encryption_key, &master_iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut data_iv_session, 48)
            .unwrap()
            .to_vec();

        let mut plaintext_buf = vec![0u8; plaintext.len() + 16]; // Padding might add up to 16 bytes
        plaintext_buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext = Aes256CbcEnc::new_from_slices(&session_key, &data_iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut plaintext_buf, plaintext.len())
            .unwrap()
            .to_vec();

        let mut master_iv_and_data = Vec::new();
        master_iv_and_data.extend_from_slice(&master_iv);
        master_iv_and_data.extend_from_slice(&encrypted_data_iv_session);
        master_iv_and_data.extend_from_slice(&ciphertext);

        let calculated_hmacsha256 = calculate_hmacsha256(hmac_key, &master_iv_and_data).unwrap();

        let mut result = Vec::new();
        result.extend_from_slice(b"ARQO");
        result.extend_from_slice(&calculated_hmacsha256);
        result.extend_from_slice(&master_iv);
        result.extend_from_slice(&encrypted_data_iv_session);
        result.extend_from_slice(&ciphertext);

        result
    }

    #[test]
    fn test_load_json_unencrypted() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"{\"test_key\": \"unencrypted_value\"}")
            .unwrap();
        let file_path = file.path();

        // Should work without keyset
        let res: DummyData = load_json_with_encryption(file_path, None).unwrap();
        assert_eq!(res.test_key, "unencrypted_value");

        // Should also work with keyset since it checks if it is encrypted first
        let keyset = EncryptedKeySet {
            encryption_key: vec![0; 32],
            hmac_key: vec![0; 32],
            blob_identifier_salt: vec![0; 32],
        };
        let res_with_keyset: DummyData =
            load_json_with_encryption(file_path, Some(&keyset)).unwrap();
        assert_eq!(res_with_keyset.test_key, "unencrypted_value");
    }

    #[test]
    fn test_load_json_encrypted() {
        let encryption_key = vec![5u8; 32];
        let hmac_key = vec![6u8; 32];
        let plaintext = b"{\"test_key\": \"encrypted_value\"}";

        let encrypted_bytes = create_encrypted_object_bytes(&encryption_key, &hmac_key, plaintext);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&encrypted_bytes).unwrap();
        let file_path = file.path();

        let keyset = EncryptedKeySet {
            encryption_key: encryption_key.clone(),
            hmac_key: hmac_key.clone(),
            blob_identifier_salt: vec![0; 32],
        };

        // Should work with correct keyset
        let res: DummyData = load_json_with_encryption(file_path, Some(&keyset)).unwrap();
        assert_eq!(res.test_key, "encrypted_value");
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
}
