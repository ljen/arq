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
