use super::backup_plan::BackupPlan;
use super::encrypted_keyset::EncryptedKeySet;
use crate::error::{Error, Result};
use crate::object_encryption::EncryptedObject;
use byteorder::{BigEndian, ReadBytesExt};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs::File;
use std::io::BufRead;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupRecordError {
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(rename = "localPath")]
    pub local_path: String,
    #[serde(rename = "pathIsDirectory")]
    pub path_is_directory: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Arq5BackupRecord {
    pub version: u32, // Expected 12
    #[serde(rename = "arqVersion")]
    pub arq_version: Option<String>,
    #[serde(rename = "backupFolderUUID")]
    pub backup_folder_uuid: String,
    #[serde(rename = "backupPlanUUID")]
    pub backup_plan_uuid: String,
    #[serde(rename = "computerOSType")]
    pub computer_os_type: Option<u32>,
    #[serde(rename = "creationDate")]
    pub creation_date: Option<f64>,
    #[serde(rename = "isComplete")]
    pub is_complete: Option<bool>,
    #[serde(rename = "arq5BucketXML")]
    pub arq5_bucket_xml: Option<String>,
    #[serde(rename = "backupRecordErrors")]
    #[serde(default)]
    pub backup_record_errors: Option<Vec<BackupRecordError>>,
    #[serde(rename = "localPath")]
    pub local_path: Option<String>,
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    #[serde(rename = "copiedFromSnapshot")]
    pub copied_from_snapshot: bool,
    #[serde(rename = "copiedFromCommit")]
    pub copied_from_commit: bool,
    #[serde(rename = "arq5TreeBlobKey")]
    pub arq5_tree_blob_key: Option<crate::blob::BlobKey>, // Updated to use the new BlobKey
    pub archived: Option<bool>, // Matches example, though original top-level was not optional
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Arq7BackupRecord {
    #[serde(rename = "backupFolderUUID")]
    pub backup_folder_uuid: String,
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: String, // Present in v100
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    pub version: u32, // Expected 100
    #[serde(rename = "backupPlanUUID")]
    pub backup_plan_uuid: String,
    #[serde(rename = "backupRecordErrors")]
    #[serde(default)]
    pub backup_record_errors: Option<Vec<BackupRecordError>>,
    #[serde(rename = "copiedFromSnapshot")]
    pub copied_from_snapshot: bool,
    #[serde(rename = "copiedFromCommit")]
    pub copied_from_commit: bool,
    pub node: crate::node::Node, // Changed to use unified Node
    #[serde(rename = "arqVersion")]
    pub arq_version: Option<String>,
    pub archived: Option<bool>,
    #[serde(rename = "backupPlanJSON")]
    pub backup_plan_json: Option<BackupPlan>,
    #[serde(rename = "relativePath")]
    pub relative_path: Option<String>,
    #[serde(rename = "computerOSType")]
    pub computer_os_type: Option<u32>, // Was optional, matches v100
    #[serde(rename = "localPath")]
    pub local_path: Option<String>, // Was optional, matches v100
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: Option<String>, // Present in v100
    #[serde(rename = "isComplete")]
    pub is_complete: Option<bool>, // Was optional, matches v100
    #[serde(rename = "creationDate")]
    #[serde(default)] // Default for Option<f64>
    #[serde(with = "f64_parser_allow_int")] // Allow parsing from integer or float
    pub creation_date: Option<f64>, // V100 has int, f64 is fine
    #[serde(rename = "volumeName")]
    pub volume_name: Option<String>, // Present in v100
                                     // Removed arq5BucketXML and arq5TreeBlobKey
                                     // Removed errorCount as backupRecordErrors is now structured
}

// Custom deserializer module for creationDate in Arq7BackupRecord
// to handle cases where it might be an integer in JSON but needs to be Option<f64>
mod f64_parser_allow_int {
    use super::*;
    use serde::de::Error;

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Option<f64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum MaybeFloatOrInt {
            Float(f64),
            Int(i64), // Allow i64 as Arq7 v100 example has integer timestamp
            None,     // Allow it to be null or missing
        }

        match MaybeFloatOrInt::deserialize(deserializer) {
            Ok(MaybeFloatOrInt::Float(f)) => Ok(Some(f)),
            Ok(MaybeFloatOrInt::Int(i)) => Ok(Some(i as f64)),
            Ok(MaybeFloatOrInt::None) => Ok(None), // This case handles explicit nulls. `#[serde(default)]` handles missing.
            Err(e) => Err(e),
        }
    }

    pub fn serialize<S>(date: &Option<f64>, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(d) => serializer.serialize_f64(*d),
            None => serializer.serialize_none(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)] // Attempt to deserialize as Arq7 first, then Arq5
pub enum GenericBackupRecord {
    Arq7(Arq7BackupRecord),
    Arq5(Arq5BackupRecord),
}

impl GenericBackupRecord {
    /// Load a GenericBackupRecord from a file path
    /// The file format is: 4-byte big-endian length + LZ4-compressed JSON data
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load GenericBackupRecord from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Self> {
        // Changed BackupRecord to Self
        let path_ref = path.as_ref();
        let file = File::open(path_ref)?;
        let mut reader = std::io::BufReader::new(file);

        Self::from_reader_with_encryption(&mut reader, keyset)
    }

    /// Load a GenericBackupRecord from a reader
    pub fn from_reader<R: BufRead>(reader: R) -> Result<Self> {
        Self::from_reader_with_encryption(reader, None)
    }

    /// Load GenericBackupRecord from reader, optionally decrypting if needed
    pub fn from_reader_with_encryption<R: BufRead>(
        mut reader: R,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Self> {
        // Changed BackupRecord to Self
        let data = if let Some(keyset) = keyset {
            // Check if this is an encrypted file by peeking at the header
            let mut header = [0u8; 4];
            reader.read_exact(&mut header)?;

            if header == [65, 82, 81, 79] {
                // "ARQO" - encrypted
                // Read the rest of the file as encrypted object
                let mut encrypted_data = Vec::new();
                reader.read_to_end(&mut encrypted_data)?;

                // Reconstruct the full encrypted object data with header
                let mut full_data = header.to_vec();
                full_data.extend(encrypted_data);

                let mut cursor = std::io::Cursor::new(&full_data);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                let decrypted_data = encrypted_obj.decrypt(&keyset.encryption_key[..])?;

                // Decrypted data follows the same format as unencrypted records:
                // 4-byte length + LZ4-compressed JSON
                if decrypted_data.len() < 4 {
                    return Err(Error::InvalidFormat("Decrypted data too short".to_string()));
                }
                let length = u32::from_be_bytes([
                    decrypted_data[0],
                    decrypted_data[1],
                    decrypted_data[2],
                    decrypted_data[3],
                ]) as usize;
                let compressed_data = &decrypted_data[4..];
                lz4_flex::block::decompress(compressed_data, length)?
            } else {
                // Not encrypted, read the rest normally
                // The header we read was the length prefix for LZ4
                let length = u32::from_be_bytes(header) as usize;
                let mut compressed_data = Vec::new();
                reader.read_to_end(&mut compressed_data)?;

                lz4_flex::block::decompress(&compressed_data, length)?
            }
        } else {
            // No encryption support, load normally
            let length = reader.read_u32::<BigEndian>()? as usize;
            let mut compressed = Vec::new();
            reader.read_to_end(&mut compressed)?;
            lz4_flex::block::decompress(&compressed, length)?
        };

        // Parse the JSON
        let json_str = String::from_utf8(data)?;
        // println!("BackupRecord Json:\n{}", json_str);
        Ok(serde_json::from_str(&json_str)?)
    }
}
