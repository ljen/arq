use super::encrypted_keyset::EncryptedKeySet;
use super::utils::load_json_with_encryption;
use crate::error::Result;
use serde::Deserialize;

/// BackupFolders represents the backupfolders.json file
///
/// This file tells Arq where to find existing objects (for de-duplication).
#[derive(Debug, Clone, Deserialize)]
pub struct BackupFolders {
    #[serde(rename = "standardObjectDirs")]
    pub standard_object_dirs: Vec<String>,
    #[serde(rename = "standardIAObjectDirs")]
    pub standard_ia_object_dirs: Vec<String>,
    #[serde(rename = "onezoneIAObjectDirs")]
    pub onezone_ia_object_dirs: Vec<String>,
    #[serde(rename = "s3GlacierObjectDirs")]
    pub s3_glacier_object_dirs: Vec<String>,
    #[serde(rename = "s3DeepArchiveObjectDirs")]
    pub s3_deep_archive_object_dirs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "s3GlacierIRObjectDirs")]
    pub s3_glacier_ir_object_dirs: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "importedFrom")]
    pub imported_from: Option<String>,
}

impl BackupFolders {
    /// Load BackupFolders from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load BackupFolders from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load BackupFolders from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<std::path::Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<BackupFolders> {
        load_json_with_encryption(path, keyset)
    }
}
