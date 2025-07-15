use super::encrypted_keyset::EncryptedKeySet;
use super::utils::load_json_with_encryption;
use crate::error::Result;

/// BackupFolder represents a backupfolder.json file within the backupfolders/<UUID>/ directory
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackupFolder {
    #[serde(rename = "localPath")]
    pub local_path: String,
    #[serde(rename = "migratedFromArq60")]
    pub migrated_from_arq60: bool,
    #[serde(rename = "storageClass")]
    pub storage_class: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "diskIdentifier")]
    pub disk_identifier: Option<String>,
    pub uuid: String,
    #[serde(rename = "migratedFromArq5")]
    pub migrated_from_arq5: bool,
    #[serde(rename = "localMountPoint")]
    pub local_mount_point: String,
    pub name: String,
}

impl BackupFolder {
    /// Load a BackupFolder from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load a BackupFolder from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::from_file_with_encryption(path, None)
    }

    /// Load BackupFolder from file, optionally decrypting if needed
    pub fn from_file_with_encryption<P: AsRef<std::path::Path>>(
        path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<BackupFolder> {
        load_json_with_encryption(path, keyset)
    }
}
