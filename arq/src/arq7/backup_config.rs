use crate::error::Result;

/// BackupConfig represents the backupconfig.json file
///
/// This file tells Arq how objects are to be added to the backup set – whether the data are
/// encrypted, what kind of hashing mechanism to use, what maximum size to use for packing
/// small files together, etc.
#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    /// 1=SHA1, 2=SHA256
    #[serde(rename = "blobIdentifierType")]
    pub blob_identifier_type: u32,
    #[serde(rename = "maxPackedItemLength")]
    pub max_packed_item_length: u64,
    #[serde(rename = "backupName")]
    pub backup_name: String,
    #[serde(rename = "isWORM")]
    pub is_worm: bool,
    #[serde(rename = "containsGlacierArchives")]
    pub contains_glacier_archives: bool,
    #[serde(rename = "additionalUnpackedBlobDirs")]
    pub additional_unpacked_blob_dirs: Vec<String>,
    /// Arq uses the same chunker version to ensure de-duplication works with old data
    #[serde(rename = "chunkerVersion")]
    pub chunker_version: u32,
    #[serde(rename = "computerName")]
    pub computer_name: String,
    #[serde(rename = "computerSerial")]
    pub computer_serial: String,
    #[serde(rename = "blobStorageClass")]
    pub blob_storage_class: String,
    #[serde(rename = "isEncrypted")]
    pub is_encrypted: bool,
}

impl BackupConfig {
    /// Load a BackupConfig from a JSON reader
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Load a BackupConfig from a file path
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
    }
}
