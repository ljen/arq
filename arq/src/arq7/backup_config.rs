use crate::error::Result;

/// BackupConfig represents the backupconfig.json file
///
/// This file tells Arq how objects are to be added to the backup set – whether the data are
/// encrypted, what kind of hashing mechanism to use, what maximum size to use for packing
/// small files together, etc.
#[derive(Debug, Clone, Deserialize)]
pub struct BackupConfig {
    #[serde(rename = "computerUUID")]
    pub computer_uuid: String,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_backup_config_from_reader() {
        let json_data = r#"{
            "computerUUID": "12345-abcde",
            "blobIdentifierType": 2,
            "maxPackedItemLength": 10485760,
            "backupName": "My Backup",
            "isWORM": false,
            "containsGlacierArchives": false,
            "additionalUnpackedBlobDirs": [],
            "chunkerVersion": 3,
            "computerName": "My Mac",
            "computerSerial": "C02XYZ123ABC",
            "blobStorageClass": "STANDARD",
            "isEncrypted": true
        }"#;

        let cursor = Cursor::new(json_data);
        let config = BackupConfig::from_reader(cursor).unwrap();

        assert_eq!(config.computer_uuid, "12345-abcde");
        assert_eq!(config.blob_identifier_type, 2);
        assert_eq!(config.max_packed_item_length, 10485760);
        assert_eq!(config.backup_name, "My Backup");
        assert_eq!(config.is_worm, false);
        assert_eq!(config.contains_glacier_archives, false);
        assert!(config.additional_unpacked_blob_dirs.is_empty());
        assert_eq!(config.chunker_version, 3);
        assert_eq!(config.computer_name, "My Mac");
        assert_eq!(config.computer_serial, "C02XYZ123ABC");
        assert_eq!(config.blob_storage_class, "STANDARD");
        assert_eq!(config.is_encrypted, true);
    }

    #[test]
    fn test_backup_config_missing_field() {
        let json_data = r#"{
            "blobIdentifierType": 2,
            "backupName": "My Backup"
        }"#;

        let cursor = Cursor::new(json_data);
        let result = BackupConfig::from_reader(cursor);
        assert!(result.is_err());
    }
}
