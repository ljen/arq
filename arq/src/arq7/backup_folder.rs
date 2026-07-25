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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_reader_valid() {
        let json_data = r#"{
            "localPath": "/Users/example",
            "migratedFromArq60": false,
            "storageClass": "STANDARD",
            "diskIdentifier": "disk1s1",
            "uuid": "1234-5678",
            "migratedFromArq5": true,
            "localMountPoint": "/",
            "name": "My Backup"
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let folder = BackupFolder::from_reader(reader).unwrap();

        assert_eq!(folder.local_path, "/Users/example");
        assert_eq!(folder.migrated_from_arq60, false);
        assert_eq!(folder.storage_class, "STANDARD");
        assert_eq!(folder.disk_identifier.as_deref(), Some("disk1s1"));
        assert_eq!(folder.uuid, "1234-5678");
        assert_eq!(folder.migrated_from_arq5, true);
        assert_eq!(folder.local_mount_point, "/");
        assert_eq!(folder.name, "My Backup");
    }

    #[test]
    fn test_from_reader_valid_no_disk_id() {
        let json_data = r#"{
            "localPath": "/Users/example2",
            "migratedFromArq60": true,
            "storageClass": "GLACIER",
            "uuid": "8765-4321",
            "migratedFromArq5": false,
            "localMountPoint": "/mnt",
            "name": "Archive Backup"
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let folder = BackupFolder::from_reader(reader).unwrap();

        assert_eq!(folder.local_path, "/Users/example2");
        assert_eq!(folder.migrated_from_arq60, true);
        assert_eq!(folder.storage_class, "GLACIER");
        assert!(folder.disk_identifier.is_none());
        assert_eq!(folder.uuid, "8765-4321");
        assert_eq!(folder.migrated_from_arq5, false);
        assert_eq!(folder.local_mount_point, "/mnt");
        assert_eq!(folder.name, "Archive Backup");
    }

    #[test]
    fn test_from_reader_invalid() {
        let json_data = r#"{
            "localPath": "/Users/example",
            "migratedFromArq60": "not a boolean",
            "storageClass": "STANDARD"
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let result = BackupFolder::from_reader(reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_valid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json_data = r#"{
            "localPath": "/Users/temp",
            "migratedFromArq60": false,
            "storageClass": "STANDARD",
            "uuid": "temp-uuid",
            "migratedFromArq5": false,
            "localMountPoint": "/",
            "name": "Temp Backup"
        }"#;
        temp_file.write_all(json_data.as_bytes()).unwrap();

        let folder = BackupFolder::from_file(temp_file.path()).unwrap();
        assert_eq!(folder.local_path, "/Users/temp");
        assert_eq!(folder.uuid, "temp-uuid");
    }

    #[test]
    fn test_from_file_invalid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json_data = r#"{ "localPath": "/Users/temp", "invalid_json"#;
        temp_file.write_all(json_data.as_bytes()).unwrap();

        let result = BackupFolder::from_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_not_found() {
        let result = BackupFolder::from_file("/path/that/does/not/exist/backupfolder.json");
        assert!(result.is_err());
    }
}
