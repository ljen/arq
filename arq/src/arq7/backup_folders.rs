use super::encrypted_keyset::EncryptedKeySet;
use super::utils::load_json_with_encryption;
use crate::error::Result;

/// BackupFolders represents the backupfolders.json file
///
/// This file tells Arq where to find existing objects (for de-duplication).
#[derive(Debug, Clone, Deserialize, Serialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_reader_valid() {
        let json_data = r#"{
            "standardObjectDirs": ["dir1", "dir2"],
            "standardIAObjectDirs": ["dir3"],
            "onezoneIAObjectDirs": [],
            "s3GlacierObjectDirs": ["dir4"],
            "s3DeepArchiveObjectDirs": [],
            "s3GlacierIRObjectDirs": ["dir5"],
            "importedFrom": "older_backup"
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let folders = BackupFolders::from_reader(reader).unwrap();

        assert_eq!(folders.standard_object_dirs, vec!["dir1", "dir2"]);
        assert_eq!(folders.standard_ia_object_dirs, vec!["dir3"]);
        assert!(folders.onezone_ia_object_dirs.is_empty());
        assert_eq!(folders.s3_glacier_object_dirs, vec!["dir4"]);
        assert!(folders.s3_deep_archive_object_dirs.is_empty());
        assert_eq!(folders.s3_glacier_ir_object_dirs.as_deref(), Some(&["dir5".to_string()][..]));
        assert_eq!(folders.imported_from.as_deref(), Some("older_backup"));
    }

    #[test]
    fn test_from_reader_valid_no_optional() {
        let json_data = r#"{
            "standardObjectDirs": [],
            "standardIAObjectDirs": [],
            "onezoneIAObjectDirs": [],
            "s3GlacierObjectDirs": [],
            "s3DeepArchiveObjectDirs": []
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let folders = BackupFolders::from_reader(reader).unwrap();

        assert!(folders.standard_object_dirs.is_empty());
        assert!(folders.standard_ia_object_dirs.is_empty());
        assert!(folders.onezone_ia_object_dirs.is_empty());
        assert!(folders.s3_glacier_object_dirs.is_empty());
        assert!(folders.s3_deep_archive_object_dirs.is_empty());
        assert!(folders.s3_glacier_ir_object_dirs.is_none());
        assert!(folders.imported_from.is_none());
    }

    #[test]
    fn test_from_reader_invalid() {
        let json_data = r#"{
            "standardObjectDirs": "not an array"
        }"#;

        let reader = std::io::Cursor::new(json_data);
        let result = BackupFolders::from_reader(reader);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_valid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let original_folders = BackupFolders {
            standard_object_dirs: vec!["dir1".to_string()],
            standard_ia_object_dirs: vec![],
            onezone_ia_object_dirs: vec![],
            s3_glacier_object_dirs: vec![],
            s3_deep_archive_object_dirs: vec![],
            s3_glacier_ir_object_dirs: None,
            imported_from: None,
        };

        let json_data = serde_json::to_string(&original_folders).unwrap();
        temp_file.write_all(json_data.as_bytes()).unwrap();

        let folders = BackupFolders::from_file(temp_file.path()).unwrap();
        assert_eq!(folders.standard_object_dirs, vec!["dir1"]);
    }

    #[test]
    fn test_from_file_invalid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json_data = r#"{ "standardObjectDirs": "#;
        temp_file.write_all(json_data.as_bytes()).unwrap();

        let result = BackupFolders::from_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_not_found() {
        let result = BackupFolders::from_file("/path/that/does/not/exist/backupfolders.json");
        assert!(result.is_err());
    }
}
