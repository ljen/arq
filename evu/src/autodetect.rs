use std::fs;
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum ArqVersion {
    Arq5,
    Arq7,
}

pub fn detect_version(path: &Path) -> Result<ArqVersion, crate::error::Error> {
    if path.join("backupconfig.json").exists() {
        return Ok(ArqVersion::Arq7);
    }

    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if entry.file_name() == "encryptionv3.dat" || entry.file_name() == "encryptionv2.dat" {
                return Ok(ArqVersion::Arq5);
            }
        }
    }

    // Check if the path is a computer UUID for Arq5
    if path.is_dir() {
        if path.join("encryptionv3.dat").exists() || path.join("encryptionv2.dat").exists() {
            return Ok(ArqVersion::Arq5);
        }
    }

    // Check if path is a subdirectory of a computer UUID for Arq5
    if let Some(parent) = path.parent() {
        if parent.join("encryptionv3.dat").exists() || parent.join("encryptionv2.dat").exists() {
            return Ok(ArqVersion::Arq5);
        }
    }

    Err(crate::error::Error::UnknownArqVersion(
        path.to_string_lossy().into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;

    #[test]
    fn test_detect_arq7() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("backupconfig.json");
        File::create(config_path).unwrap();

        let version = detect_version(temp_dir.path()).unwrap();
        assert_eq!(version, ArqVersion::Arq7);
    }

    #[test]
    fn test_detect_arq5_encryptionv3() {
        let temp_dir = TempDir::new().unwrap();
        let dat_path = temp_dir.path().join("encryptionv3.dat");
        File::create(dat_path).unwrap();

        let version = detect_version(temp_dir.path()).unwrap();
        assert_eq!(version, ArqVersion::Arq5);
    }

    #[test]
    fn test_detect_arq5_encryptionv2() {
        let temp_dir = TempDir::new().unwrap();
        let dat_path = temp_dir.path().join("encryptionv2.dat");
        File::create(dat_path).unwrap();

        let version = detect_version(temp_dir.path()).unwrap();
        assert_eq!(version, ArqVersion::Arq5);
    }

    #[test]
    fn test_detect_arq5_in_subdirectory() {
        let temp_dir = TempDir::new().unwrap();
        // The parent directory acts as the computer UUID folder
        let dat_path = temp_dir.path().join("encryptionv3.dat");
        File::create(dat_path).unwrap();

        // The subdir acts as a backup folder inside the computer UUID folder
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();

        let version = detect_version(&sub_dir).unwrap();
        assert_eq!(version, ArqVersion::Arq5);
    }

    #[test]
    fn test_detect_unknown_version() {
        let temp_dir = TempDir::new().unwrap();

        let result = detect_version(temp_dir.path());
        match result {
            Err(crate::error::Error::UnknownArqVersion(path)) => {
                assert_eq!(path, temp_dir.path().to_string_lossy().into_owned());
            }
            _ => panic!("Expected UnknownArqVersion error, got {:?}", result),
        }
    }
}
