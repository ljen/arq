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
            return Ok(ArqVersion::Arq5)
        }
    }


    Err(crate::error::Error::UnknownArqVersion(
        path.to_string_lossy().into_owned(),
    ))
}
