use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use rpassword;

use crate::error::Result;

use arq::folder::{Folder, FolderData};
use arq::object_encryption;

pub fn get_latest_folder_data_path(path: &Path) -> Result<PathBuf> {
    let mut newest = "0".to_string();
    let read_dir_result = match std::fs::read_dir(path) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::error::Error::NotFound(format!(
                "Path not found: {}",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
    for entry in read_dir_result {
        let filename = entry?.file_name().to_string_lossy().to_string();
        if filename > newest {
            newest = filename;
        }
    }
    Ok(path.join(newest))
}

pub fn read_arq_folder(
    path: &str,
    computer: &str,
    folder: &str,
    master_keys: Vec<Vec<u8>>,
) -> Result<Folder> {
    let path = Path::new(path).join(computer).join("buckets").join(folder);
    let mut reader = get_file_reader(path);
    Ok(Folder::new(&mut reader, &master_keys)?)
}

pub fn find_latest_folder_sha(path: &str, computer: &str, folder: &str) -> Result<String> {
    let refs_path = Path::new(path)
        .join(computer)
        .join("bucketdata")
        .join(folder)
        .join("refs");

    let folder_data_path = get_latest_folder_data_path(&refs_path.join("logs").join("master"))?;
    let master_sha_path = refs_path.join("heads").join("master");
    let master_sha = std::fs::read(&master_sha_path)?;
    let mut reader = get_file_reader(folder_data_path);
    let fd = FolderData::new(&mut reader, &master_sha)?;
    Ok(fd.new_head_sha1)
}

pub fn get_file_reader(filename: PathBuf) -> BufReader<File> {
    let file = match File::open(&filename) {
        Ok(f) => f,
        Err(err) => panic!(
            "Could not open file {}: {}",
            filename.display(),
            err
        ),
    };
    BufReader::new(file)
}

pub fn get_password() -> Result<String> {
    if cfg!(test) {
        return Ok("testpassword".to_string());
    }
    Ok(rpassword::prompt_password("Enter encryption password: ")?)
}

pub fn get_master_keys(path: &str, computer: &str) -> Result<Vec<Vec<u8>>> {
    let enc_path = Path::new(path).join(computer).join("encryptionv3.dat");
    let mut reader = get_file_reader(enc_path);
    let password = get_password()?;
    let enc_data = object_encryption::EncryptionDat::new(&mut reader, &password)?;
    Ok(enc_data.master_keys)
}

use std::sync::atomic::{AtomicBool, Ordering};

static IS_DEBUG: AtomicBool = AtomicBool::new(false);

pub fn initialize_debug_from_args(matches: &clap::ArgMatches) {
    let is_debug = matches.is_present("debug");
    IS_DEBUG.store(is_debug, Ordering::Relaxed);
}

pub fn is_debug_enabled() -> bool {
    IS_DEBUG.load(Ordering::Relaxed)
}

#[macro_export]
macro_rules! debug_eprintln {
    ($($arg:tt)*) => {
        if $crate::utils::is_debug_enabled() {
            eprintln!($($arg)*);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::{NamedTempFile, tempdir};
    use std::fs;

    #[test]
    fn test_get_file_reader_success() {
        use std::io::Write;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let test_data = b"Hello, world!";
        temp_file.write_all(test_data).expect("Failed to write to temp file");

        let mut reader = get_file_reader(temp_file.path().to_path_buf());
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).expect("Failed to read from file");

        assert_eq!(buffer, test_data);
    }

    #[test]
    #[should_panic(expected = "Could not open file")]
    fn test_get_file_reader_failure() {
        let non_existent_path = PathBuf::from("does_not_exist.txt");
        get_file_reader(non_existent_path);
    }

    #[test]
    fn test_get_latest_folder_data_path_success() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path();

        fs::File::create(path.join("001")).expect("Failed to create file");
        fs::File::create(path.join("003")).expect("Failed to create file");
        fs::File::create(path.join("002")).expect("Failed to create file");

        let latest = get_latest_folder_data_path(path).expect("Failed to get latest path");
        assert_eq!(latest, path.join("003"));
    }

    #[test]
    fn test_get_latest_folder_data_path_empty_dir() {
        let dir = tempdir().expect("Failed to create temp dir");
        let path = dir.path();

        let latest = get_latest_folder_data_path(path).expect("Failed to get latest path");
        assert_eq!(latest, path.join("0"));
    }

    #[test]
    fn test_get_latest_folder_data_path_missing_dir() {
        let path = PathBuf::from("does_not_exist_dir");

        let result = get_latest_folder_data_path(&path);
        assert!(result.is_err());

        if let Err(crate::error::Error::NotFound(msg)) = result {
            assert_eq!(msg, format!("Path not found: {}", path.display()));
        } else {
            panic!("Expected NotFound error");
        }
    }
}
