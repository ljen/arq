use std::fs::File;
use std::io::{BufReader, Result as IoResult};
use std::path::{Path, PathBuf};

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
        let filename = entry?.file_name().to_str().unwrap().to_string();
        if filename > newest {
            newest = filename;
        }
    }
    Ok(path.join(newest))
}

pub fn read_arq_folder(
    path: &str,
    _computer: &str,
    folder: &str,
    master_keys: Vec<Vec<u8>>,
) -> Result<Folder> {
    let path = Path::new(path).join("buckets").join(folder);
    let mut reader = get_file_reader(&path)?;
    Ok(Folder::new(&mut reader, &master_keys)?)
}

pub fn find_latest_folder_sha(path: &str, _computer: &str, folder: &str) -> Result<String> {
    let refs_path = Path::new(path).join("bucketdata").join(folder).join("refs");

    let folder_data_path = get_latest_folder_data_path(&refs_path.join("logs").join("master"))?;
    let master_sha_path = refs_path.join("heads").join("master");
    let master_sha = std::fs::read(&master_sha_path)?;
    let mut reader = get_file_reader(&folder_data_path)?;
    let fd = FolderData::new(&mut reader, &master_sha)?;
    Ok(fd.new_head_sha1)
}

pub fn get_file_reader(filename: &Path) -> IoResult<BufReader<File>> {
    let file = File::open(&filename)?;
    Ok(BufReader::new(file))
}

pub fn get_password() -> Result<String> {
    if let Ok(password) = std::env::var("ARQ_PASSWORD") {
        Ok(password)
    } else {
        rpassword::prompt_password("Enter encryption password: ")
            .map_err(|e| crate::error::Error::Generic(e.to_string()))
    }
}

pub fn get_master_keys(
    path: &str,
    _computer: &str,
) -> Result<Vec<Vec<u8>>> {
    let enc_path = Path::new(path).join("encryptionv3.dat");
    let mut reader = get_file_reader(&enc_path)?;
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
    use std::fs;
    use tempfile::{NamedTempFile, TempDir, tempdir};
    use plist;

    #[test]
    fn test_find_latest_folder_sha_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let base_path = temp_dir.path();

        let result = find_latest_folder_sha(
            base_path.to_str().unwrap(),
            "test_computer",
            "test_folder",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_find_latest_folder_sha_success() {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        let base_path = temp_dir.path();
        let computer = "test_computer";
        let folder = "test_folder";

        let refs_path = base_path
            .join(computer)
            .join("bucketdata")
            .join(folder)
            .join("refs");

        let logs_master_path = refs_path.join("logs").join("master");
        fs::create_dir_all(&logs_master_path).expect("Failed to create logs/master dir");

        let heads_path = refs_path.join("heads");
        fs::create_dir_all(&heads_path).expect("Failed to create heads dir");

        let master_sha_path = heads_path.join("master");
        fs::write(&master_sha_path, b"test_master_sha_short").expect("Failed to write master sha");

        let folder_data_path = logs_master_path.join("1");
        let mut file = File::create(&folder_data_path).expect("Failed to create folder data file");

        let mut dict = plist::Dictionary::new();
        dict.insert("newHeadSHA1".into(), plist::Value::String("test_new_head_sha".into()));
        dict.insert("oldHeadSHA1".into(), plist::Value::String("test_old_head_sha".into()));
        dict.insert("packSHA1".into(), plist::Value::String("test_pack_sha".into()));
        dict.insert("old_head_stretch_key".into(), plist::Value::Boolean(false));
        dict.insert("new_head_stretch_key".into(), plist::Value::Boolean(false));
        dict.insert("is_rewrite".into(), plist::Value::Boolean(false));

        plist::to_writer_xml(&mut file, &dict).expect("Failed to write plist");

        let result = find_latest_folder_sha(
            base_path.to_str().unwrap(),
            computer,
            folder,
        ).expect("find_latest_folder_sha failed");

        assert_eq!(result, "test_new_head_sha");
    }

    #[test]
    fn test_get_file_reader_success() {
        use std::io::Write;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let test_data = b"Hello, world!";
        temp_file.write_all(test_data).expect("Failed to write to temp file");

        let mut reader = get_file_reader(temp_file.path()).unwrap();
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).expect("Failed to read from file");

        assert_eq!(buffer, test_data);
    }

    #[test]
    fn test_get_file_reader_failure() {
        let non_existent_path = PathBuf::from("does_not_exist.txt");
        let result = get_file_reader(&non_existent_path);
        assert!(result.is_err(), "Expected an error when opening non-existent file");
    }

    #[test]
    fn test_is_debug_enabled_default() {
        // By default, the IS_DEBUG atomic bool should be initialized to false.
        assert_eq!(is_debug_enabled(), false);
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
            assert_eq!(msg, format!("Backup path does not exist: {}", path.display()));
        } else {
            panic!("Expected NotFound error");
        }
    }
}
