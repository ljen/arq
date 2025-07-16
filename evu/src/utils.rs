use std::fs::File;
use std::io::{BufReader, Result as IoResult};
use std::path::{Path, PathBuf};

use crate::error::Result;

use arq::folder::{Folder, FolderData};
use arq::object_encryption;

pub fn get_latest_folder_data_path(path: &Path) -> Result<PathBuf> {
    let mut newest = "0".to_string();
    for entry in std::fs::read_dir(path)? {
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
    let refs_path = Path::new(path)
        .join("bucketdata")
        .join(folder)
        .join("refs");

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

pub fn get_master_keys(path: &str, _computer: &str, password: Option<&str>) -> Result<Vec<Vec<u8>>> {
    let enc_path = Path::new(path).join("encryptionv3.dat");
    let mut reader = get_file_reader(&enc_path)?;
    let password = match password {
        Some(p) => p.to_string(),
        None => rpassword::prompt_password("Enter encryption password: ")?,
    };
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
