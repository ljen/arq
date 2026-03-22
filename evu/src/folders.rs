use std;
use std::path::Path;

use crate::error::Result;
use crate::utils;

use arq::folder::Folder;

pub fn show(path: &str, computer: &str, password: Option<&str>) -> Result<()> {
    let computer_path = Path::new(path);
    let master_keys = utils::get_master_keys(&path, &computer, password)?;

    println!("Folders for computer {}\n----------------", computer);
    for entry in std::fs::read_dir(computer_path.join("buckets"))? {
        let filename = entry?.path();
        let mut reader = utils::get_file_reader(&filename)?;
        let folder = Folder::new(&mut reader, &master_keys)?;
        println!(
            "Bucket: {} ({})\nPath: {}\n",
            folder.bucket_name, folder.bucket_uuid, folder.local_path
        );
    }
    Ok(())
}
