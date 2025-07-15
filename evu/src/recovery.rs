use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::packset;
use arq::tree;
use arq::commit::{Commit};

pub fn restore_file(
    path: &str,
    computer: &str,
    folder: &str,
    absolute_filepath: &str,
) -> Result<()> {
    let trees_path = Path::new(path)
        .join(computer)
        .join("packsets")
        .join(format!("{}-trees", folder));

    let master_keys = utils::get_master_keys(&path, &computer)?;
    let keyset = EncryptedKeySet::from_master_keys(master_keys.clone())?;
    let head_sha = utils::find_latest_folder_sha(path, computer, folder)?;

    let data = packset::restore_blob_with_sha(&trees_path, &head_sha, &keyset)?;
    let commit = Commit::new(Cursor::new(data))?;

    let arq_folder = utils::read_arq_folder(path, computer, folder, master_keys.clone())?;
    let tree_blob = packset::restore_blob_with_sha(&trees_path, &commit.tree_sha1, &keyset)?;
    let tree = tree::Tree::new_arq5(&tree_blob, commit.tree_compression_type)?;
    restore_file_in_tree(
        Path::new(&arq_folder.local_path),
        &trees_path,
        absolute_filepath,
        folder,
        tree,
        &keyset,
    )
}

fn restore_file_in_tree(
    prefix: &Path,
    path: &PathBuf,
    absolute_filepath: &str,
    folder: &str,
    tree: tree::Tree,
    keyset: &EncryptedKeySet,
) -> Result<()> {
    for (name, node) in tree.nodes {
        if !node.is_tree {
            let inner = prefix.join(name);
            if inner.as_os_str().to_str().unwrap() == absolute_filepath {
                restore_object(path, folder, &node, absolute_filepath, &keyset.encryption_key)?;
                // Passed node as reference
            }
        } else {
            let data =
                packset::restore_blob_with_sha(path, &node.data_blob_locs[0].blob_identifier, keyset)?; // Changed to data_blob_locs and blob_identifier
            let inner_tree = tree::Tree::new_arq5(
                &data,
                node.arq5_data_compression_type
                    .unwrap_or(arq::compression::CompressionType::None),
            )?; // Changed to arq5_data_compression_type
            restore_file_in_tree(
                prefix.join(name).as_path(),
                path,
                absolute_filepath,
                folder,
                inner_tree,
                keyset,
            )?;
        }
    }
    Ok(())
}

fn restore_object(
    path: &Path,
    folder: &str,
    node: &arq::node::Node, // Changed to &arq::node::Node
    absolute_filepath: &str,
    master_key: &[u8],
) -> Result<()> {
    let path = path
        .parent()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("inexistent parent folder")))?
        .join(format!("{}-blobs", folder));

    let restore_path = Path::new(absolute_filepath);
    let filename = restore_path
        .file_name()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("not a valid restore path")))?;

    let compression = node.arq5_data_compression_type.unwrap_or(arq::compression::CompressionType::None); // Changed to arq5_data_compression_type

    for blob in &node.data_blob_locs { // Iterate over a reference to avoid moving
        for entry in std::fs::read_dir(&path)? {
            let fname = entry?.file_name().to_str().unwrap().to_string();
            if fname.ends_with(".index") {
                let index_path = path.join(&fname);
                let mut reader = utils::get_file_reader(index_path);
                let index = packset::PackIndex::new(&mut reader)?;
                for obj in index.objects {
                    if obj.sha1 == blob.blob_identifier { // Changed blob.sha1 to blob.blob_identifier
                        let pack_path = path.join(&fname.replace(".index", ".pack"));
                        let mut reader = utils::get_file_reader(pack_path);
                        reader.seek(SeekFrom::Start(obj.offset as u64))?;
                        let ob = packset::PackObject::new(&mut reader)?;
                        let mut f = File::create(filename)?;
                        let data = ob.original(compression.clone(), master_key)?;
                        f.write_all(&data)?;
                        println!("Recovered '{}' to {:?}", absolute_filepath, filename);
                    }
                }
            }
        }
    }
    Ok(())
}
