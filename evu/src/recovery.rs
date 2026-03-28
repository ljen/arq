use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::packset;
use arq::tree;
use arq::commit::Commit;

pub fn restore_file(
    path: &str,
    computer: &str,
    folder: &str,
    absolute_filepath: &str,
) -> Result<()> {
    use rpassword;

    let trees_path = Path::new(path)
        .join(computer)
        .join("packsets")
        .join(format!("{}-trees", folder));

    let password = rpassword::prompt_password("Enter encryption password: ")?;
    let master_keys = utils::get_master_keys(path, computer, Some(&password))?;
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
            let inner = prefix.join(&name);
            if inner.as_os_str().to_str().unwrap() == absolute_filepath {
                restore_object(path, folder, &node, absolute_filepath, &keyset.encryption_key)?;
            }
        } else {
            let tree_blob_loc = node.tree_blob_loc.as_ref().ok_or_else(|| {
                Error::Generic(format!(
                    "Tree node '{}' has no tree_blob_loc",
                    name
                ))
            })?;
            let data =
                packset::restore_blob_with_sha(path, &tree_blob_loc.blob_identifier, keyset)?;
            let inner_tree = tree::Tree::new_arq5(
                &data,
                node.arq5_data_compression_type
                    .unwrap_or(arq::compression::CompressionType::None),
            )?;
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
    node: &arq::node::Node,
    absolute_filepath: &str,
    master_key: &[u8],
) -> Result<()> {
    let blobs_path = path
        .parent()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("inexistent parent folder")))?
        .join(format!("{}-blobs", folder));

    let restore_path = Path::new(absolute_filepath);
    let filename = restore_path
        .file_name()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("not a valid restore path")))?;

    let compression = node
        .arq5_data_compression_type
        .unwrap_or(arq::compression::CompressionType::None);

    // Collect all blob data chunks first, then write once
    let mut file_data = Vec::new();

    for blob in &node.data_blob_locs {
        let mut found = false;
        for entry in std::fs::read_dir(&blobs_path)? {
            let fname = entry?.file_name().to_str().unwrap().to_string();
            if fname.ends_with(".index") {
                let index_path = blobs_path.join(&fname);
                let mut reader = utils::get_file_reader(&index_path)?;
                let index = packset::PackIndex::new(&mut reader)?;
                for obj in index.objects {
                    if obj.sha1 == blob.blob_identifier {
                        let pack_path = blobs_path.join(&fname.replace(".index", ".pack"));
                        let mut reader = utils::get_file_reader(&pack_path)?;
                        reader.seek(SeekFrom::Start(obj.offset as u64))?;
                        let ob = packset::PackObject::new(&mut reader)?;
                        let data = ob.original(compression.clone(), master_key)?;
                        file_data.extend_from_slice(&data);
                        found = true;
                        break;
                    }
                }
            }
            if found {
                break;
            }
        }
    }

    let mut f = File::create(filename)?;
    f.write_all(&file_data)?;
    println!("Recovered '{}' to {:?}", absolute_filepath, filename);
    Ok(())
}
