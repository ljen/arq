use std::io::{Cursor, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::commit::Commit;
use arq::packset;
use arq::tree;
use std::collections::HashMap;

pub struct RestoreOptions<'a, 'b> {
    pub path: &'a PathBuf,
    pub absolute_filepath: &'a str,
    pub folder: &'a str,
    pub keyset: &'a EncryptedKeySet,
    pub index_cache: &'b mut HashMap<String, packset::PackIndex>,
    pub packset: &'a packset::PackSet,
}

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

    let packset = packset::PackSet::new(&trees_path);
    let data = packset.restore_blob_with_sha(&head_sha, &keyset)?;
    let commit = Commit::new(Cursor::new(data))?;

    let arq_folder = utils::read_arq_folder(path, computer, folder, master_keys.clone())?;
    let tree_blob = packset.restore_blob_with_sha(&commit.tree_sha1, &keyset)?;
    let tree = tree::Tree::new_arq5(&tree_blob, commit.tree_compression_type)?;

    let mut index_cache = HashMap::new();

    let mut options = RestoreOptions {
        path: &trees_path,
        absolute_filepath,
        folder,
        keyset: &keyset,
        index_cache: &mut index_cache,
        packset: &packset,
    };

    restore_file_in_tree(Path::new(&arq_folder.local_path), tree, &mut options)
}

fn restore_file_in_tree(
    prefix: &Path,
    tree: tree::Tree,
    options: &mut RestoreOptions,
) -> Result<()> {
    for (name, node) in tree.nodes {
        if !node.is_tree {
            let inner = prefix.join(name);
            if inner.as_os_str().to_string_lossy() == options.absolute_filepath {
                restore_object(
                    options.path,
                    options.folder,
                    &node,
                    options.absolute_filepath,
                    &options.keyset.encryption_key,
                    options.index_cache,
                )?;
                // Passed node as reference
            }
        } else {
            let tree_blob = node.data_blob_locs.first().ok_or_else(|| {
                Error::NotFound(format!("Tree '{}' has no backup blob reference", name))
            })?;
            let data = options
                .packset
                .restore_blob_with_sha(&tree_blob.blob_identifier, options.keyset)?;
            let inner_tree = tree::Tree::new_arq5(
                &data,
                node.arq5_data_compression_type
                    .unwrap_or(arq::compression::CompressionType::None),
            )?; // Changed to arq5_data_compression_type
            restore_file_in_tree(prefix.join(name).as_path(), inner_tree, options)?;
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
    index_cache: &mut std::collections::HashMap<String, packset::PackIndex>,
) -> Result<()> {
    let path = path
        .parent()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("inexistent parent folder")))?
        .join(format!("{}-blobs", folder));

    let restore_path = Path::new(absolute_filepath);
    if !restore_path.is_absolute() {
        return Err(Error::CliInputError(format!(
            "Arq 5 restore destination must be absolute: {}",
            restore_path.display()
        )));
    }
    let parent = restore_path.parent().ok_or_else(|| {
        Error::CliInputError(format!(
            "Invalid restore destination: {}",
            restore_path.display()
        ))
    })?;
    if !parent.is_dir() {
        return Err(Error::NotFound(format!(
            "Restore destination parent does not exist: {}",
            parent.display()
        )));
    }

    let compression = node
        .arq5_data_compression_type
        .unwrap_or(arq::compression::CompressionType::None);

    for entry in std::fs::read_dir(&path)? {
        let fname = entry?.file_name().to_string_lossy().to_string();
        if fname.ends_with(".index") && !index_cache.contains_key(&fname) {
            let index_path = path.join(&fname);
            let mut reader = utils::get_file_reader(&index_path)?;
            let index = packset::PackIndex::new(&mut reader)?;
            index_cache.insert(fname, index);
        }
    }

    let mut found_blobs = std::collections::HashMap::new();
    let required_blobs: std::collections::HashSet<_> = node
        .data_blob_locs
        .iter()
        .map(|blob| blob.blob_identifier.clone())
        .collect();
    for (fname, index) in index_cache.iter() {
        for object in &index.objects {
            if required_blobs.contains(&object.sha1) {
                found_blobs
                    .entry(object.sha1.clone())
                    .or_insert_with(Vec::new)
                    .push((fname.clone(), object.offset as u64));
            }
        }
    }

    let mut file_data = Vec::new();
    for blob in &node.data_blob_locs {
        let locations = found_blobs.get(&blob.blob_identifier).ok_or_else(|| {
            Error::NotFound(format!("Backup blob not found: {}", blob.blob_identifier))
        })?;
        let (index_name, offset) = locations.first().ok_or_else(|| {
            Error::NotFound(format!(
                "Backup blob has no pack location: {}",
                blob.blob_identifier
            ))
        })?;
        let pack_path = path.join(index_name.replace(".index", ".pack"));
        let mut reader = std::io::BufReader::new(utils::get_file_reader(&pack_path)?);
        reader.seek(SeekFrom::Start(*offset))?;
        let object = packset::PackObject::new(&mut reader)?;
        file_data.extend_from_slice(&object.original(compression.clone(), master_key)?);
    }

    if file_data.len() as u64 != node.item_size {
        return Err(Error::Generic(format!(
            "Restored size mismatch for {}: expected {} bytes, got {}",
            restore_path.display(),
            node.item_size,
            file_data.len()
        )));
    }

    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(restore_path)?;
    output.write_all(&file_data)?;
    filetime::set_file_mtime(
        restore_path,
        filetime::FileTime::from_unix_time(node.modification_time_sec, 0),
    )?;
    println!(
        "Recovered '{}' to {}",
        absolute_filepath,
        restore_path.display()
    );
    Ok(())
}
// weave: run 'weave explain evu/src/recovery.rs' for per-hunk detail, 'weave check' to verify your resolution
