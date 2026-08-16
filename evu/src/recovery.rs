use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom, Write};
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
    use rpassword;

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
            let data = options.packset.restore_blob_with_sha(
                &node.data_blob_locs[0].blob_identifier,
                options.keyset,
            )?; // Changed to data_blob_locs and blob_identifier
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
    let filename = restore_path
        .file_name()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("not a valid restore path")))?;

    let compression = node
        .arq5_data_compression_type
        .unwrap_or(arq::compression::CompressionType::None); // Changed to arq5_data_compression_type

    for entry in std::fs::read_dir(&path)? {
        let fname = entry?.file_name().to_string_lossy().to_string();
        if fname.ends_with(".index") {
            if !index_cache.contains_key(&fname) {
                let index_path = path.join(&fname);
                let mut reader = utils::get_file_reader(&index_path)?;
                let index = packset::PackIndex::new(&mut reader)?;
                index_cache.insert(fname.clone(), index);
            }
        }
    }

    let mut found_blobs = std::collections::HashMap::new();
    let required_blobs: std::collections::HashSet<_> = node
        .data_blob_locs
        .iter()
        .map(|b| b.blob_identifier.clone())
        .collect();

    for (fname, index) in index_cache.iter() {
        for obj in &index.objects {
            if required_blobs.contains(&obj.sha1) {
                found_blobs
                    .entry(obj.sha1.clone())
                    .or_insert_with(Vec::new)
                    .push((fname.clone(), obj.offset as u64));
            }
        }
    }

    for blob in &node.data_blob_locs {
        // Iterate over a reference to avoid moving
        if let Some(locations) = found_blobs.get(&blob.blob_identifier) {
            for (fname, offset) in locations {
                let pack_path = path.join(&fname.replace(".index", ".pack"));
                let mut reader = std::io::BufReader::new(utils::get_file_reader(&pack_path)?);
                reader.seek(SeekFrom::Start(*offset))?;
                let mut reader = std::io::BufReader::new(reader);
                let ob = packset::PackObject::new(&mut reader)?;
                let mut f = File::create(filename)?;
                let data = ob.original(compression.clone(), master_key)?;
                f.write_all(&data)?;
                println!("Recovered '{}' to {:?}", absolute_filepath, filename);
            }
        }
    }
    Ok(())
}
// weave: run 'weave explain evu/src/recovery.rs' for per-hunk detail, 'weave check' to verify your resolution
