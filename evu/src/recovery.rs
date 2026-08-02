use std::fs::File;
use std::io::{Cursor, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::commit::Commit;
use arq::packset;
use arq::tree;

pub struct RestoreOptions<'a> {
    pub trees_packset: &'a arq::packset::PackSet,
    pub blobs_packset: &'a arq::packset::PackSet,
    pub absolute_filepath: &'a str,
    pub folder: &'a str,
    pub keyset: &'a EncryptedKeySet,
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

    let blobs_path = Path::new(path)
        .join(computer)
        .join("packsets")
        .join(format!("{}-blobs", folder));

    let master_keys = utils::get_master_keys(&path, &computer)?;
    let keyset = EncryptedKeySet::from_master_keys(master_keys.clone())?;
    let head_sha = utils::find_latest_folder_sha(path, computer, folder)?;

    let trees_packset = packset::PackSet::new(&trees_path)?;
    let blobs_packset = packset::PackSet::new(&blobs_path)?;

    let data = trees_packset
        .restore_blob_with_sha(&head_sha, &keyset)?
        .ok_or_else(|| Error::NotFound(head_sha.clone()))?;
    let commit = Commit::new(Cursor::new(data))?;

    let arq_folder = utils::read_arq_folder(path, computer, folder, master_keys.clone())?;
    let tree_blob = trees_packset
        .restore_blob_with_sha(&commit.tree_sha1, &keyset)?
        .ok_or_else(|| Error::NotFound(commit.tree_sha1.clone()))?;
    let tree = tree::Tree::new_arq5(&tree_blob, commit.tree_compression_type)?;

    let options = RestoreOptions {
        trees_packset: &trees_packset,
        blobs_packset: &blobs_packset,
        absolute_filepath,
        folder,
        keyset: &keyset,
    };

    restore_file_in_tree(Path::new(&arq_folder.local_path), tree, &options)
}

fn restore_file_in_tree(prefix: &Path, tree: tree::Tree, options: &RestoreOptions) -> Result<()> {
    for (name, node) in tree.nodes {
        if !node.is_tree {
            let inner = prefix.join(name);
            if inner.as_os_str().to_string_lossy() == options.absolute_filepath {
                restore_object(
                    options.blobs_packset,
                    &node,
                    options.absolute_filepath,
                    options.keyset,
                )?;
                // Passed node as reference
            }
        } else {
            let data = options
                .trees_packset
                .restore_blob_with_sha(&node.data_blob_locs[0].blob_identifier, options.keyset)?
                .ok_or_else(|| Error::NotFound(node.data_blob_locs[0].blob_identifier.clone()))?; // Changed to data_blob_locs and blob_identifier
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
    blobs_packset: &arq::packset::PackSet,
    node: &arq::node::Node, // Changed to &arq::node::Node
    absolute_filepath: &str,
    keyset: &EncryptedKeySet,
) -> Result<()> {
    let restore_path = Path::new(absolute_filepath);
    let filename = restore_path
        .file_name()
        .ok_or_else(|| Error::OsError(std::ffi::OsString::from("not a valid restore path")))?;

    let compression = node
        .arq5_data_compression_type
        .unwrap_or(arq::compression::CompressionType::None); // Changed to arq5_data_compression_type

    let mut f = File::create(filename)?;

    for blob in &node.data_blob_locs {
        let data = blobs_packset
            .restore_blob_with_sha(&blob.blob_identifier, keyset)?
            .ok_or_else(|| Error::NotFound(blob.blob_identifier.clone()))?;
        let decompressed = arq::compression::CompressionType::decompress(&data, compression)?;
        f.write_all(&decompressed)?;
    }

    println!("Recovered '{}' to {:?}", absolute_filepath, filename);
    Ok(())
}
