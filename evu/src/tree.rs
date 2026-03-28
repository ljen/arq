use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::packset;
use arq::tree;
use arq::commit::Commit;

pub fn show(path: &str, computer: &str, folder: &str, password: Option<&str>) -> Result<()> {
    println!("Tree for folder {}\n----------------", folder);

    let computer_path = Path::new(path);
    let trees_path = computer_path
        .join("packsets")
        .join(format!("{}-trees", folder));
    let master_keys = utils::get_master_keys(&path, &computer, password)?;
    let keyset = EncryptedKeySet::from_master_keys(master_keys.clone())?;
    let arq_folder = utils::read_arq_folder(path, computer, folder, master_keys.clone())?;
    let head_sha = utils::find_latest_folder_sha(path, computer, folder)?;

    render_tree(
        Path::new(&arq_folder.local_path),
        &trees_path,
        &head_sha,
        &keyset,
    )
}

fn render_tree(
    prefix: &std::path::Path,
    path: &std::path::PathBuf,
    sha: &str,
    keyset: &EncryptedKeySet,
) -> Result<()> {
    let data = packset::restore_blob_with_sha(path, sha, keyset)?;
    let commit = Commit::new(Cursor::new(data))?;
    let tree_blob = packset::restore_blob_with_sha(path, &commit.tree_sha1, keyset)?;
    let tree = tree::Tree::new_arq5(&tree_blob, commit.tree_compression_type)?;
    render_internal_tree(prefix, &path, tree, keyset)?;
    Ok(())
}

fn render_internal_tree(
    prefix: &std::path::Path,
    path: &PathBuf,
    tr: tree::Tree,
    keyset: &EncryptedKeySet,
) -> Result<()> {
    for (k, v) in tr.nodes {
        if v.is_tree {
            let tree_blob_loc = match v.tree_blob_loc.as_ref() {
                Some(loc) => loc,
                None => continue, // Skip trees with no tree blob reference
            };
            let data =
                packset::restore_blob_with_sha(path, &tree_blob_loc.blob_identifier, keyset)?;
            let tree = tree::Tree::new_arq5(
                &data,
                v.arq5_data_compression_type
                    .unwrap_or(arq::compression::CompressionType::None),
            )?;
            render_internal_tree(prefix.join(k).as_path(), path, tree, keyset)?;
        } else {
            println!("{}", prefix.join(k).as_os_str().to_str().unwrap());
        }
    }
    Ok(())
}
