use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::utils;

use arq::arq7::EncryptedKeySet;
use arq::packset;
use arq::tree;
use arq::commit::{self, Commit};

fn show_commit(commit: &Commit) {
    println!(
        "   - author: {}, comment: {}, version: {}, location: {}",
        &commit.author, &commit.comment, &commit.version, &commit.folder_path
    );
    println!("   - failed files count: {}", &commit.failed_files.len());
    println!("   - has missing nodes: {}", &commit.has_missing_nodes);
    println!("   - is complete: {}", &commit.is_complete);
    println!("   - arq version: {}", &commit.arq_version);
    println!("   - tree sha1: {}", &commit.tree_sha1);
    println!(
        "   - date: {}",
        &commit
            .creation_date
            .map_or("N/A".to_string(), |d| d.to_rfc3339())
    );
    println!("   - tree compression: {:?}", &commit.tree_compression_type);
    if !commit.parent_commits.is_empty() {
        println!("   ::Parent commits::");
        for parent_commit in commit.parent_commits.keys() {
            println!("    - {}", parent_commit);
        }
    }
}

pub fn show(path: &str, computer: &str, folder: &str) -> Result<()> {
    println!("Tree\n----");
    println!("\nComputer: {}, Folder: {}\n", computer, folder);

    let trees_path = std::path::Path::new(path)
        .join(computer)
        .join("packsets")
        .join(format!("{}-trees", folder));
    let master_keys = utils::get_master_keys(&path, &computer)?;
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
    //show_commit(&commit);

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
            if v.data_blob_locs.is_empty() {
                // Changed data_blob_keys to data_blob_locs
                continue;
            }
            let data =
                packset::restore_blob_with_sha(&path, &v.data_blob_locs[0].blob_identifier, &keyset)?; // Changed to data_blob_locs and blob_identifier
            let tree = tree::Tree::new_arq5(
                &data,
                v.arq5_data_compression_type
                    .unwrap_or(arq::compression::CompressionType::None),
            )?; // Changed to arq5_data_compression_type
            render_internal_tree(prefix.join(k).as_path(), &path, tree, &keyset)?;
        } else {
            println!("{}", prefix.join(k).as_os_str().to_str().unwrap());
        }
    }
    Ok(())
}
