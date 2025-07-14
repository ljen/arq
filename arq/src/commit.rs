//! Commits
//! ------------------------
//!
//! When Arq backs up a folder, it creates 3 types of objects: "commits", "trees"
//! and "blobs".
//!
//! Each backup that you see in Arq corresponds to a "commit" object in the backup
//! data.  Its name is the SHA1 of its contents. The commit contains the SHA1 of a
//! "tree" object in the backup data. This tree corresponds to the folder you're
//! backing up.
//!
//! Each tree contains "nodes" (defined in `crate::node::Node`); each node has either a pointer
//! to another tree or data blobs for a file.
//!
//! This module defines the `Commit` and unified `Tree` structures. The `Tree` struct
//! can represent directory structures from both legacy Arq5/6 binary formats (parsed by `Tree::new_arq5`)
//! and the Arq7 binary tree format (parsed by `Tree::from_arq7_binary_data`).
//!
//! All commits, trees and blobs are typically stored as EncryptedObjects in Arq backups.
use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::compression::CompressionType;
use crate::error::Result;
use crate::type_utils::ArqRead;

pub type ParentCommits = HashMap<String, bool>;
pub type FailedFile = (String, String);

/// Commit
///
/// A "commit" contains the following bytes:
///
/// ```ascii
///     43 6f 6d 6d 69 74 56 30 31 32      "CommitV012"
///     [String:"<author>"]
///     [String:"<comment>"]
///     [UInt64:num_parent_commits]        (this is always 0 or 1)
///     (
///         [String:parent_commit_sha1] /* can't be null */
///         [Bool:parent_commit_encryption_key_stretched]] /* present for Commit version >= 4 */
///     )   /* repeat num_parent_commits times */
///     [String:tree_sha1]] /* can't be null */
///     [Bool:tree_encryption_key_stretched]] /* present for Commit version >= 4 */
///     [Bool:tree_is_compressed] /* present for Commit version 8 and 9 only; indicates Gzip compression or none */
///     [CompressionType:tree_compression_type] /* present for Commit version >= 10 */
///
///     [String:"file://<hostname><path_to_folder>"]
///     [String:"<merge_common_ancestor_sha1>"] /* only present for Commit version 7 or *older* (was never used) */
///     [Bool:is_merge_common_ancestor_encryption_key_stretched] /* only present for Commit version 4 to 7 */
///     [Date:creation_date]
///     [UInt64:num_failed_files] /* only present for Commit version 3 or later */
///     (
///         [String:"<relative_path>"] /* only present for Commit version 3 or later */
///         [String:"<error_message>"] /* only present for Commit version 3 or later */
///     )   /* repeat num_failed_files times */
///     [Bool:has_missing_nodes] /* only present for Commit version 8 or later */
///     [Bool:is_complete] /* only present for Commit version 9 or later */
///     [Data:config_plist_xml] /* a copy of the XML file as described above */
///     [String:arq_version] /* the version of the Arq app that created this Commit */
/// ```
///
/// The SHA1 of the most recent Commit is stored in
/// `/<computer_uuid>/bucketdata/<folder_uuid>/refs/heads/master` appended with a "Y" for
/// historical reasons.
///
/// In addition, Arq writes a file in
/// `/<computer_uuid>/bucketdata/<folder_uuid>/refs/logs/master` each time a new Commit is
/// created (the filename is a timestamp). It's a plist containing the previous and current
/// Commit SHA1s, the SHA1 of the pack file containing the new Commit, and whether the new
/// Commit is a "rewrite" (because the user deleted a backup record for instance).
pub struct Commit {
    pub version: u32,
    pub author: String,
    pub comment: String,
    pub parent_commits: HashMap<String, bool>,
    pub tree_sha1: String,
    pub tree_encryption_key_stretched: bool,
    pub tree_compression_type: CompressionType,
    pub folder_path: String,
    pub creation_date: Option<DateTime<Utc>>,
    pub failed_files: Vec<(String, String)>,
    pub has_missing_nodes: bool,
    pub is_complete: bool,
    pub config_plist_xml: Vec<u8>,
    pub arq_version: String,
}

impl Commit {
    pub fn is_commit(content: &[u8]) -> bool {
        content[..10] == [67, 111, 109, 109, 105, 116, 86, 48, 49, 50] // CommitV012
    }

    pub fn new<R: ArqRead>(mut reader: R) -> Result<Commit> {
        let header = reader.read_bytes(10)?;
        assert_eq!(header[..7], [67, 111, 109, 109, 105, 116, 86]); // CommitV
        let version = std::str::from_utf8(&header[7..])?.parse::<u32>()?;

        let author = reader.read_arq_string()?;
        let comment = reader.read_arq_string()?;

        let mut num_parent_commits = reader.read_arq_u64()?;
        assert!(num_parent_commits == 0 || num_parent_commits == 1);

        let mut parent_commits: HashMap<String, bool> = HashMap::new();
        while num_parent_commits > 0 {
            let sha1 = reader.read_arq_string()?;
            let encryption_key_stretched = reader.read_arq_bool()?;

            parent_commits.insert(sha1, encryption_key_stretched);
            num_parent_commits -= 1;
        }

        let tree_sha1 = reader.read_arq_string()?;
        let tree_encryption_key_stretched = reader.read_arq_bool()?;
        let tree_compression_type = reader.read_arq_compression_type()?;
        let folder_path = reader.read_arq_string()?;

        // Read and convert creation_date
        let parsed_creation_date: Option<DateTime<Utc>>;
        let present_byte = reader.read_bytes(1)?;
        if present_byte[0] == 0x01 {
            let milliseconds_since_epoch = reader.read_arq_u64()?;
            if milliseconds_since_epoch == 0 {
                parsed_creation_date = None;
            } else {
                parsed_creation_date =
                    DateTime::from_timestamp_millis(milliseconds_since_epoch as i64);
                if parsed_creation_date.is_none() {
                    return Err(crate::error::Error::InvalidFormat(format!(
                        "Invalid timestamp for commit creation_date: {}ms",
                        milliseconds_since_epoch
                    )));
                }
            }
        } else {
            parsed_creation_date = None;
        }

        let mut num_failed_files = reader.read_arq_u64()?;
        let mut failed_files: Vec<(String, String)> = Vec::new();
        while num_failed_files > 0 {
            let relative_path = reader.read_arq_string()?;
            let error_message = reader.read_arq_string()?;

            failed_files.push((relative_path, error_message));
            num_failed_files -= 1;
        }

        let has_missing_nodes = reader.read_arq_bool()?;
        let is_complete = reader.read_arq_bool()?;
        let config_plist_xml = reader.read_arq_data()?;
        let arq_version = reader.read_arq_string()?;

        Ok(Commit {
            version,
            author,
            comment,
            parent_commits,
            tree_sha1,
            tree_encryption_key_stretched,
            tree_compression_type,
            folder_path,
            creation_date: parsed_creation_date,
            failed_files,
            has_missing_nodes,
            is_complete,
            config_plist_xml,
            arq_version,
        })
    }
}
