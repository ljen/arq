//! # Unified Node
//!
//! This module defines the unified `Node` structure, designed to represent file system
//! entries (files or directories) from various Arq backup formats, including Arq 5/6 (legacy binary)
//! and Arq 7 (JSON and a newer binary format).
//!
//! The `Node` struct aims to consolidate fields from different Arq versions into a single,
//! comprehensive representation. It uses `Option` for fields not present in all versions
//! and primarily aligns with the Arq 7 JSON structure for `serde` serialization/deserialization.
//!
//! ## Key Features:
//! - **Unified Representation**: Handles metadata from both older and newer Arq formats.
//! - **Serde Compatibility**: Derives `Serialize` and `Deserialize` for compatibility with Arq 7 JSON records.
//! - **Binary Parsers**: Provides methods (`from_binary_reader_arq5` and `from_binary_reader_arq7`)
//!   to parse nodes from their respective binary formats.
//! - **BlobLoc Usage**: Uses `BlobLoc` (from `crate::arq7`) for referencing data, tree, xattrs, and ACL blobs,
//!   aligning with Arq 7's approach.
//!
//! The fields specific to older Arq 5/6 formats are typically stored as `Option`al values
//! and may not be part of the default JSON serialization if they are primarily for internal
//! representation during parsing of those older formats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::blob_location::BlobLoc; // Changed path
use crate::blob::BlobKey; // For legacy fields if needed, though BlobLoc is preferred
use crate::compression::CompressionType; // For legacy fields
use crate::error::Result;
use crate::type_utils::ArqRead;
use crate::arq7::binary::ArqBinaryReader; // For Arq7 binary parsing

/// Represents a file system node (a file or a directory) in a unified way,
/// accommodating fields from different Arq backup formats (Arq 5/6 legacy and Arq 7).
///
/// This struct is designed to be the primary representation of nodes after parsing.
/// It aligns with Arq 7's JSON structure for `serde` compatibility but includes
/// optional fields (`arq5_...`) to store metadata specific to older Arq formats
/// if parsed from such a source.
///
/// Key aspects:
/// - `is_tree`: Indicates if the node is a directory (true) or a file (false).
/// - `item_size`: For files, the size of the file data. For trees, often 0.
/// - Timestamps (`modification_time_sec`, `change_time_sec`, `creation_time_sec`, etc.) are stored in seconds and nanoseconds.
/// - Permissions and ownership (`st_mode`, `st_uid`, `st_gid`, etc.) are stored, with names generally
///   following Arq 7's `mac_st_...` convention for JSON, but representing standard POSIX values.
/// - `data_blob_locs`: A list of `BlobLoc` structs pointing to the actual data chunks for files.
/// - `tree_blob_loc`: An optional `BlobLoc` pointing to the binary tree data if `is_tree` is true.
///   This is primarily used by Arq 7 and Arq 5 trees (where it's derived from the first data blob key).
/// - `xattrs_blob_locs`, `acl_blob_loc`: Optional `BlobLoc`s for extended attributes and ACLs.
/// - Arq5-specific fields like `arq5_data_compression_type` or `arq5_finder_flags` are stored
///   optionally to preserve information when parsing older formats. These are typically not
///   serialized to JSON.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    // Common fields (mostly from Arq7 structure for JSON compatibility)
    #[serde(rename = "isTree")]
    pub is_tree: bool,
    #[serde(rename = "itemSize")]
    pub item_size: u64, // For files: data_size. For trees: often 0 or size of tree data itself.
    #[serde(default)] // Arq5 nodes are not explicitly "deleted" in the same way
    pub deleted: bool,
    #[serde(rename = "computerOSType", skip_serializing_if = "Option::is_none", default)]
    pub computer_os_type: Option<u32>, // 1 for Mac, 2 for Windows, 3 for Linux (Arq7)

    // Timestamps (Arq7 names)
    #[serde(rename = "modificationTime_sec")]
    pub modification_time_sec: i64,
    #[serde(rename = "modificationTime_nsec")]
    pub modification_time_nsec: i64,
    #[serde(rename = "changeTime_sec")]
    pub change_time_sec: i64,
    #[serde(rename = "changeTime_nsec")]
    pub change_time_nsec: i64,
    #[serde(rename = "creationTime_sec")]
    pub creation_time_sec: i64,
    #[serde(rename = "creationTime_nsec")]
    pub creation_time_nsec: i64,

    // Permissions and ownership (Arq7 names, with optional mapping from Arq5)
    #[serde(rename = "mac_st_mode")] // Equivalent to 'mode' in Arq5
    pub st_mode: u32,
    #[serde(rename = "mac_st_ino")] // Arq5 'st_ino' is i32
    pub st_ino: u64,
    #[serde(rename = "mac_st_nlink")]
    pub st_nlink: u32,
    #[serde(rename = "mac_st_gid")] // Arq5 'gid' is i32
    pub st_gid: u32,
    #[serde(rename = "mac_st_uid", skip_serializing_if = "Option::is_none", default)] // Arq5 'uid' is i32
    pub st_uid: Option<u32>,

    #[serde(rename = "username", skip_serializing_if = "Option::is_none", default)]
    pub username: Option<String>,
    #[serde(rename = "groupName", skip_serializing_if = "Option::is_none", default)]
    pub group_name: Option<String>,

    // Device info (Arq7 names)
    #[serde(rename = "mac_st_dev")]
    pub st_dev: i32,
    #[serde(rename = "mac_st_rdev")]
    pub st_rdev: i32,

    // Flags (Arq7 names)
    #[serde(rename = "mac_st_flags")] // Arq5 'flags'
    pub st_flags: i32,

    // Windows specific (Arq7)
    #[serde(rename = "winAttrs", skip_serializing_if = "Option::is_none", default)]
    pub win_attrs: Option<u32>,
    #[serde(rename = "reparseTag", skip_serializing_if = "Option::is_none", default)]
    pub reparse_tag: Option<u32>,
    #[serde(rename = "reparsePointIsDirectory", skip_serializing_if = "Option::is_none", default)]
    pub reparse_point_is_directory: Option<bool>,

    // Counts (Arq7)
    #[serde(rename = "containedFilesCount", skip_serializing_if = "Option::is_none", default)]
    pub contained_files_count: Option<u64>, // For trees

    // BlobLocs - primary way to store data pointers (Arq7 style)
    #[serde(rename = "dataBlobLocs", default, skip_serializing_if = "Vec::is_empty")]
    pub data_blob_locs: Vec<BlobLoc>,
    #[serde(rename = "treeBlobLoc", skip_serializing_if = "Option::is_none", default)]
    pub tree_blob_loc: Option<BlobLoc>, // For trees
    #[serde(rename = "xattrsBlobLocs", skip_serializing_if = "Option::is_none", default)]
    pub xattrs_blob_locs: Option<Vec<BlobLoc>>,
    #[serde(rename = "aclBlobLoc", skip_serializing_if = "Option::is_none", default)]
    pub acl_blob_loc: Option<BlobLoc>,

    // Arq5 specific fields (to be populated by from_binary_reader_arq5)
    // These might not be serialized to JSON if they are purely for internal representation of older formats.
    // Or, they are mapped to the Arq7 fields above.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_tree_contains_missing_items: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_data_compression_type: Option<CompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_xattrs_compression_type: Option<CompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_acl_compression_type: Option<CompressionType>,

    // Arq5 uses Vec<BlobKey> for data_blob_keys. This will be transformed into Vec<BlobLoc>
    // by the arq5 parser. We don't store them directly as BlobKey here to keep unified structure.
    // pub arq5_data_blob_keys: Option<Vec<BlobKey>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_xattrs_blob_key: Option<BlobKey>, // Stored if needed for direct Arq5 data access
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_xattrs_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_acl_blob_key: Option<BlobKey>, // Stored if needed

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_finder_flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_extended_finder_flags: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_finder_file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_finder_file_creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_is_file_extension_hidden: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_st_blocks: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arq5_st_blksize: Option<u32>,
}

impl Node {
    /// Parses a Node from the Arq 7 binary format.
    ///
    /// This method is used to decode a node when reading an Arq 7 binary tree
    /// (usually from a `treeBlobLoc`).
    ///
    /// # Arguments
    /// * `reader`: A reader implementing `ArqBinaryReader` positioned at the start of the node data.
    /// * `tree_version`: The version of the Arq 7 binary tree containing this node. This is
    ///   used to handle version-specific fields like reparse point data.
    pub fn from_binary_reader_arq7<R: ArqBinaryReader>(
        reader: &mut R,
        tree_version: Option<u32>, // Arq7 tree version (e.g., from BinaryTree header)
    ) -> Result<Self> {
        let is_tree = reader.read_arq_bool()?;
        let tree_blob_loc = if is_tree {
            BlobLoc::from_binary_reader(reader).ok()
        } else {
            None
        };
        let computer_os_type = reader.read_arq_u32()?;
        let data_blob_locs_count = reader.read_arq_u64()?;
        let mut data_blob_locs = Vec::new();
        for _i in 0..data_blob_locs_count {
            data_blob_locs.push(BlobLoc::from_binary_reader(reader).map_err(|e| {
                crate::error::Error::ParseErrorMsg(format!("Failed to parse data BlobLoc: {}", e))
            })?);
        }

        let acl_blob_loc = match reader.read_arq_bool()? {
            true => Some(BlobLoc::from_binary_reader(reader).map_err(|e| {
                crate::error::Error::ParseErrorMsg(format!("Failed to parse acl BlobLoc: {}", e))
            })?),
            false => None,
        };

        let xattrs_blob_locs_count = reader.read_arq_u64().unwrap_or(0);
        let mut parsed_xattrs_blob_locs = Vec::new();
        for _ in 0..xattrs_blob_locs_count {
            parsed_xattrs_blob_locs.push(BlobLoc::from_binary_reader(reader).map_err(|e| {
                crate::error::Error::ParseErrorMsg(format!("Failed to parse xattrs BlobLoc: {}", e))
            })?);
        }
        let xattrs_blob_locs = if parsed_xattrs_blob_locs.is_empty() {
            None
        } else {
            Some(parsed_xattrs_blob_locs)
        };

        let item_size = reader.read_arq_u64().unwrap_or(if is_tree { 0 } else { 0 }); // Default to 0 if missing
        let contained_files_count = Some(reader.read_arq_u64().unwrap_or(if is_tree { 0 } else { 1 }));

        let modification_time_sec = reader.read_arq_i64().unwrap_or(0);
        let modification_time_nsec = reader.read_arq_i64().unwrap_or(0);
        let change_time_sec = reader.read_arq_i64().unwrap_or(0);
        let change_time_nsec = reader.read_arq_i64().unwrap_or(0);
        let creation_time_sec = reader.read_arq_i64().unwrap_or(0);
        let creation_time_nsec = reader.read_arq_i64().unwrap_or(0);

        let username = reader.read_arq_string().ok().flatten();
        let group_name = reader.read_arq_string().ok().flatten();
        let deleted = reader.read_arq_bool().unwrap_or(false);

        let st_dev = reader.read_arq_i32().unwrap_or(0);
        let st_ino = reader.read_arq_u64().unwrap_or(0);
        let st_mode = reader.read_arq_u32().unwrap_or(if is_tree { 0o040755 } else { 0o100644 });
        let st_nlink = reader.read_arq_u32().unwrap_or(1);
        let st_uid = Some(reader.read_arq_u32().unwrap_or(0));
        let st_gid = reader.read_arq_u32().unwrap_or(0);
        let st_rdev = reader.read_arq_i32().unwrap_or(0);
        let st_flags = reader.read_arq_i32().unwrap_or(0); // mac_st_flags

        let win_attrs = reader.read_arq_u32().ok(); // Optional

        let mut reparse_tag = None;
        let mut reparse_point_is_directory = None;

        // Arq 7 binary Node format has versioning for reparse points based on Tree version,
        // but the provided `arq::arq7::Node::from_binary_reader` uses tree_version >= 2.
        // The `arq::arq7::binary::BinaryTree` itself has a version.
        // We assume `tree_version` passed here corresponds to the version of the containing tree.
        if tree_version.unwrap_or(0) >= 2 { // Default to 0 if no tree_version, won't read these
            reparse_tag = reader.read_arq_u32().ok();
            reparse_point_is_directory = reader.read_arq_bool().ok();
        }

        Ok(Node {
            is_tree,
            item_size,
            deleted,
            computer_os_type: Some(computer_os_type),
            modification_time_sec,
            modification_time_nsec,
            change_time_sec,
            change_time_nsec,
            creation_time_sec,
            creation_time_nsec,
            st_mode,
            st_ino,
            st_nlink,
            st_gid,
            st_uid,
            username,
            group_name,
            st_dev,
            st_rdev,
            st_flags,
            win_attrs,
            contained_files_count,
            data_blob_locs,
            tree_blob_loc,
            xattrs_blob_locs,
            acl_blob_loc,
            reparse_tag,
            reparse_point_is_directory,
            // Arq5 specific fields are None when parsing from Arq7
            arq5_tree_contains_missing_items: None,
            arq5_data_compression_type: None,
            arq5_xattrs_compression_type: None,
            arq5_acl_compression_type: None,
            arq5_xattrs_blob_key: None,
            arq5_xattrs_size: None,
            arq5_acl_blob_key: None,
            arq5_finder_flags: None,
            arq5_extended_finder_flags: None,
            arq5_finder_file_type: None,
            arq5_finder_file_creator: None,
            arq5_is_file_extension_hidden: None,
            arq5_st_blocks: None,
            arq5_st_blksize: None,
        })
    }

    /// Parses a Node from the legacy Arq 5/6 binary format.
    ///
    /// This method is used to decode a node when reading an Arq 5/6 format tree
    /// (e.g., when parsing a tree blob obtained via `crate::tree::Tree::new_arq5`).
    ///
    /// # Arguments
    /// * `reader`: A reader implementing `ArqRead + std::io::BufRead` positioned at the start of the node data.
    /// * `tree_version`: The version of the Arq 5/6 tree containing this node (e.g., 12, 18, 22).
    ///   This is crucial for correctly parsing version-dependent fields.
    pub fn from_binary_reader_arq5<R: ArqRead + std::io::BufRead>( // ArqRead for arq_primitives, BufRead for general use
        reader: &mut R,
        tree_version: u32, // Arq5 tree versions (e.g., 12, 18, 19, 20, 22)
    ) -> Result<Self> {
        let is_tree = reader.read_arq_bool()?;

        let tree_contains_missing_items = if tree_version >= 18 {
            reader.read_arq_bool()?
        } else {
            false // Default for older versions
        };

        let mut data_compression_type_arq5 = CompressionType::None;
        let mut xattrs_compression_type_arq5 = CompressionType::None;
        let mut acl_compression_type_arq5 = CompressionType::None;

        if tree_version >= 19 {
            data_compression_type_arq5 = reader.read_arq_compression_type()?;
            xattrs_compression_type_arq5 = reader.read_arq_compression_type()?;
            acl_compression_type_arq5 = reader.read_arq_compression_type()?;
        } else if tree_version >= 12 { // Versions 12-18 used simple booleans
            if reader.read_arq_bool()? { data_compression_type_arq5 = CompressionType::Gzip; }
            if reader.read_arq_bool()? { xattrs_compression_type_arq5 = CompressionType::Gzip; }
            if reader.read_arq_bool()? { acl_compression_type_arq5 = CompressionType::Gzip; }
        }

        let mut data_blob_keys_count = reader.read_arq_i32()?;
        let mut arq5_data_blob_keys = Vec::new();
        while data_blob_keys_count > 0 {
            if let Some(data_blob_key) = BlobKey::new(reader)? {
                arq5_data_blob_keys.push(data_blob_key);
            }
            data_blob_keys_count -= 1;
        }
        let data_size = reader.read_arq_u64()?;

        // Thumbnail and preview SHA1s (Arq5 specific, deprecated)
        if tree_version <= 18 {
            let _thumbnail_sha1 = reader.read_arq_string()?; // unused
            if tree_version >= 14 {
                let _is_thumbnail_encryption_key_stretched = reader.read_arq_bool()?; // unused
            }
            let _preview_sha1 = reader.read_arq_string()?; // unused
            if tree_version >= 14 {
                let _is_preview_encryption_key_stretched = reader.read_arq_bool()?; // unused
            }
        }

        let xattrs_blob_key_arq5 = BlobKey::new(reader)?;
        let xattrs_size_arq5 = reader.read_arq_u64()?;
        let acl_blob_key_arq5 = BlobKey::new(reader)?;

        let uid_val = reader.read_arq_i32()?;
        let gid_val = reader.read_arq_i32()?;
        let mode_val = reader.read_arq_i32()?;
        let mtime_sec_val = reader.read_arq_i64()?;
        let mtime_nsec_val = reader.read_arq_i64()?;
        let flags_val = reader.read_arq_i64()?;
        let finder_flags_val = reader.read_arq_i32()?;
        let extended_finder_flags_val = reader.read_arq_i32()?;
        let finder_file_type_val = reader.read_arq_string()?;
        let finder_file_creator_val = reader.read_arq_string()?;
        let is_file_extension_hidden_val = reader.read_arq_bool()?;
        let st_dev_val = reader.read_arq_i32()?;
        let st_ino_val = reader.read_arq_i32()?; // Note: i32 in Arq5, u64 in Arq7 (st_ino)
        let st_nlink_val = reader.read_arq_u32()?;
        let st_rdev_val = reader.read_arq_i32()?;
        let ctime_sec_val = reader.read_arq_i64()?;
        let ctime_nsec_val = reader.read_arq_i64()?;

        let create_time_sec_val = if tree_version >= 15 { reader.read_arq_i64()? } else { 0 };
        let create_time_nsec_val = if tree_version >= 15 { reader.read_arq_i64()? } else { 0 };

        let st_blocks_val = reader.read_arq_i64()?;
        let st_blksize_val = reader.read_arq_u32()?;

        // Transform Arq5 BlobKeys to Arq7 BlobLocs. This is a simplification.
        // A proper transformation would require context about pack files if these blobs are packed.
        // For now, create "unpacked" BlobLocs using the SHA1 as identifier.
        // This assumes Arq5 blobs are standalone or their pack context is resolved elsewhere.
        let data_blob_locs_transformed: Vec<BlobLoc> = arq5_data_blob_keys.iter().map(|bk| BlobLoc {
            blob_identifier: bk.sha1.clone(),
            compression_type: bk.compression_type, // BlobKey now has this
            is_packed: false, // Assumption: Arq5 Node format doesn't specify packing for individual data keys here
            length: bk.archive_size, // Approximation, actual length might differ post-decompression
            offset: 0,
            relative_path: format!("arq5_blob/{}", bk.sha1), // Placeholder path
            stretch_encryption_key: bk.stretch_encryption_key,
            is_large_pack: Some(false),
        }).collect();

        let tree_blob_loc_transformed = if is_tree {
            // Arq5 Node format doesn't have a direct tree_blob_key/loc like Arq7.
            // The tree's content (other nodes) are part of the same stream for Arq5 Tree.
            // If this node *is* a tree, its *data_blob_keys* would point to tree data.
            // This is a key difference. For now, if is_tree, take the first data_blob_loc.
            // This might need refinement based on how Arq5 trees are structured if a single Node object represents a tree *pointer*.
            // However, `arq::tree::Node` seems to represent an entry *within* a tree.
            // If `is_tree` is true, `data_blob_keys` actually points to the content of the sub-tree.
            // So, we use the first data_blob_loc as the tree_blob_loc.
            data_blob_locs_transformed.first().cloned()
        } else {
            None
        };

        let xattrs_blob_loc_transformed = xattrs_blob_key_arq5.as_ref().map(|bk| BlobLoc {
            blob_identifier: bk.sha1.clone(),
            compression_type: bk.compression_type,
            is_packed: false,
            length: bk.archive_size,
            offset: 0,
            relative_path: format!("arq5_xattrs/{}", bk.sha1),
            stretch_encryption_key: bk.stretch_encryption_key,
            is_large_pack: Some(false),
        });

        let acl_blob_loc_transformed = acl_blob_key_arq5.as_ref().map(|bk| BlobLoc {
            blob_identifier: bk.sha1.clone(),
            compression_type: bk.compression_type,
            is_packed: false,
            length: bk.archive_size,
            offset: 0,
            relative_path: format!("arq5_acl/{}", bk.sha1),
            stretch_encryption_key: bk.stretch_encryption_key,
            is_large_pack: Some(false),
        });

        Ok(Node {
            is_tree,
            item_size: data_size, // Arq5 data_size is equivalent to item_size for files
            deleted: false, // Arq5 nodes don't have this flag directly
            computer_os_type: Some(1), // Assume Mac for Arq5 unless specified otherwise, Arq7 is more explicit

            modification_time_sec: mtime_sec_val,
            modification_time_nsec: mtime_nsec_val,
            change_time_sec: ctime_sec_val,
            change_time_nsec: ctime_nsec_val,
            creation_time_sec: create_time_sec_val,
            creation_time_nsec: create_time_nsec_val,

            st_mode: mode_val as u32,
            st_ino: st_ino_val as u64, // Cast from i32
            st_nlink: st_nlink_val,
            st_gid: gid_val as u32, // Cast from i32
            st_uid: Some(uid_val as u32), // Cast from i32

            username: None, // Arq5 format doesn't store username/groupname in Node
            group_name: None,

            st_dev: st_dev_val,
            st_rdev: st_rdev_val,
            st_flags: flags_val as i32, // Cast from i64 if necessary, though st_flags is usually i32 range

            win_attrs: None, // No Windows specific attributes in Arq5 node format
            reparse_tag: None,
            reparse_point_is_directory: None,

            contained_files_count: None, // Arq5 Node doesn't store this directly; Tree does.

            data_blob_locs: if is_tree { vec![] } else { data_blob_locs_transformed } , // If it's a tree, tree_blob_loc_transformed holds its pointer
            tree_blob_loc: tree_blob_loc_transformed,
            xattrs_blob_locs: xattrs_blob_loc_transformed.map(|loc| vec![loc]), // Arq7 allows multiple, Arq5 implies one
            acl_blob_loc: acl_blob_loc_transformed,

            // Arq5 specific fields
            arq5_tree_contains_missing_items: Some(tree_contains_missing_items),
            arq5_data_compression_type: Some(data_compression_type_arq5),
            arq5_xattrs_compression_type: Some(xattrs_compression_type_arq5),
            arq5_acl_compression_type: Some(acl_compression_type_arq5),
            arq5_xattrs_blob_key: xattrs_blob_key_arq5,
            arq5_xattrs_size: Some(xattrs_size_arq5),
            arq5_acl_blob_key: acl_blob_key_arq5,
            arq5_finder_flags: Some(finder_flags_val),
            arq5_extended_finder_flags: Some(extended_finder_flags_val),
            arq5_finder_file_type: Some(finder_file_type_val),
            arq5_finder_file_creator: Some(finder_file_creator_val),
            arq5_is_file_extension_hidden: Some(is_file_extension_hidden_val),
            arq5_st_blocks: Some(st_blocks_val),
            arq5_st_blksize: Some(st_blksize_val),
        })
    }

    // Methods previously on arq::arq7::Node or new methods for unified node
    /// Loads and parses the tree data associated with this node, if this node represents a tree.
    ///
    /// This method handles both Arq 7 style binary trees and older Arq 5/6 style trees.
    /// It uses `self.tree_blob_loc` (populated by parsers) and `self.arq5_data_compression_type`
    /// as a heuristic to determine the tree format and appropriate parsing method.
    ///
    /// # Arguments
    /// * `backup_set_dir`: The path to the root of the backup set.
    /// * `keyset`: An optional `EncryptedKeySet` for decrypting data if the backup is encrypted.
    ///
    /// # Returns
    /// `Ok(Some(Tree))` if the node is a tree and its data is successfully loaded and parsed.
    /// `Ok(None)` if the node is not a tree, or if the tree data is empty or cannot be found.
    /// `Err` if any error occurs during data loading or parsing.
    pub fn load_tree_with_encryption<P: AsRef<std::path::Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&crate::arq7::EncryptedKeySet>, // Ensure correct path for EncryptedKeySet
    ) -> Result<Option<crate::tree::Tree>> {
        if !self.is_tree {
            return Ok(None);
        }

        if let Some(ref blob_loc) = self.tree_blob_loc {
            // self.tree_blob_loc is populated by both from_binary_reader_arq5 and from_binary_reader_arq7.
            // We need to distinguish the format of the data pointed to by blob_loc.

            // Heuristic: If arq5_data_compression_type is Some, it's an Arq5 tree.
            // The Arq5 node stores the compression type for its *data* (which for a tree node, is the tree blob itself).
            if let Some(compression) = self.arq5_data_compression_type {
                // This indicates an Arq5-style tree.
                // The `blob_loc` (which is self.tree_blob_loc) points to the (potentially) compressed tree data.
                // `BlobLoc::load_data` will handle decryption and its own potential decompression (e.g. if pack entry is LZ4).
                // The result `tree_data_from_blob` should be the data that `Tree::new_arq5` expects (raw, possibly GZipped).
                let tree_data_from_blob = blob_loc.load_data(backup_set_dir.as_ref(), keyset)?;
                if tree_data_from_blob.is_empty() {
                    return Ok(None);
                }
                // `Tree::new_arq5` itself handles the `compression` (e.g. Gzip) indicated by the Arq5 node.
                return crate::tree::Tree::new_arq5(&tree_data_from_blob, compression).map(Some);
            } else {
                // Assume Arq7 style binary tree.
                // `BlobLoc::load_data` handles decryption and its own potential decompression (e.g. LZ4 for the blob/pack entry).
                // The result `tree_data_from_blob` is the data that `Tree::from_arq7_binary_data` expects.
                let tree_data_from_blob = blob_loc.load_data(backup_set_dir.as_ref(), keyset)?;
                if tree_data_from_blob.is_empty() {
                    return Ok(None);
                }
                return crate::tree::Tree::from_arq7_binary_data(&tree_data_from_blob).map(Some);
            }
        }

        // If self.tree_blob_loc is None, but it is_tree, this is an unusual case.
        // It might imply an Arq5 tree where the data_blob_locs were not correctly promoted
        // to tree_blob_loc, or an empty directory that doesn't even have a tree blob.
        // For an empty directory that's correctly represented, tree_blob_loc might be None,
        // and from_arq7_binary_data or new_arq5 should handle empty data if it's a valid state.
        // However, if load_data returned empty above, we already returned Ok(None).
        // If tree_blob_loc is None from the start for a tree node, it implies no actual tree data reference.
        Ok(None)
    }

    /// Reconstructs the complete file data for this node by fetching and concatenating all its data blobs.
    ///
    /// This method should only be called if `self.is_tree` is `false`.
    /// It iterates over `self.data_blob_locs`, loads the data for each `BlobLoc`
    /// (which handles decryption and decompression as specified by the `BlobLoc`),
    /// and then concatenates these chunks.
    ///
    /// # Arguments
    /// * `backup_set_dir`: The path to the root of the backup set.
    /// * `keyset`: An optional `EncryptedKeySet` for decrypting data if the backup is encrypted.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the complete file data.
    /// `Err` if the node is a tree, or if any error occurs during data loading or processing.
    pub fn reconstruct_file_data_with_encryption<P: AsRef<std::path::Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&crate::arq7::EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        if self.is_tree {
            return Err(crate::error::Error::InvalidOperation(
                "Cannot reconstruct file data from a tree node.".to_string(),
            ));
        }

        let mut combined_data = Vec::new();
        let backup_set_dir_ref = backup_set_dir.as_ref();

        for blob_loc in &self.data_blob_locs {
            // BlobLoc::load_data handles decryption and decompression specified by the BlobLoc
            // (e.g. LZ4 from pack, or Gzip for older standalone if BlobLoc.compression_type indicates it).
            // The arq5_data_compression_type on the Node might be redundant if BlobLocs are correctly formed.
            let data_chunk = blob_loc.load_data(backup_set_dir_ref, keyset)?;
            combined_data.extend_from_slice(&data_chunk);
        }
        Ok(combined_data)
    }

    /// Extracts the complete file data for this node and writes it to the specified output path.
    ///
    /// This method calls `reconstruct_file_data_with_encryption` to get the file data
    /// and then writes it to disk. It should only be called if `self.is_tree` is `false`.
    ///
    /// # Arguments
    /// * `backup_set_dir`: The path to the root of the backup set directory.
    /// * `output_path`: The file system path where the extracted file should be written.
    /// * `keyset`: An optional `EncryptedKeySet` for decrypting data if the backup is encrypted.
    ///
    /// # Returns
    /// `Ok(())` if the file is successfully extracted and written.
    /// `Err` if the node is a tree, if any error occurs during data reconstruction, or if there's an IO error writing the file.
    pub fn extract_file_with_encryption<P1: AsRef<std::path::Path>, P2: AsRef<std::path::Path>>(
        &self,
        backup_set_dir: P1,
        output_path: P2,
        keyset: Option<&crate::arq7::EncryptedKeySet>,
    ) -> Result<()> {
        if self.is_tree {
            return Err(crate::error::Error::InvalidOperation(
                "Cannot extract directory as a file.".to_string(),
            ));
        }
        let file_data = self.reconstruct_file_data_with_encryption(backup_set_dir.as_ref(), keyset)?;
        std::fs::write(output_path.as_ref(), file_data)
            .map_err(|e| crate::error::Error::IoError(e))?; // Map std::io::Error to crate::error::Error
        Ok(())
    }
}
