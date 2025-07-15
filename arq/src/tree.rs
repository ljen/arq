//! Commits, Trees and Nodes
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
use std;
use std::collections::HashMap;
use std::io::BufReader;

use byteorder::ReadBytesExt;

use crate::arq7::binary::ArqBinaryReader;
use crate::blob;
use crate::compression::CompressionType;
use crate::error::Result;
use crate::type_utils::ArqRead;

/// Tree
///
/// A tree contains the following bytes:
///
/// ```ascii
///     [Bool:isTree]
///     [Bool:treeContainsMissingItems] /* present for Tree version >= 18 */
///     [Bool:data_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:data_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:xattrs_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:xattrs_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:acl_is_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:acl_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Int32:data_blob_keys_count]
///     (
///         [BlobKey:data_blob_key]
///     )   /* repeat <data_blob_keys_count> times */
///     [UIn64:data_size]
///     [String:"<thumbnail sha1>"] /* only present for Tree version 18 or earlier (never used) */
///     [Bool:is_thumbnail_encryption_key_stretched] /* only present for Tree version 14 to 18 */
///     [String:"<preview sha1>"] /* only present for Tree version 18 or earlier (never used) */
///     [Bool:is_preview_encryption_key_stretched] /* only present for Tree version 14 to 18 */
///     [BlobKey:xattrs_blob_key] /* null if file has no xattrs */
///     [UInt64:xattrs_size]
///     [BlobKey:acl_blob_key] /* null if file has no acl */
///     [Int32:uid]
///     [Int32:gid]
///     [Int32:mode]
///     [Int64:mtime_sec]
///     [Int64:mtime_nsec]
///     [Int64:flags]
///     [Int32:finderFlags]
///     [Int32:extendedFinderFlags]
///     [String:"<finder file type>"]
///     [String:"<finder file creator>"]
///     [Bool:is_file_extension_hidden]
///     [Int32:st_dev]
///     [Int32:st_ino]
///     [UInt32:st_nlink]
///     [Int32:st_rdev]
///     [Int64:ctime_sec]
///     [Int64:ctime_nsec]
///     [Int64:create_time_sec]
///     [Int64:create_time_nsec]
///     [Int64:st_blocks]
///     [UInt32:st_blksize]
/// ```
///
/// Notes:
///
/// - A Node can have multiple data SHA1s if the file is very large. Arq breaks up large
///   files into multiple blobs using a rolling checksum algorithm. This way Arq only
///   backs up the parts of a file that have changed.
///
/// - "<xattrs_blob_key>" is the key of a blob containing the sorted extended attributes
///   of the file (see "XAttrSet Format" below). Note this means extended-attribute sets
///   are "de-duplicated".
///
/// - "<acl_blob_key>" is the SHA1 of the blob containing the result of acl_to_text() on
/// the file's ACL. Note this means the ACLs are "de-duplicated".
///
/// - "create_time_sec" and "create_time_nsec" contain the value of the ATTR_CMN_CRTIME
/// attribute of the file
///
///
/// XAttrSet Format
/// ---------------
///
/// Each XAttrSet blob contains the following bytes:
///
/// ```ascii
///     58 41 74 74 72 53 65 74  56 30 30 32    "XAttrSetV002"
///     [UInt64:xattr_count]
///     (
///         [String:"<xattr name>"] /* can't be null */
///         [Data:xattr_data]
///     )
/// ```
pub struct Node {
    pub is_tree: bool,
    pub tree_contains_missing_items: bool,
    pub data_compression_type: CompressionType,
    pub xattrs_compression_type: CompressionType,
    pub acl_compression_type: CompressionType,
    pub data_blob_keys: Vec<blob::BlobKey>,
    pub data_size: u64,
    pub xattrs_blob_key: Option<blob::BlobKey>,
    pub xattrs_size: u64,
    pub acl_blob_key: Option<blob::BlobKey>,
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub finder_file_type: String,
    pub finder_file_creator: String,
    pub is_file_extension_hidden: bool,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
}

// The old arq::tree::Node struct and its impl Node::new have been removed.
// The unified node is now crate::node::Node.
// The parsing logic from the old Node::new is incorporated into
// crate::node::Node::from_binary_reader_arq5.

/// Tree
///
/// A tree contains the following bytes:
///
/// ```ascii
///     54 72 65 65 56 30 32 32             "TreeV022"
///     [Bool:xattrs_are_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:xattrs_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Bool:acl_is_compressed] /* present for Tree versions 12-18 */
///     [CompressionType:acl_compression_type] /* present for Tree version >= 19; indicates Gzip compression or none */
///     [Int32:xattrs_compression_type] /* present for Tree version >= 20; older Trees are gzip compression type */
///     [Int32:acl_compression_type] /* present for Tree version >= 20; older Trees are gzip compression type */
///     [BlobKey:xattrs_blob_key] /* null if directory has no xattrs */
///     [UInt64:xattrs_size]
///     [BlobKey:acl_blob_key] /* null if directory has no acl */
///     [Int32:uid]
///     [Int32:gid]
///     [Int32:mode]
///     [Int64:mtime_sec]
///     [Int64:mtime_nsec]
///     [Int64:flags]
///     [Int32:finderFlags]
///     [Int32:extendedFinderFlags]
///     [Int32:st_dev]
///     [Int32:st_ino]
///     [UInt32:st_nlink]
///     [Int32:st_rdev]
///     [Int64:ctime_sec]
///     [Int64:ctime_nsec]
///     [Int64:st_blocks]
///     [UInt32:st_blksize]
///     [UInt64:aggregate_size_on_disk] /* only present for Tree version 11 to 16 (never used) */
///     [Int64:create_time_sec] /* only present for Tree version 15 or later */
///     [Int64:create_time_nsec] /* only present for Tree version 15 or later */
///     [UInt32:missing_node_count] /* only present for Tree version 18 or later */
///     (
///         [String:"<missing_node_name>"] /* only present for Tree version 18 or later */
///     )   /* repeat <missing_node_count> times */
///     [UInt32:node_count]
///     (
///         [String:"<file name>"] /* can't be null */
///         [Node]
///     )   /* repeat <node_count> times */
/// ```
///
/// This struct represents a parsed tree, containing metadata about the directory itself
/// (if applicable, primarily for Arq5 format trees) and a map of child nodes.
/// The `nodes` field uses the unified `crate::node::Node` struct.
///
/// The `version` field's meaning depends on the source format:
/// - For Arq5 format trees (parsed by `new_arq5`): It's the "TreeV0XX" version from the header (e.g., 22).
/// - For Arq7 binary trees (parsed by `from_arq7_binary_data`): It's the internal version of the Arq7 binary tree structure (e.g., 3).
pub struct Tree {
    // Arq5 specific Tree metadata - these are set to defaults when parsing Arq7 binary trees
    // as Arq7 binary trees don't have this header; metadata is per-node.
    pub xattrs_compression_type: CompressionType,
    pub acl_compression_type: CompressionType,
    pub xattrs_blob_key: Option<blob::BlobKey>,
    pub xattrs_size: u64,
    pub acl_blob_key: Option<blob::BlobKey>,
    pub uid: i32,
    pub gid: i32,
    pub mode: i32,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub flags: i64,
    pub finder_flags: i32,
    pub extended_finder_flags: i32,
    pub st_dev: i32,
    pub st_ino: i32,
    pub st_nlink: u32,
    pub st_rdev: i32,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub create_time_sec: i64,
    pub create_time_nsec: i64,
    pub st_blocks: i64,
    pub st_blksize: u32,
    /// For Arq5 format: The version number from the "TreeV0XX" header (e.g., 22).
    /// For Arq7 binary format: The internal version of the Arq7 binary tree structure (e.g., 3).
    pub version: u32,
    pub missing_nodes: Vec<String>, // For Arq5 Tree format
    pub nodes: HashMap<String, crate::node::Node>, // Unified Node
}

impl Tree {
    /// Parses a legacy Arq 5/6 format tree from decompressed binary data.
    ///
    /// The binary data is expected to start with the "TreeV0XX" header.
    /// Child nodes are parsed using `crate::node::Node::from_binary_reader_arq5`.
    ///
    /// # Arguments
    /// * `compressed_content`: The raw, potentially compressed byte slice of the tree data blob.
    /// * `compression_type`: The `CompressionType` (e.g., Gzip) used on `compressed_content`.
    ///                       Note that individual nodes within the tree might have their own
    ///                       compression settings for their attributes (xattrs, ACLs).
    ///
    /// # Example
    /// ```ignore
    /// // Assuming tree_bytes is Vec<u8> read from an Arq5 tree blob & commit specifies Gzip
    /// let tree = arq::tree::Tree::new_arq5(&tree_bytes, arq::compression::CompressionType::Gzip).unwrap();
    /// assert_eq!(tree.version, 22); // Example, actual version depends on input data
    /// ```
    pub fn new_arq5(compressed_content: &[u8], compression_type: CompressionType) -> Result<Tree> {
        let content = CompressionType::decompress(compressed_content, compression_type)?;
        let mut reader = BufReader::new(std::io::Cursor::new(content));
        let tree_header = reader.read_bytes(8)?; // Reads "TreeV0XX" - ArqRead::read_bytes is unambiguous
        if &tree_header[..5] != b"TreeV" {
            return Err(crate::error::Error::InvalidFormat(
                "Invalid Arq5 tree header".to_string(),
            ));
        }
        let version = std::str::from_utf8(&tree_header[5..])?.parse::<u32>()?;

        // These fields are specific to the Tree object itself in Arq5 format
        let xattrs_compression_type = reader.read_arq_compression_type()?;
        let acl_compression_type = reader.read_arq_compression_type()?;
        let xattrs_blob_key = blob::BlobKey::new(&mut reader)?;
        let xattrs_size = ArqBinaryReader::read_arq_u64(&mut reader)?;
        let acl_blob_key = blob::BlobKey::new(&mut reader)?;
        let uid = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let gid = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let mode = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let mtime_sec = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let mtime_nsec = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let flags = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let finder_flags = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let extended_finder_flags = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let st_dev = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let st_ino = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let st_nlink = ArqBinaryReader::read_arq_u32(&mut reader)?;
        let st_rdev = ArqBinaryReader::read_arq_i32(&mut reader)?;
        let ctime_sec = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let ctime_nsec = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let st_blocks = ArqBinaryReader::read_arq_i64(&mut reader)?;
        let st_blksize = ArqBinaryReader::read_arq_u32(&mut reader)?;

        let create_time_sec = if version >= 15 {
            ArqBinaryReader::read_arq_i64(&mut reader)?
        } else {
            mtime_sec
        }; // Fallback for older trees
        let create_time_nsec = if version >= 15 {
            ArqBinaryReader::read_arq_i64(&mut reader)?
        } else {
            mtime_nsec
        };

        let mut missing_node_count = if version >= 18 {
            ArqBinaryReader::read_arq_u32(&mut reader)?
        } else {
            0
        };
        let mut missing_nodes = Vec::new();
        while missing_node_count > 0 {
            if let Some(missing_node_name) = ArqBinaryReader::read_arq_string(&mut reader)? {
                missing_nodes.push(missing_node_name);
            } else {
                // Or handle error: return Err(crate::error::Error::InvalidFormat("Missing node name was null".to_string()));
                // For now, pushing an empty string if it's None, though Arq spec might imply it's always Some(String)
                missing_nodes.push(String::new());
            }
            missing_node_count -= 1;
        }

        let mut node_count = ArqBinaryReader::read_arq_u32(&mut reader)?;
        let mut nodes = HashMap::new();
        while node_count > 0 {
            let node_name = match ArqBinaryReader::read_arq_string(&mut reader)? {
                Some(name) if !name.is_empty() => name,
                Some(_) => {
                    // Name is Some("")
                    // Arq documentation states file name can't be null, but handle defensively
                    return Err(crate::error::Error::InvalidFormat(
                        "Empty node name in Arq5 tree".to_string(),
                    ));
                }
                None => {
                    // Name is None
                    // Arq documentation states file name can't be null
                    return Err(crate::error::Error::InvalidFormat(
                        "Null node name in Arq5 tree".to_string(),
                    ));
                }
            };
            // Pass the tree's version to the node parser, as some node fields are version-dependent
            let node = crate::node::Node::from_binary_reader_arq5(&mut reader, version)?;
            nodes.insert(node_name, node);
            node_count -= 1;
        }

        Ok(Tree {
            version,
            xattrs_compression_type,
            acl_compression_type,
            xattrs_blob_key,
            xattrs_size,
            acl_blob_key,
            uid,
            gid,
            mode,
            mtime_sec,
            mtime_nsec,
            flags,
            finder_flags,
            extended_finder_flags,
            st_dev,
            st_ino,
            st_nlink,
            st_rdev,
            ctime_sec,
            ctime_nsec,
            st_blocks,
            st_blksize,
            create_time_sec,
            create_time_nsec,
            missing_nodes,
            nodes,
        })
    }

    /// Parses an Arq7 format tree from decompressed binary data.
    ///
    /// Arq 7 uses a different binary format for trees compared to older versions. This format
    /// typically does not have the extensive header metadata found in Arq 5/6 trees; such metadata
    /// is usually per-node in Arq 7. The binary data for an Arq 7 tree starts directly with
    /// its own version number, followed by the count and data of child nodes.
    /// Child nodes are parsed using `crate::node::Node::from_binary_reader_arq7`.
    ///
    /// When a `Tree` struct is created using this method, its top-level metadata fields
    /// (like `uid`, `gid`, `mode`, `xattrs_blob_key`, etc., which are from the Arq5 tree header)
    /// will be set to default values as they are not present in the Arq7 binary tree stream itself.
    /// The `version` field of the `Tree` struct will store the Arq7 binary tree's internal version.
    ///
    /// # Arguments
    /// * `data`: A byte slice containing the decompressed binary data of an Arq 7 tree.
    ///           This data is typically obtained by loading a `BlobLoc` (often `treeBlobLoc` from a `Node`)
    ///           which itself handles any outer compression like LZ4 used for pack files.
    pub fn from_arq7_binary_data(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        // The Arq7 binary tree format starts with its own version, then childNodesByNameCount, then nodes.
        // It does not have the same extensive header as the Arq5 tree.

        let version = cursor.read_u32::<byteorder::BigEndian>()?; // Arq7 BinaryTree version - from ReadBytesExt, unambiguous
        let child_nodes_count = cursor.read_u64::<byteorder::BigEndian>()?; // from ReadBytesExt, unambiguous
        let mut child_nodes_map = HashMap::new();

        for i in 0..child_nodes_count {
            let child_name_opt = ArqBinaryReader::read_arq_string(&mut cursor)?; // Disambiguated to ArqBinaryReader
            let name = match child_name_opt {
                Some(name) if !name.is_empty() => name,
                Some(_) => format!("empty_child_name_{}", i), // Handle Some("") case
                None => format!("unnamed_child_{}", i),       // Handle None case
            };
            // Use the unified Node's Arq7 binary parser
            // The `tree_version` here is the version of the BinaryTree structure itself.
            let node = crate::node::Node::from_binary_reader_arq7(&mut cursor, Some(version))?;
            child_nodes_map.insert(name, node);
        }

        // Arq7 BinaryTree doesn't have the same metadata fields directly within it
        // as Arq5 Tree (uid, gid, mode, timestamps, etc. are per-node).
        // So, for a Tree object created from Arq7 binary data, these top-level
        // metadata fields in the Tree struct will be defaults or indicate they aren't from Arq5.
        Ok(Tree {
            version, // This is the Arq7 BinaryTree version, not Arq5 TreeV0XX version
            xattrs_compression_type: CompressionType::None, // Default, not in Arq7 BinaryTree header
            acl_compression_type: CompressionType::None,    // Default
            xattrs_blob_key: None,                          // Default
            xattrs_size: 0,                                 // Default
            acl_blob_key: None,                             // Default
            uid: 0,                                         // Default
            gid: 0,                                         // Default
            mode: 0,                                        // Default
            mtime_sec: 0,                                   // Default
            mtime_nsec: 0,                                  // Default
            flags: 0,                                       // Default
            finder_flags: 0,                                // Default
            extended_finder_flags: 0,                       // Default
            st_dev: 0,                                      // Default
            st_ino: 0,                                      // Default
            st_nlink: 0,                                    // Default
            st_rdev: 0,                                     // Default
            ctime_sec: 0,                                   // Default
            ctime_nsec: 0,                                  // Default
            create_time_sec: 0,                             // Default
            create_time_nsec: 0,                            // Default
            st_blocks: 0,                                   // Default
            st_blksize: 0,                                  // Default
            missing_nodes: Vec::new(), // Default (specific to Arq5 tree parsing)
            nodes: child_nodes_map,
        })
    }
}
