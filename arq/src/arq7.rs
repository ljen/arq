//! Arq 7 data format support
//!
//! This module provides comprehensive support for the Arq 7 backup format, which uses JSON
//! configuration files and a different directory structure compared to earlier versions.
//!
//! ## Features Implemented
//!
//! ### ✅ JSON Configuration Parsing
//! - `BackupConfig` - Parse backupconfig.json files
//! - `BackupFolders` - Parse backupfolders.json files
//! - `BackupPlan` - Parse backupplan.json files
//! - `BackupFolder` - Parse individual folder configurations
//! - `BackupRecord` - Parse LZ4-compressed JSON backup records
//!
//! ### ✅ Complete Backup Set Loading
//! - `BackupSet::from_directory()` - Load entire backup set from directory
//! - Automatic discovery and loading of all JSON configuration files
//! - Recursive loading of backup records from all folders
//! - Error handling with graceful degradation
//!
//! ### 🔄 Binary Format Support
//! - The `arq::arq7::binary` module provides `ArqBinaryReader` for low-level binary parsing.
//! - Arq 7 binary nodes are parsed into the unified `crate::node::Node` using `crate::node::Node::from_binary_reader_arq7`.
//! - Arq 7 binary trees are parsed into the unified `crate::tree::Tree` using `crate::tree::Tree::from_arq7_binary_data`.
//! - `BlobLoc` (now `crate::blob_location::BlobLoc`) is used for referencing data in pack files or standalone objects,
//!   with support for LZ4 decompression where applicable.
//!
//! ## Usage Examples
//!
//! ### Loading a complete backup set:
//! ```rust,no_run
//! use arq::arq7::BackupSet;
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let backup_set = BackupSet::from_directory("/path/to/backup/set")?;
//!     println!("Backup name: {}", backup_set.backup_config.backup_name);
//!
//!     // Access backup records
//!     for (folder_uuid, records) in &backup_set.backup_records {
//!         println!("Folder {}: {} records", folder_uuid, records.len());
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### Loading individual components:
//! ```rust,no_run
//! use arq::arq7::{BackupConfig, BackupPlan};
//! use std::error::Error;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     let config = BackupConfig::from_file("backupconfig.json")?;
//!     let plan = BackupPlan::from_file("backupplan.json")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Arq 7 Directory Structure
//!
//! ```text
//! backup_set_directory/
//! +-- backupconfig.json          # Backup configuration
//! +-- backupfolders.json         # Object directory locations
//! +-- backupplan.json            # Backup plan settings
//! +-- backupfolders/             # Per-folder configurations
//! |   L-- <folder-uuid>/
//! |       +-- backupfolder.json  # Folder metadata
//! |       L-- backuprecords/     # Backup records by timestamp
//! |           L-- <timestamp>/
//! |               L-- *.backuprecord  # LZ4-compressed JSON records
//! +-- blobpacks/                 # Packed blob data
//! +-- treepacks/                 # Packed tree data
//! L-- standardobjects/           # Standalone objects
//! ```
//!
//! ## Data Format Notes
//!
//! - JSON files use exact field names (not camelCase transformed)
//! - Backup records are LZ4-compressed JSON with 4-byte big-endian length prefix
//! - Binary pack files contain multiple objects at specific offsets
//! - All timestamps are Unix epoch seconds
//! - UUIDs are used extensively for identifying backup plans, folders, and objects

pub mod backup_config;
pub mod backup_folder;
pub mod backup_folders;
pub mod backup_plan;
pub mod backup_record;
pub mod backup_set;
pub mod binary;
pub mod blob_loc;
pub mod encrypted_keyset;
pub mod node;
pub mod utils;
pub mod virtual_fs;

pub use backup_config::BackupConfig;
pub use backup_folder::BackupFolder;
pub use backup_folders::BackupFolders;
pub use backup_plan::{
    BackupFolderPlan, BackupPlan, EmailReport, ExcludedDrive, ExcludedDriveEntry, Schedule,
    TransferRate,
};
pub use backup_record::{
    Arq5BackupRecord, Arq7BackupRecord, BackupRecordError, GenericBackupRecord,
};
pub use backup_set::{BackupSet, BackupStatistics, IntegrityReport};
pub use blob_loc::BlobLoc;
pub use encrypted_keyset::EncryptedKeySet;
pub use node::Node;
pub use virtual_fs::{DirectoryEntry, DirectoryEntryNode, FileEntry};
