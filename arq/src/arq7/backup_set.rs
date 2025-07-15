use super::backup_config::BackupConfig;
use super::backup_folder::BackupFolder;
use super::backup_folders::BackupFolders;
use super::backup_plan::BackupPlan;
use super::backup_record::GenericBackupRecord;
use super::encrypted_keyset::EncryptedKeySet;
use super::virtual_fs::{DirectoryEntry, DirectoryEntryNode, FileEntry};
use crate::error::{Error, Result};
use chrono::DateTime;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// BackupSet represents an entire Arq 7 backup set
#[derive(Debug, Clone)]
pub struct BackupSet {
    pub backup_config: BackupConfig,
    pub backup_folders: BackupFolders,
    pub backup_plan: BackupPlan,
    pub backup_folder_configs: HashMap<String, BackupFolder>,
    pub backup_records: HashMap<String, Vec<GenericBackupRecord>>, // Changed to GenericBackupRecord
    pub encryption_keyset: Option<EncryptedKeySet>,
    pub root_path: PathBuf,
}

#[derive(Debug, Default)]
pub struct BackupStatistics {
    pub folder_count: u32,
    pub record_count: u32,
    pub total_files: u32,
    pub total_size: u64,
    pub complete_backups: u32,
}

#[derive(Debug, Default)]
pub struct IntegrityReport {
    pub total_blobs: u32,
    pub valid_blobs: u32,
    pub invalid_blobs: u32,
    pub total_blob_size: u64,
    pub treepacks_exist: bool,
    pub blobpacks_exist: bool,
}

impl BackupSet {
    /// Load a complete BackupSet from a directory path
    pub fn from_directory<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let root_path = PathBuf::from(path.as_ref());
        let path = path.as_ref();

        // Load main configuration files
        let backup_config = BackupConfig::from_file(path.join("backupconfig.json"))?;
        let backup_folders = BackupFolders::from_file(path.join("backupfolders.json"))?;
        let backup_plan = BackupPlan::from_file(path.join("backupplan.json"))?;

        // Load backup folder configurations
        let mut backup_folder_configs = HashMap::new();
        let mut backup_records = HashMap::new();
        let backupfolders_dir = path.join("backupfolders");

        if backupfolders_dir.exists() {
            for entry in std::fs::read_dir(backupfolders_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let folder_uuid = entry.file_name().to_string_lossy().to_string();
                    let config_path = entry.path().join("backupfolder.json");

                    if config_path.exists() {
                        let backup_folder = BackupFolder::from_file(config_path)?;
                        backup_folder_configs.insert(folder_uuid.clone(), backup_folder);
                    }

                    // Load backup records for this folder
                    let records_dir = entry.path().join("backuprecords");
                    if records_dir.exists() {
                        let mut folder_records = Vec::new();
                        Self::load_backup_records_recursive(&records_dir, &mut folder_records)?;
                        if !folder_records.is_empty() {
                            backup_records.insert(folder_uuid, folder_records);
                        }
                    }
                }
            }
        }

        Ok(BackupSet {
            backup_config,
            backup_folders,
            backup_plan,
            backup_folder_configs,
            backup_records,
            encryption_keyset: None,
            root_path,
        })
    }

    /// Add method to load with explicit password
    pub fn from_directory_with_password<P: AsRef<Path>>(
        dir_path: P,
        password: Option<&str>,
    ) -> Result<BackupSet> {
        let root_path = PathBuf::from(dir_path.as_ref());
        let dir_path = dir_path.as_ref();

        // Load backup config first to check if encrypted
        let config_path = dir_path.join("backupconfig.json");
        let backup_config = BackupConfig::from_file(&config_path)?;

        // Load encryption keyset if this is an encrypted backup
        let encryption_keyset = if backup_config.is_encrypted {
            let keyset_path = dir_path.join("encryptedkeyset.dat");
            if keyset_path.exists() {
                match password {
                    Some(pwd) => Some(EncryptedKeySet::from_file(&keyset_path, pwd)?),
                    None => {
                        return Err(Error::InvalidFormat(
                            "Encrypted backup requires password".to_string(),
                        ))
                    }
                }
            } else {
                return Err(Error::InvalidFormat(
                    "Encrypted backup missing encryptedkeyset.dat".to_string(),
                ));
            }
        } else {
            None
        };

        // Load other components with encryption support
        let folders_path = dir_path.join("backupfolders.json");
        let backup_folders =
            BackupFolders::from_file_with_encryption(&folders_path, encryption_keyset.as_ref())?;

        let plan_path = dir_path.join("backupplan.json");
        let backup_plan =
            BackupPlan::from_file_with_encryption(&plan_path, encryption_keyset.as_ref())?;

        // Load backup folder configs
        let mut backup_folder_configs = HashMap::new();
        let backupfolders_dir = dir_path.join("backupfolders");
        if backupfolders_dir.exists() {
            for entry in std::fs::read_dir(&backupfolders_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let folder_uuid = entry.file_name().to_string_lossy().to_string();
                    let config_path = entry.path().join("backupfolder.json");
                    if config_path.exists() {
                        match BackupFolder::from_file_with_encryption(
                            &config_path,
                            encryption_keyset.as_ref(),
                        ) {
                            Ok(folder_config) => {
                                backup_folder_configs.insert(folder_uuid.clone(), folder_config);
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: Failed to load folder config for {}: {}",
                                    folder_uuid, e
                                );
                            }
                        }
                    }
                }
            }
        }

        // Load backup records
        let backup_records = Self::load_backup_records_with_encryption(
            &backupfolders_dir,
            encryption_keyset.as_ref(),
        )?;

        Ok(BackupSet {
            backup_config,
            backup_folders,
            backup_plan,
            backup_folder_configs,
            backup_records,
            encryption_keyset,
            root_path,
        })
    }

    /// Get a reference to the encryption keyset if available
    pub fn encryption_keyset(&self) -> Option<&EncryptedKeySet> {
        self.encryption_keyset.as_ref()
    }

    /// Check if this backup set is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.backup_config.is_encrypted
    }

    /// Recursively load backup record files from a directory
    fn load_backup_records_recursive(
        dir: &std::path::Path,
        records: &mut Vec<GenericBackupRecord>, // Changed to GenericBackupRecord
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if entry.file_type()?.is_dir() {
                // Recursively search subdirectories
                Self::load_backup_records_recursive(&path, records)?;
            } else if path.extension().and_then(|s| s.to_str()) == Some("backuprecord") {
                // Try to parse backup record file
                match GenericBackupRecord::from_file(&path) {
                    // Changed to GenericBackupRecord
                    Ok(record) => records.push(record),
                    Err(e) => {
                        // Log error but continue processing other files
                        eprintln!("Warning: Failed to parse backup record {:?}: {}", path, e);
                    }
                }
            }
        }
        Ok(())
    }

    fn load_backup_records_with_encryption(
        backupfolders_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<HashMap<String, Vec<GenericBackupRecord>>> {
        // Changed to GenericBackupRecord
        let mut backup_records = HashMap::new();

        if !backupfolders_dir.exists() {
            return Ok(backup_records);
        }

        for entry in std::fs::read_dir(backupfolders_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let folder_uuid = entry.file_name().to_string_lossy().to_string();
                let records_dir = entry.path().join("backuprecords");

                if records_dir.exists() {
                    let mut folder_records = Vec::new();

                    // Recursively traverse backup records directories
                    fn collect_records(
                        dir: &Path,
                        records: &mut Vec<GenericBackupRecord>, // Changed to GenericBackupRecord
                        keyset: Option<&EncryptedKeySet>,
                    ) -> Result<()> {
                        for entry in std::fs::read_dir(dir)? {
                            let entry = entry?;
                            let path = entry.path();

                            if path.is_dir() {
                                collect_records(&path, records, keyset)?;
                            } else if path.extension().map_or(false, |ext| ext == "backuprecord") {
                                match GenericBackupRecord::from_file_with_encryption(&path, keyset)
                                {
                                    // Changed to GenericBackupRecord
                                    Ok(record) => records.push(record),
                                    Err(e) => {
                                        println!(
                                            "Warning: Failed to load backup record {:?}: {}",
                                            path, e
                                        );
                                    }
                                }
                            }
                        }
                        Ok(())
                    }

                    if let Err(e) = collect_records(&records_dir, &mut folder_records, keyset) {
                        println!(
                            "Warning: Failed to load backup records for folder {}: {}",
                            folder_uuid, e
                        );
                    }

                    if !folder_records.is_empty() {
                        backup_records.insert(folder_uuid, folder_records);
                    }
                }
            }
        }

        Ok(backup_records)
    }

    /// Extract a file from the backup set with full encryption support
    pub fn extract_file_by_path<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        backup_set_dir: P1,
        file_path: &str,
        output_path: P2,
    ) -> Result<()> {
        // Find the file in the backup records
        for (_, records) in &self.backup_records {
            for generic_record in records {
                if let GenericBackupRecord::Arq7(record) = generic_record {
                    // Only Arq7 records have a direct node
                    if let Some(node) = self.find_node_by_path(&record.node, file_path)? {
                        if !node.is_tree {
                            return node.extract_file_with_encryption(
                                backup_set_dir.as_ref(),
                                output_path,
                                self.encryption_keyset.as_ref(),
                            );
                        }
                    }
                }
            }
        }

        Err(Error::InvalidFormat(format!(
            "File not found or not extractable from Arq7 records: {}", // Clarified error
            file_path
        )))
    }

    /// Recursively find a node by path (operates on a given Node, typically from an Arq7 record)
    fn find_node_by_path(
        &self,
        node: &crate::node::Node, // This function is now more general, called with a specific node
        target_path: &str,
    ) -> Result<Option<crate::node::Node>> {
        let path_parts: Vec<&str> = target_path.trim_start_matches('/').split('/').collect();
        self.find_node_recursive(node, &path_parts, 0)
    }

    // find_node_recursive remains largely the same as it operates on a Node,
    // but its callers need to ensure they provide a valid Node.
    fn find_node_recursive(
        &self,
        node: &crate::node::Node,
        path_parts: &[&str],
        depth: usize,
    ) -> Result<Option<crate::node::Node>> {
        let backup_set_dir_ref: &Path = self.root_path.as_ref();

        if depth >= path_parts.len() {
            return Ok(Some(node.clone()));
        }

        if !node.is_tree {
            return Ok(None);
        }
        // TODO: This method needs to be implemented on crate::node::Node
        // For now, assume it returns Ok(None) to allow compilation.
        // This will affect functionality until `crate::node::Node::load_tree_with_encryption` is implemented.
        // if let Some(tree) =
        //     node.load_tree_with_encryption(backup_set_dir_ref, self.encryption_keyset.as_ref())?
        // {
        //     let target_name = path_parts[depth];
        //     if let Some(child_node) = tree.child_nodes.get(target_name) {
        //         return self.find_node_recursive(child_node, path_parts, depth + 1);
        //     }
        // }
        // Use the Node's own method now
        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir_ref, self.encryption_keyset.as_ref())?
        {
            let target_name = path_parts[depth];
            // The unified Tree uses `nodes` for its HashMap
            if let Some(child_node_entry) = tree.nodes.get(target_name) {
                return self.find_node_recursive(child_node_entry, path_parts, depth + 1);
            }
        }
        Ok(None)
    }

    /// List all files in the backup set (primarily from Arq7 records)
    pub fn list_all_files(&self) -> Result<Vec<String>> {
        let mut files = Vec::new();
        let backup_set_dir_ref = self.root_path.as_ref();

        for (_, records) in &self.backup_records {
            for generic_record in records {
                if let GenericBackupRecord::Arq7(record) = generic_record {
                    self.collect_files_recursive(
                        &record.node, // This is now crate::node::Node
                        String::new(),
                        &mut files,
                        backup_set_dir_ref,
                    )?;
                }
                // Arq5 records do not have a top-level node in this structure for listing files directly.
            }
        }
        Ok(files)
    }

    // collect_files_recursive remains largely the same.
    fn collect_files_recursive(
        &self,
        node: &crate::node::Node, // Changed to crate::node::Node
        current_path: String,
        files: &mut Vec<String>,
        backup_set_dir: &Path,
    ) -> Result<()> {
        if !node.is_tree {
            if !current_path.is_empty() {
                files.push(current_path);
            }
            return Ok(());
        }

        // TODO: This method needs to be implemented on crate::node::Node
        // For now, assume it returns Ok(None) to allow compilation.
        // This will affect functionality until `crate::node::Node::load_tree_with_encryption` is implemented.
        // if let Some(tree) =
        //     node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        // {
        //     for (name, child_node) in &tree.child_nodes {
        //         let child_path = if current_path.is_empty() {
        //             name.clone()
        //         } else {
        //             format!("{}/{}", current_path, name)
        //         };
        //         self.collect_files_recursive(child_node, child_path, files, backup_set_dir)?;
        //     }
        // }
        if let Some(tree) =
            node.load_tree_with_encryption(backup_set_dir, self.encryption_keyset.as_ref())?
        {
            for (name, child_node_entry) in &tree.nodes {
                // Use tree.nodes
                let child_path = if current_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", current_path, name)
                };
                self.collect_files_recursive(child_node_entry, child_path, files, backup_set_dir)?;
            }
        }
        Ok(())
    }

    /// Get backup statistics
    pub fn get_statistics(&self) -> Result<BackupStatistics> {
        let mut stats: BackupStatistics = BackupStatistics::default();
        let backup_set_dir_ref = self.root_path.as_ref();

        for (_, records_vec) in &self.backup_records {
            // Renamed records to records_vec to avoid conflict
            stats.folder_count += 1; // This counts folders in backup_records map, not file system folders.
            stats.record_count += records_vec.len() as u32;

            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        let (file_count, total_size) = count_files_in_node(
                            &record.node, // This is now crate::node::Node
                            backup_set_dir_ref,
                            self.encryption_keyset.as_ref(),
                        )?;
                        stats.total_files += file_count;
                        stats.total_size += total_size;
                        if record.is_complete.unwrap_or(false) {
                            stats.complete_backups += 1;
                        }
                    }
                    GenericBackupRecord::Arq5(record) => {
                        // Arq5 records don't have a direct node for file counting here.
                        // We could potentially sum itemSize if arq5TreeBlobKey implies a single item,
                        // but that's an assumption. For now, only count if complete.
                        if record.is_complete.unwrap_or(false) {
                            stats.complete_backups += 1;
                        }
                        // total_files and total_size for Arq5 might need different logic
                        // based on arq5TreeBlobKey or other fields if applicable.
                    }
                }
            }
        }
        Ok(stats)
    }

    /// Verify backup integrity by checking all blob locations
    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport::default();
        let backup_set_dir_ref: &Path = self.root_path.as_ref();

        // let backup_set_dir_ref2: &Path = self.root_path.as_ref();

        let blob_locations = self.find_all_blob_locations(); // This method needs adjustment
        report.total_blobs = blob_locations.len() as u32;

        for blob_loc in blob_locations {
            match blob_loc.load_data(backup_set_dir_ref, self.encryption_keyset.as_ref()) {
                Ok(data) => {
                    report.valid_blobs += 1;
                    report.total_blob_size += data.len() as u64;
                }
                Err(e) => {
                    report.invalid_blobs += 1;
                    eprintln!(
                        "Warning: Failed to load blob {}: {}",
                        blob_loc.blob_identifier, e
                    );
                }
            }
        }

        // Check pack files exist
        let treepacks_dir = backup_set_dir_ref.join("treepacks"); // Used backup_set_dir_ref
        let blobpacks_dir = backup_set_dir_ref.join("blobpacks"); // Used backup_set_dir_ref

        report.treepacks_exist = treepacks_dir.exists();
        report.blobpacks_exist = blobpacks_dir.exists();

        Ok(report)
    }

    /// Converts a Node into a DirectoryEntry (File or Directory).
    fn node_to_directory_entry(
        &self,
        node: &crate::node::Node,
        name: String,
    ) -> Result<DirectoryEntry> {
        if node.is_tree {
            // For directories, create a DirectoryEntryNode without loading children.
            // Children will be loaded on demand.
            Ok(DirectoryEntry::Directory(DirectoryEntryNode {
                name,
                children: None, // Children are not loaded initially
                tree_blob_loc: node.tree_blob_loc.as_ref().map(|loc| loc.clone().into()), // Convert to blob_location::BlobLoc
                modification_time_sec: node.modification_time_sec,
                creation_time_sec: node.creation_time_sec,
                mode: node.st_mode, // Using st_mode from crate::node::Node
            }))
        } else {
            // For files, create a FileEntry with all necessary details for later content loading.
            Ok(DirectoryEntry::File(FileEntry {
                name,
                size: node.item_size,
                data_blob_locs: node
                    .data_blob_locs
                    .iter()
                    .map(|loc| loc.clone().into())
                    .collect(), // Convert to blob_location::BlobLoc
                modification_time_sec: node.modification_time_sec,
                creation_time_sec: node.creation_time_sec,
                mode: node.st_mode, // Using st_mode from crate::node::Node
            }))
        }
    }

    /// Creates a virtual filesystem view of the backup set.
    /// The root directory contains subdirectories for each backup record (named by creation date).
    /// Each subdirectory contains the files and folders from that backup.
    pub fn get_root_directory(&self) -> Result<DirectoryEntryNode> {
        let mut root_children_entries = Vec::new();

        for (folder_uuid, records) in &self.backup_records {
            for record in records {
                if let GenericBackupRecord::Arq7(arq7_record) = record {
                    let record_dir_name = arq7_record
                        .creation_date
                        .map(|ts| {
                            let secs = ts as i64;
                            let nanos = ((ts.fract()) * 1_000_000_000.0) as u32;
                            match DateTime::from_timestamp(secs, nanos) {
                                Some(datetime_utc) => {
                                    datetime_utc.format("%Y-%m-%dT%H-%M-%S").to_string()
                                }
                                None => format!("unknown_date_{}", folder_uuid),
                            }
                        })
                        .unwrap_or_else(|| format!("no_date_{}", folder_uuid));

                    // Convert the root node of the backup record into a DirectoryEntry.
                    // This will be a shallow entry due to the modified node_to_directory_entry.
                    let backup_root_entry =
                        self.node_to_directory_entry(&arq7_record.node, folder_uuid.clone())?;

                    // Create a directory entry for this specific backup record session (e.g., named by date).
                    // This directory will contain the actual root of the backed-up folder/file.
                    let record_session_dir = DirectoryEntry::Directory(DirectoryEntryNode {
                        name: record_dir_name,
                        children: Some(vec![backup_root_entry]), // Contains the single root of the backup
                        tree_blob_loc: None, // This directory is virtual, not from a blob
                        modification_time_sec: arq7_record.node.modification_time_sec, // Or use record's creation time
                        creation_time_sec: arq7_record.node.creation_time_sec, // Or use record's creation time
                        mode: 0o040755, // Typical directory mode
                    });
                    root_children_entries.push(record_session_dir);
                }
            }
        }

        Ok(DirectoryEntryNode {
            name: "/".to_string(),
            children: Some(root_children_entries), // Ensure children is Some Vec
            tree_blob_loc: None,                   // Root is virtual
            modification_time_sec: 0,              // Or some other sensible default/current time
            creation_time_sec: 0,
            mode: 0o040755, // Typical directory mode
        })
    }

    /// Loads the children of a DirectoryEntryNode on demand.
    pub fn load_directory_children(&self, dir_entry_node: &mut DirectoryEntryNode) -> Result<()> {
        // If children are already loaded, or if it's a virtual directory without a tree_blob_loc
        if dir_entry_node.children.is_some() {
            return Ok(());
        }

        let blob_loc = match &dir_entry_node.tree_blob_loc {
            Some(loc) => loc,
            None => {
                // No blob loc, so it's an empty or virtual directory.
                dir_entry_node.children = Some(Vec::new());
                return Ok(());
            }
        };

        // Load the tree data using the blob_loc
        match blob_loc
            .load_tree_with_encryption(&self.root_path, self.encryption_keyset.as_ref())?
        {
            Some(tree) => {
                let mut children_entries = Vec::new();
                for (name, child_node) in tree.nodes {
                    // Convert each child Node into a shallow DirectoryEntry
                    let child_entry = self.node_to_directory_entry(&child_node, name)?;
                    children_entries.push(child_entry);
                }
                dir_entry_node.children = Some(children_entries);
            }
            None => {
                // Tree blob was empty or indicated no children
                dir_entry_node.children = Some(Vec::new());
            }
        }
        Ok(())
    }

    /// Reads the content of a file represented by a FileEntry.
    pub fn read_file_content(&self, file_entry: &FileEntry) -> Result<Vec<u8>> {
        let mut full_content = Vec::new();

        if file_entry.data_blob_locs.is_empty() {
            // Handle cases like zero-byte files that might not have blob locs.
            // Depending on Arq's behavior, item_size might be 0 for these.
            // If size is > 0 but no locs, it could be an error or an unsupported case.
            if file_entry.size == 0 {
                return Ok(full_content); // Empty file, return empty content
            } else {
                // This might indicate an issue or a file type not represented by dataBlobLocs here
                return Err(Error::InvalidFormat(format!(
                    "File '{}' has size {} but no data blob locations.",
                    file_entry.name, file_entry.size
                )));
            }
        }

        for blob_loc in &file_entry.data_blob_locs {
            let blob_data = blob_loc.load_data(&self.root_path, self.encryption_keyset.as_ref())?;
            full_content.extend(blob_data);
        }

        // As a sanity check, compare the loaded content size with the expected size.
        // This might not always be strictly necessary if Arq guarantees consistency,
        // but can catch issues during development or with corrupted data.
        if full_content.len() as u64 != file_entry.size {
            eprintln!(
                // Using eprintln for warnings, not returning an error yet unless it's critical
                "Warning: Loaded content size {} for file '{}' does not match expected size {}.",
                full_content.len(),
                file_entry.name,
                file_entry.size
            );
            // Depending on strictness, one might choose to return an error here:
            // return Err(Error::InvalidFormat(format!("Content size mismatch for file '{}'", file_entry.name)));
        }

        Ok(full_content)
    }

    /// Find real blob locations for files in the backup records
    /// This can be used when binary parsing produces fake blob paths
    pub fn find_all_blob_locations(&self) -> Vec<crate::blob_location::BlobLoc> {
        // Updated return type
        let mut blob_locations = Vec::new();

        for (_, records_vec) in &self.backup_records {
            for generic_record in records_vec {
                match generic_record {
                    GenericBackupRecord::Arq7(record) => {
                        collect_blob_locations_from_node(&record.node, &mut blob_locations);
                    }
                    GenericBackupRecord::Arq5(record) => {
                        if let Some(key) = &record.arq5_tree_blob_key {
                            // Convert crate::blob::BlobKey to crate::blob_location::BlobLoc.
                            blob_locations.push(crate::blob_location::BlobLoc {
                                // Updated type
                                blob_identifier: key.sha1.clone(),
                                compression_type: key.compression_type,
                                is_packed: false,
                                length: key.archive_size, // From unified BlobKey
                                offset: 0,                // Assumption for Arq5TreeBlobKey context
                                relative_path: format!("arq5_migrated_tree_blob/{}", key.sha1), // Placeholder path
                                stretch_encryption_key: key.stretch_encryption_key, // From unified BlobKey
                                is_large_pack: None, // Arq5 context might not have this concept
                            });
                        }
                        // backupRecordErrors in Arq5 might list problematic files, but these are not primary data blobs.
                        // arq5BucketXML parsing is out of scope.
                    }
                }
            }
        }
        blob_locations
    }
}

/// Recursively collect blob locations from a node tree (used for Arq7 records)
fn collect_blob_locations_from_node(
    node: &crate::node::Node,
    blob_locations: &mut Vec<crate::blob_location::BlobLoc>,
) {
    // Updated Vec type
    // Add data blob locations from this node
    for blob_loc in &node.data_blob_locs {
        // Convert arq7::BlobLoc to blob_location::BlobLoc
        blob_locations.push(blob_loc.clone().into());
    }

    // Add tree blob location if present
    if let Some(tree_blob_loc) = &node.tree_blob_loc {
        blob_locations.push(tree_blob_loc.clone().into());
    }

    // Add xattrs blob locations if present
    if let Some(xattrs_blob_locs) = &node.xattrs_blob_locs {
        for blob_loc in xattrs_blob_locs {
            blob_locations.push(blob_loc.clone());
        }
    }
    // Add acl blob location if present
    if let Some(acl_blob_loc) = &node.acl_blob_loc {
        blob_locations.push(acl_blob_loc.clone());
    }
}

/// Helper function for metadata extraction
fn count_files_in_node(
    node: &crate::node::Node, // Changed to crate::node::Node
    backup_set_dir: &Path,
    keyset: Option<&EncryptedKeySet>,
) -> Result<(u32, u64)> {
    if !node.is_tree {
        // This is a file
        let size = node.item_size;
        return Ok((1, size));
    }

    // This is a directory
    let mut file_count = 0u32;
    let mut total_size = 0u64;

    // TODO: This method needs to be implemented on crate::node::Node
    // For now, assume it returns Ok(None) to allow compilation.
    // if let Some(tree) = node.load_tree_with_encryption(backup_set_dir, keyset)? {
    //     for (_, child_node) in &tree.child_nodes {
    //         let (child_files, child_size) =
    //             count_files_in_node(child_node, backup_set_dir, keyset)?;
    //         file_count += child_files;
    //         total_size += child_size;
    //     }
    // }
    if let Some(tree) = node.load_tree_with_encryption(backup_set_dir, keyset)? {
        for (_, child_node_entry) in &tree.nodes {
            // Use tree.nodes
            let (child_files, child_size) =
                count_files_in_node(child_node_entry, backup_set_dir, keyset)?;
            file_count += child_files;
            total_size += child_size;
        }
    }
    Ok((file_count, total_size))
}
