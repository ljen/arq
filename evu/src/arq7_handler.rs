use crate::error::{Error, Result};
use arq::arq7::{BackupSet, EncryptedKeySet};
use arq::node::Node; // Updated to use arq::node::Node
use chrono::DateTime;
use std::path::Path;

// Helper function to load the backup set
fn load_backup_set(backup_set_path: &Path, password: Option<&str>) -> Result<BackupSet> {
    BackupSet::from_directory_with_password(backup_set_path, password).map_err(Error::ArqError) // Convert arq::Error to local Error type
}

// Helper function to find a record by a unique identifier (e.g., timestamp string)
fn find_record_by_identifier<'a>(
    backup_set: &'a BackupSet,
    identifier: &str,
) -> Option<&'a arq::arq7::Arq7BackupRecord> {
    // Changed return type
    for records_vec in backup_set.backup_records.values() {
        for gen_record in records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(arq7_record) => {
                    if let Some(creation_date_val) = arq7_record.creation_date {
                        if creation_date_val.to_string().starts_with(identifier) {
                            return Some(arq7_record);
                        }
                    }
                    // Also check against the raw timestamp string from the record's path if needed,
                    // similar to how list_backup_records formats it.
                    // For now, sticking to creation_date field.
                }
                arq::arq7::GenericBackupRecord::Arq5(arq5_record) => {
                    // If Arq5 records also need to be identifiable by a similar timestamp,
                    // this logic would need to be adapted. For now, focusing on Arq7.
                    if let Some(creation_date_val) = arq5_record.creation_date {
                        if creation_date_val.to_string().starts_with(identifier) {
                            // Cannot return arq5_record as Arq7BackupRecord.
                            // This function is now specific to finding Arq7 records.
                        }
                    }
                } // Removed duplicate Arq5 match arm here
            }
        }
    }
    None
}

// Helper function to find a node (file or folder) within a record's tree
fn find_node_in_record_tree(
    node: &Node,
    path_parts: &[&str],
    current_depth: usize,
    backup_set_path: &Path,
    keyset: Option<&EncryptedKeySet>,
) -> Result<Option<Node>> {
    if current_depth == path_parts.len() {
        return Ok(Some(node.clone()));
    }

    if !node.is_tree {
        return Ok(None);
    }

    match node.load_tree_with_encryption(backup_set_path, keyset) {
        Ok(Some(tree)) => {
            let target_child_name = path_parts[current_depth];
            eprintln!(
                "DEBUG: find_node_in_record_tree: Depth: {}, Target: '{}', Children: {:?}",
                current_depth,
                target_child_name,
                tree.nodes.keys() // Changed from child_nodes to nodes
            );
            if let Some(child_node) = tree.nodes.get(target_child_name) {
                // Changed from child_nodes to nodes
                return find_node_in_record_tree(
                    child_node,
                    path_parts,
                    current_depth + 1,
                    backup_set_path,
                    keyset,
                );
            }
        }
        Ok(None) => {
            let current_path_segment = if current_depth > 0 {
                path_parts[current_depth - 1]
            } else {
                "root"
            };
            return Err(Error::Generic(format!(
                "Node was expected to be a tree with loadable data, but found none for path part: {}",
                current_path_segment
            )));
        }
        Err(e) => {
            return Err(Error::ArqError(e)); // Directly use ArqError
        }
    }
    Ok(None)
}

pub fn list_backup_records(backup_set_path: &Path, password: Option<&str>) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    println!("Arq 7 Backup Records:");
    println!("---------------------");

    eprintln!("DEBUG: All loaded backup_folder_configs:");
    for (uuid, config) in &backup_set.backup_folder_configs {
        eprintln!(
            "  UUID: {}, Name: {}, LocalPath: {}",
            uuid, config.name, config.local_path
        );
    }

    if backup_set.backup_records.is_empty() {
        println!("No backup records found.");
        return Ok(());
    }

    for (folder_uuid, records_vec) in &backup_set.backup_records {
        let folder_config = backup_set.backup_folder_configs.get(folder_uuid);
        let folder_name = folder_config.map_or("Unknown Folder", |fc| &fc.name);
        let folder_local_path = folder_config.map_or("N/A", |fc| &fc.local_path);

        eprintln!(
            "DEBUG: list_backup_records: Processing folder_uuid: {}, Retrieved local_path: {}",
            folder_uuid, folder_local_path
        );

        println!("\nFolder: {} (UUID: {})", folder_name, folder_uuid);
        println!("  Original Path: {}", folder_local_path);
        if records_vec.is_empty() {
            println!("  No records for this folder.");
            continue;
        }
        for gen_record in records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    let timestamp_str = record.creation_date.map_or_else(
                        || "Unknown Timestamp".to_string(),
                        |ts_f64| {
                            // Arq 7 uses f64 for timestamp (seconds with fractional part)
                            // For display, we can truncate or round to seconds.
                            // Assuming ts_f64 is seconds since epoch.
                            chrono::DateTime::from_timestamp(
                                ts_f64 as i64,
                                (ts_f64.fract() * 1_000_000_000.0) as u32,
                            )
                            .map_or_else(
                                || ts_f64.to_string(),
                                |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            )
                        },
                    );
                    println!(
                        "  - Record Timestamp: {} (Arq7, Raw: {:?})",
                        timestamp_str,
                        record.creation_date.unwrap_or(0.0)
                    );
                    println!(
                        "    Arq Version: {}",
                        record.arq_version.as_deref().unwrap_or("N/A")
                    );
                    println!("    Complete: {}", record.is_complete.unwrap_or(false));
                    let error_count = record.backup_record_errors.as_ref().map_or(0, |v| v.len());
                    println!("    Error Count: {}", error_count);
                    println!("    Root Node Size: {} bytes", record.node.item_size);
                    if let Some(files_count) = record.node.contained_files_count {
                        println!("    Contained Files (approx): {}", files_count);
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    let timestamp_str = record.creation_date.map_or_else(
                        || "Unknown Timestamp".to_string(),
                        |ts_f64| {
                            chrono::DateTime::from_timestamp(
                                ts_f64 as i64,
                                (ts_f64.fract() * 1_000_000_000.0) as u32,
                            )
                            .map_or_else(
                                || ts_f64.to_string(),
                                |dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                            )
                        },
                    );
                    println!(
                        "  - Record Timestamp: {} (Arq5, Raw: {:?})",
                        timestamp_str,
                        record.creation_date.unwrap_or(0.0)
                    );
                    println!(
                        "    Arq Version: {}",
                        record.arq_version.as_deref().unwrap_or("N/A")
                    );
                    println!("    Complete: {}", record.is_complete.unwrap_or(false));
                    let error_count = record.backup_record_errors.as_ref().map_or(0, |v| v.len());
                    println!("    Error Count: {}", error_count);
                    println!("    (Arq5 record - detailed node info not directly listed here)");
                }
            }
        }
    }
    Ok(())
}

pub fn list_file_versions(
    backup_set_path: &Path,
    file_path_in_backup: &str,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();
    println!("Versions for file: {}", file_path_in_backup);
    println!("------------------------------------");

    let path_parts: Vec<&str> = file_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if path_parts.is_empty() {
        return Err(Error::Generic("File path cannot be empty".to_string()));
    }

    let mut found_versions = 0;

    for (folder_uuid, records_vec) in &backup_set.backup_records {
        for gen_record in records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    let record_local_path_str = record.local_path.as_deref().unwrap_or("");
                    let mut effective_path_parts = path_parts.clone();

                    // Path adjustment logic (remains largely the same, uses record.local_path)
                    if !record_local_path_str.is_empty()
                        && file_path_in_backup.starts_with(record_local_path_str)
                    {
                        let relative_file_path = file_path_in_backup
                            .strip_prefix(record_local_path_str)
                            .unwrap_or(file_path_in_backup);
                        let relative_file_path_trimmed = relative_file_path.trim_start_matches('/');
                        effective_path_parts = relative_file_path_trimmed
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .collect();
                        if effective_path_parts.is_empty() && !relative_file_path_trimmed.is_empty()
                        {
                            effective_path_parts = vec![relative_file_path_trimmed];
                        }
                    } else if record_local_path_str.is_empty()
                        && backup_set.backup_folder_configs.get(folder_uuid).is_some()
                    {
                        if let Some(bf_config) = backup_set.backup_folder_configs.get(folder_uuid) {
                            if file_path_in_backup.starts_with(&bf_config.local_path) {
                                let relative_file_path = file_path_in_backup
                                    .strip_prefix(&bf_config.local_path)
                                    .unwrap_or(file_path_in_backup);
                                let relative_file_path_trimmed =
                                    relative_file_path.trim_start_matches('/');
                                effective_path_parts = relative_file_path_trimmed
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                if effective_path_parts.is_empty()
                                    && !relative_file_path_trimmed.is_empty()
                                {
                                    effective_path_parts = vec![relative_file_path_trimmed];
                                }
                            }
                        }
                    }

                    if effective_path_parts.is_empty() {
                        continue;
                    }

                    match find_node_in_record_tree(
                        &record.node, // This is arq::arq7::Node from Arq7BackupRecord
                        &effective_path_parts,
                        0,
                        backup_set_path,
                        keyset,
                    ) {
                        Ok(Some(node)) if !node.is_tree => {
                            eprintln!(
                                "DEBUG list_file_versions: Found file node: {:?}, size: {}",
                                node.data_blob_locs.first().map(|b| &b.blob_identifier),
                                node.item_size
                            );
                            let timestamp_str = record.creation_date.map_or_else(
                                || "Unknown Timestamp".to_string(),
                                |ts_f64| {
                                    chrono::DateTime::from_timestamp(
                                        ts_f64 as i64,
                                        (ts_f64.fract() * 1_000_000_000.0) as u32,
                                    )
                                    .unwrap()
                                    .format("%Y-%m-%d %H:%M:%S UTC")
                                    .to_string()
                                },
                            );
                            println!(
                                "  - Record Timestamp: {} (Arq7, Raw: {:?}), Size: {} bytes, Modified: {}",
                                timestamp_str,
                                record.creation_date.unwrap_or(0.0),
                                node.item_size,
                                chrono::DateTime::from_timestamp(node.modification_time_sec, 0) // Assuming nsec is 0 for this display
                                    .unwrap()
                                    .format("%Y-%m-%d %H:%M:%S")
                            );
                            found_versions += 1;
                        }
                        Ok(Some(_node)) => {} // Found a directory when expecting a file
                        Ok(None) => {}        // Path not found in this record
                        Err(e) => {
                            eprintln!(
                                "Warning: Error processing Arq7 record {:?}: {}",
                                record.creation_date, e
                            );
                        }
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    // Arq5 records don't have a direct `node` of type `arq::arq7::Node`.
                    // Listing versions from Arq5 records would require loading the Arq5 tree structure.
                    // For this update, we'll skip detailed listing for Arq5.
                    let timestamp_str = record.creation_date.map_or_else(
                        || "Unknown Timestamp".to_string(),
                        |ts_f64| {
                            chrono::DateTime::from_timestamp(
                                ts_f64 as i64,
                                (ts_f64.fract() * 1_000_000_000.0) as u32,
                            )
                            .unwrap()
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                        },
                    );
                    eprintln!(
                        "DEBUG list_file_versions: Skipping Arq5 record (Timestamp: {}) for detailed version listing.",
                        timestamp_str
                    );
                }
            }
        }
    }

    if found_versions == 0 {
        println!("No versions found for this file."); // Reverted to expect "file"
    }
    Ok(())
}

pub fn list_folder_versions(
    backup_set_path: &Path,
    folder_path_in_backup: &str,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();
    println!("Versions for folder: {}", folder_path_in_backup);
    println!("--------------------------------------");

    let path_parts: Vec<&str> = folder_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut found_versions = 0;

    for (folder_uuid, records_vec) in &backup_set.backup_records {
        for gen_record in records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    let record_local_path_str = record.local_path.as_deref().unwrap_or("");
                    let mut effective_path_parts = path_parts.clone();

                    eprintln!(
                        "DEBUG list_folder_versions: Folder: '{}', Record LocalPath: '{}'",
                        folder_path_in_backup, record_local_path_str
                    );

                    // Path adjustment logic
                    if folder_path_in_backup == "/" || folder_path_in_backup.is_empty() {
                        effective_path_parts = Vec::new();
                    } else if !record_local_path_str.is_empty()
                        && folder_path_in_backup.starts_with(record_local_path_str)
                    {
                        let relative_folder_path = folder_path_in_backup
                            .strip_prefix(record_local_path_str)
                            .unwrap_or(folder_path_in_backup);
                        let relative_folder_path_trimmed =
                            relative_folder_path.trim_start_matches('/');
                        effective_path_parts = relative_folder_path_trimmed
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .collect();
                        if relative_folder_path_trimmed.is_empty()
                            && !relative_folder_path.is_empty()
                            && folder_path_in_backup != "/"
                        {
                            effective_path_parts = Vec::new();
                        }
                    } else if record_local_path_str.is_empty()
                        && backup_set.backup_folder_configs.get(folder_uuid).is_some()
                    {
                        if let Some(bf_config) = backup_set.backup_folder_configs.get(folder_uuid) {
                            if folder_path_in_backup.starts_with(&bf_config.local_path) {
                                let relative_folder_path = folder_path_in_backup
                                    .strip_prefix(&bf_config.local_path)
                                    .unwrap_or(folder_path_in_backup);
                                let relative_folder_path_trimmed =
                                    relative_folder_path.trim_start_matches('/');
                                effective_path_parts = relative_folder_path_trimmed
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                if relative_folder_path_trimmed.is_empty()
                                    && !relative_folder_path.is_empty()
                                    && folder_path_in_backup != "/"
                                {
                                    effective_path_parts = Vec::new();
                                }
                            }
                        }
                    }
                    // End of path adjustment logic

                    match find_node_in_record_tree(
                        &record.node, // This is arq::arq7::Node from Arq7BackupRecord
                        &effective_path_parts,
                        0,
                        backup_set_path,
                        keyset,
                    ) {
                        Ok(Some(node)) if node.is_tree => {
                            let timestamp_str = record.creation_date.map_or_else(
                                || "Unknown Timestamp".to_string(),
                                |ts_f64| {
                                    // Use ts_f64 for Arq7 f64 timestamp
                                    chrono::DateTime::from_timestamp(
                                        ts_f64 as i64,
                                        (ts_f64.fract() * 1_000_000_000.0) as u32,
                                    )
                                    .unwrap()
                                    .format("%Y-%m-%d %H:%M:%S UTC")
                                    .to_string()
                                },
                            );
                            println!(
                                "  - Record Timestamp: {} (Arq7, Raw: {:?}), Items: ~{}, Modified: {}",
                                timestamp_str,
                                record.creation_date.unwrap_or(0.0), // Use 0.0 for f64
                                node.contained_files_count.unwrap_or(0),
                                chrono::DateTime::from_timestamp(node.modification_time_sec, 0)
                                    .unwrap()
                                    .format("%Y-%m-%d %H:%M:%S")
                            );
                            found_versions += 1;
                        }
                        Ok(Some(_node)) => {}
                        Ok(None) => {}
                        Err(e) => {
                            eprintln!(
                                "Warning: Error processing Arq7 record {:?}: {}",
                                record.creation_date, e
                            );
                        }
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    let timestamp_str = record.creation_date.map_or_else(
                        || "Unknown Timestamp".to_string(),
                        |ts_f64| {
                            chrono::DateTime::from_timestamp(
                                ts_f64 as i64,
                                (ts_f64.fract() * 1_000_000_000.0) as u32,
                            )
                            .unwrap()
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                        },
                    );
                    eprintln!(
                        "DEBUG list_folder_versions: Skipping Arq5 record (Timestamp: {}) for detailed version listing.",
                        timestamp_str
                    );
                }
            }
        }
    }
    if found_versions == 0 {
        println!("No versions found for this folder.");
    }
    Ok(())
}

pub fn restore_full_record(
    backup_set_path: &Path,
    record_identifier: &str,
    destination: &Path,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();

    if !destination.exists() {
        std::fs::create_dir_all(destination)?;
    }
    if !destination.is_dir() {
        return Err(Error::Generic(format!(
            "Destination '{}' is not a directory.",
            destination.display()
        )));
    }

    match find_record_by_identifier(&backup_set, record_identifier) {
        Some(arq7_record) => {
            // Changed variable name to reflect it's an Arq7BackupRecord
            let timestamp_str = arq7_record
                .creation_date
                .map_or_else(|| record_identifier.to_string(), |ts| ts.to_string());
            let record_dest_name = format!("record_{}", timestamp_str);
            let final_destination = destination.join(record_dest_name);
            std::fs::create_dir_all(&final_destination)?;

            println!(
                "Restoring record (Timestamp: {}) to {}...",
                timestamp_str,
                final_destination.display()
            );

            let mut stats = ExtractionStats::default();
            extract_node_to_destination_recursive(
                &arq7_record.node, // Access node from arq7_record
                backup_set_path,
                keyset,
                &final_destination,
                "",
                &mut stats,
            )?;
            println!(
                "Successfully restored record. Files: {}, Dirs: {}, Total Size: {} bytes. Errors: {}",
                stats.files_restored, stats.dirs_created, stats.bytes_restored, stats.errors
            );
            if stats.errors > 0 {
                eprintln!(
                    "Warning: {} errors occurred during restoration.",
                    stats.errors
                );
            }
            Ok(())
        }
        None => Err(Error::NotFound(format!(
            "Record with identifier '{}' not found.",
            record_identifier
        ))),
    }
}

pub fn restore_specific_file_from_record(
    backup_set_path: &Path,
    record_identifier: &str,
    file_path_in_backup: &str,
    destination: &Path,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier).ok_or_else(|| {
            // Renamed record to arq7_record
            Error::NotFound(format!(
                "Record with identifier '{}' not found.",
                record_identifier
            ))
        })?;

    let path_parts: Vec<&str> = file_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if path_parts.is_empty() {
        return Err(Error::Generic("File path cannot be empty".to_string()));
    }

    let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or(""); // Used arq7_record
    let mut effective_path_parts = path_parts.clone();
    if !record_local_path_str.is_empty() && file_path_in_backup.starts_with(record_local_path_str) {
        let relative_file_path = file_path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(file_path_in_backup);
        let relative_file_path_trimmed = relative_file_path.trim_start_matches('/');
        effective_path_parts = relative_file_path_trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if effective_path_parts.is_empty() && !relative_file_path_trimmed.is_empty() {
            effective_path_parts = vec![relative_file_path_trimmed];
        }
    } else if record_local_path_str.is_empty() {
        if let Some(bf_config) = backup_set
            .backup_folder_configs
            .get(&arq7_record.backup_folder_uuid)
        // Used arq7_record
        {
            if file_path_in_backup.starts_with(&bf_config.local_path) {
                let relative_file_path = file_path_in_backup
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(file_path_in_backup);
                let relative_file_path_trimmed = relative_file_path.trim_start_matches('/');
                effective_path_parts = relative_file_path_trimmed
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if effective_path_parts.is_empty() && !relative_file_path_trimmed.is_empty() {
                    effective_path_parts = vec![relative_file_path_trimmed];
                }
            }
        }
    }
    if effective_path_parts.is_empty() {
        return Err(Error::NotFound(format!(
            "Adjusted file path is empty for '{}' relative to record's local path '{}'. Cannot restore directory root as a file.",
            file_path_in_backup, record_local_path_str
        )));
    }

    let target_node = find_node_in_record_tree(
        &arq7_record.node, // Used arq7_record
        &effective_path_parts,
        0,
        backup_set_path,
        keyset,
    )?
    .ok_or_else(|| {
        Error::NotFound(format!(
            "File '{}' not found in record '{}'.",
            file_path_in_backup, record_identifier
        ))
    })?;

    if target_node.is_tree {
        return Err(Error::Generic(format!(
            "Path '{}' points to a directory, not a file.",
            file_path_in_backup
        )));
    }

    let output_path = if destination.is_dir() || destination.to_string_lossy().ends_with('/') {
        let filename = effective_path_parts
            .last()
            .ok_or_else(|| Error::Generic("Could not determine filename".to_string()))?;
        destination.join(filename)
    } else {
        destination.to_path_buf()
    };

    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    println!(
        "Restoring file '{}' from record (Timestamp: {:?}) to {}...",
        file_path_in_backup,
        arq7_record.creation_date, // Used arq7_record
        output_path.display()
    );
    let file_data = target_node.reconstruct_file_data_with_encryption(backup_set_path, keyset)?;
    std::fs::write(&output_path, file_data)?;

    println!("Successfully restored file to {}.", output_path.display());
    Ok(())
}

pub fn restore_specific_folder_from_record(
    backup_set_path: &Path,
    record_identifier: &str,
    folder_path_in_backup: &str,
    destination: &Path,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier).ok_or_else(|| {
            // Renamed record to arq7_record
            Error::NotFound(format!(
                "Record with identifier '{}' not found.",
                record_identifier
            ))
        })?;

    let path_parts: Vec<&str> = folder_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut effective_path_parts = path_parts.clone();
    let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or(""); // Used arq7_record

    if folder_path_in_backup == "/" || folder_path_in_backup.is_empty() {
        effective_path_parts = Vec::new();
    } else if !record_local_path_str.is_empty()
        && folder_path_in_backup.starts_with(record_local_path_str)
    {
        let relative_path = folder_path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(folder_path_in_backup);
        let trimmed_relative_path = relative_path.trim_start_matches('/');
        effective_path_parts = trimmed_relative_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if trimmed_relative_path.is_empty()
            && !relative_path.is_empty()
            && folder_path_in_backup != "/"
        {
            effective_path_parts = Vec::new();
        }
    } else if record_local_path_str.is_empty() {
        if let Some(bf_config) = backup_set
            .backup_folder_configs
            .get(&arq7_record.backup_folder_uuid)
        // Used arq7_record
        {
            if folder_path_in_backup.starts_with(&bf_config.local_path) {
                let relative_path = folder_path_in_backup
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(folder_path_in_backup);
                let trimmed_relative_path = relative_path.trim_start_matches('/');
                effective_path_parts = trimmed_relative_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if trimmed_relative_path.is_empty()
                    && !relative_path.is_empty()
                    && folder_path_in_backup != "/"
                {
                    effective_path_parts = Vec::new();
                }
            }
        }
    }

    let target_node = find_node_in_record_tree(
        &arq7_record.node, // Used arq7_record
        &effective_path_parts,
        0,
        backup_set_path,
        keyset,
    )?
    .ok_or_else(|| {
        Error::NotFound(format!(
            "Folder '{}' not found in record '{}'.",
            folder_path_in_backup, record_identifier
        ))
    })?;

    if !target_node.is_tree {
        return Err(Error::Generic(format!(
            "Path '{}' points to a file, not a directory.",
            folder_path_in_backup
        )));
    }

    if !destination.exists() {
        std::fs::create_dir_all(destination)?;
    }
    if !destination.is_dir() {
        return Err(Error::Generic(format!(
            "Destination '{}' is not a directory.",
            destination.display()
        )));
    }

    let base_folder_name = effective_path_parts.last().map_or("root_content", |n| *n);
    let final_destination_for_folder_content = destination.join(base_folder_name);
    if !final_destination_for_folder_content.exists() {
        std::fs::create_dir_all(&final_destination_for_folder_content)?;
    }

    println!(
        "Restoring folder '{}' from record (Timestamp: {:?}) to {}...",
        folder_path_in_backup,
        arq7_record.creation_date, // Used arq7_record
        final_destination_for_folder_content.display()
    );

    let mut stats = ExtractionStats::default();
    extract_node_to_destination_recursive(
        &target_node,
        backup_set_path,
        keyset,
        &final_destination_for_folder_content,
        "",
        &mut stats,
    )?;

    println!(
        "Successfully restored folder. Files: {}, Dirs: {}, Total Size: {} bytes. Errors: {}",
        stats.files_restored, stats.dirs_created, stats.bytes_restored, stats.errors
    );
    if stats.errors > 0 {
        eprintln!(
            "Warning: {} errors occurred during restoration.",
            stats.errors
        );
    }
    Ok(())
}

pub fn restore_all_folder_versions(
    backup_set_path: &Path,
    folder_path_in_backup: &str,
    destination_root: &Path,
    password: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path, password)?;
    let keyset = backup_set.encryption_keyset();

    if !destination_root.exists() {
        std::fs::create_dir_all(destination_root)?;
    }
    if !destination_root.is_dir() {
        return Err(Error::Generic(format!(
            "Destination root '{}' is not a directory.",
            destination_root.display()
        )));
    }

    println!(
        "Restoring all versions of folder '{}' to root '{}'",
        folder_path_in_backup,
        destination_root.display()
    );

    let path_parts: Vec<&str> = folder_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut versions_restored_count = 0;

    for (folder_uuid, gen_records_vec) in &backup_set.backup_records {
        // Renamed records to gen_records_vec
        for gen_record in gen_records_vec {
            // Renamed record to gen_record
            match gen_record {
                // Added match statement to handle GenericBackupRecord
                arq::arq7::GenericBackupRecord::Arq7(arq7_record) => {
                    // Handle Arq7 variant

                    let timestamp_str = arq7_record.creation_date.map_or_else(
                        // Used arq7_record
                        || format!("unknown_ts_{}", versions_restored_count),
                        |ts_f64| {
                            // Arq7 uses f64
                            DateTime::from_timestamp(
                                ts_f64 as i64,
                                (ts_f64.fract() * 1_000_000_000.0) as u32,
                            )
                            .map_or_else(
                                || ts_f64.to_string(), // Fallback to raw string if conversion fails
                                |dt| dt.to_rfc3339(),
                            )
                        },
                    );

                    eprintln!(
                        "DEBUG: restore_all_folder_versions: Arq7 record timestamp: {}",
                        timestamp_str
                    );
                    let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or("");
                    let mut effective_path_parts = path_parts.clone();

                    if folder_path_in_backup == "/" || folder_path_in_backup.is_empty() {
                        effective_path_parts = Vec::new();
                    } else if !record_local_path_str.is_empty()
                        && folder_path_in_backup.starts_with(record_local_path_str)
                    {
                        let relative_path = folder_path_in_backup
                            .strip_prefix(record_local_path_str)
                            .unwrap_or(folder_path_in_backup);
                        let trimmed_relative_path = relative_path.trim_start_matches('/');
                        effective_path_parts = trimmed_relative_path
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .collect();
                        if trimmed_relative_path.is_empty()
                            && !relative_path.is_empty()
                            && folder_path_in_backup != "/"
                        {
                            effective_path_parts = Vec::new();
                        }
                    } else if record_local_path_str.is_empty() {
                        if let Some(bf_config) = backup_set.backup_folder_configs.get(folder_uuid) {
                            if folder_path_in_backup.starts_with(&bf_config.local_path) {
                                let relative_path = folder_path_in_backup
                                    .strip_prefix(&bf_config.local_path)
                                    .unwrap_or(folder_path_in_backup);
                                let trimmed_relative_path = relative_path.trim_start_matches('/');
                                effective_path_parts = trimmed_relative_path
                                    .split('/')
                                    .filter(|s| !s.is_empty())
                                    .collect();
                                if trimmed_relative_path.is_empty()
                                    && !relative_path.is_empty()
                                    && folder_path_in_backup != "/"
                                {
                                    effective_path_parts = Vec::new();
                                }
                            }
                        }
                    }

                    if let Ok(Some(target_node)) = find_node_in_record_tree(
                        &arq7_record.node, // Used arq7_record
                        &effective_path_parts,
                        0,
                        backup_set_path,
                        keyset,
                    ) {
                        if target_node.is_tree {
                            let timestamp_str = arq7_record.creation_date.map_or_else(
                                // Used arq7_record
                                || format!("unknown_ts_{}", versions_restored_count),
                                |ts_f64| {
                                    // Arq7 uses f64
                                    DateTime::from_timestamp(
                                        ts_f64 as i64,
                                        (ts_f64.fract() * 1_000_000_000.0) as u32,
                                    )
                                    .map_or_else(
                                        || ts_f64.to_string(), // Fallback to raw string if conversion fails
                                        |dt| dt.to_rfc3339(),
                                    )
                                },
                            );

                            let version_dest_dir_name = format!("{}", timestamp_str);
                            let version_destination = destination_root.join(version_dest_dir_name);

                            let content_dest_dir_name =
                                effective_path_parts.last().map_or("root_content", |n| *n);
                            let final_content_destination =
                                version_destination.join(content_dest_dir_name);

                            if !final_content_destination.exists() {
                                std::fs::create_dir_all(&final_content_destination)?;
                            }

                            println!(
                                "  Restoring version from record (Timestamp: {}) to {}...",
                                timestamp_str,
                                final_content_destination.display()
                            );
                            let mut stats = ExtractionStats::default();
                            match extract_node_to_destination_recursive(
                                &target_node,
                                backup_set_path,
                                keyset,
                                &final_content_destination,
                                "",
                                &mut stats,
                            ) {
                                Ok(_) => {
                                    println!(
                                        "    Successfully restored version. Files: {}, Dirs: {}, Size: {} bytes. Errors: {}",
                                        stats.files_restored,
                                        stats.dirs_created,
                                        stats.bytes_restored,
                                        stats.errors
                                    );
                                    if stats.errors > 0 {
                                        eprintln!(
                                            "    Warning: {} errors occurred during this version's restoration.",
                                            stats.errors
                                        );
                                    }
                                    versions_restored_count += 1;
                                }
                                Err(e) => {
                                    eprintln!(
                                        "    Error restoring version from record {}: {}",
                                        timestamp_str, e
                                    );
                                }
                            }
                        }
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(_arq5_record) => {
                    // Arq5 records don't have a direct `node` of type `arq::arq7::Node`
                    // and this function is geared towards Arq7's structure for restoring.
                    // So, we'll skip Arq5 records for this specific function.
                    eprintln!(
                        "DEBUG restore_all_folder_versions: Skipping Arq5 record for folder version restoration."
                    );
                }
            }
        }
    }

    if versions_restored_count == 0 {
        println!(
            "No versions of folder '{}' found to restore.",
            folder_path_in_backup
        );
    } else {
        println!(
            "Finished restoring {} versions of folder '{}'.",
            versions_restored_count, folder_path_in_backup
        );
    }

    Ok(())
}

// --- Helper for recursive extraction (based on arq7_test.rs logic) ---
#[derive(Debug, Default, Clone, Copy)]
struct ExtractionStats {
    files_restored: usize,
    dirs_created: usize,
    bytes_restored: u64,
    errors: usize,
}

fn extract_node_to_destination_recursive(
    node: &Node,
    backup_set_path: &Path,
    keyset: Option<&EncryptedKeySet>,
    current_materialized_path: &Path,
    relative_path_for_node: &str,
    stats: &mut ExtractionStats,
) -> Result<()> {
    let node_output_path = if relative_path_for_node.is_empty() {
        current_materialized_path.to_path_buf()
    } else {
        current_materialized_path.join(relative_path_for_node)
    };

    if node.is_tree {
        if !node_output_path.exists() {
            std::fs::create_dir_all(&node_output_path).map_err(Error::IoError)?;
            stats.dirs_created += 1;
        }

        match node.load_tree_with_encryption(backup_set_path, keyset) {
            Ok(Some(tree)) => {
                for (child_name, child_node) in &tree.nodes {
                    // Changed from child_nodes to nodes
                    if let Err(e) = extract_node_to_destination_recursive(
                        child_node,
                        backup_set_path,
                        keyset,
                        &node_output_path,
                        child_name,
                        stats,
                    ) {
                        eprintln!("Error processing child '{}': {}", child_name, e);
                        stats.errors += 1;
                    }
                }
            }
            Ok(None) => {
                eprintln!(
                    "Warning: Node {} is a tree but has no loadable tree data.",
                    node_output_path.display()
                );
            }
            Err(e) => {
                eprintln!(
                    "Error loading tree for {}: {}",
                    node_output_path.display(),
                    e
                );
                stats.errors += 1;
            }
        }
    } else {
        if let Some(parent_dir) = node_output_path.parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir).map_err(Error::IoError)?;
            }
        }

        match node.reconstruct_file_data_with_encryption(backup_set_path, keyset) {
            Ok(file_data) => {
                std::fs::write(&node_output_path, &file_data).map_err(Error::IoError)?;
                stats.files_restored += 1;
                stats.bytes_restored += file_data.len() as u64;

                if node.modification_time_sec > 0 {
                    use std::time::UNIX_EPOCH;
                    if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(
                        node.modification_time_sec as u64,
                    )) {
                        let _ = filetime::set_file_mtime(
                            &node_output_path,
                            filetime::FileTime::from_system_time(mtime),
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Error reconstructing file data for {}: {}",
                    node_output_path.display(),
                    e
                );
                stats.errors += 1;
            }
        }
    }
    Ok(())
}
