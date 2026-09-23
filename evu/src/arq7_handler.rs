use crate::error::{Error, Result};
use arq::arq7::{BackupSet, EncryptedKeySet};
use arq::node::Node;
use chrono::DateTime;
use rayon::prelude::*;
use std::path::Path;

/// Safely convert an f64 timestamp (seconds since epoch) to a formatted string.
fn format_timestamp(ts_f64: f64) -> String {
    let secs = ts_f64 as i64;
    let fract = ts_f64.fract();
    let nanos = if fract >= 0.0 {
        (fract * 1_000_000_000.0) as u32
    } else {
        0
    };
    DateTime::from_timestamp(secs, nanos)
        .map(|dt| {
            use chrono::{Datelike, Timelike};
            let naive = dt.naive_utc();
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
                naive.year(),
                naive.month(),
                naive.day(),
                naive.hour(),
                naive.minute(),
                naive.second()
            )
        })
        .unwrap_or_else(|| ts_f64.to_string())
}

/// Safely convert an f64 timestamp to RFC3339 format.
fn format_timestamp_rfc3339(ts_f64: f64) -> String {
    let secs = ts_f64 as i64;
    let fract = ts_f64.fract();
    let nanos = if fract >= 0.0 {
        (fract * 1_000_000_000.0) as u32
    } else {
        0
    };
    DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts_f64.to_string())
}

/// Safely format a seconds-since-epoch i64 for display.
fn format_epoch_secs(secs: i64) -> String {
    DateTime::from_timestamp(secs, 0)
        .map(|dt| {
            use chrono::{Datelike, Timelike};
            let naive = dt.naive_utc();
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                naive.year(),
                naive.month(),
                naive.day(),
                naive.hour(),
                naive.minute(),
                naive.second()
            )
        })
        .unwrap_or_else(|| secs.to_string())
}

fn timestamp_identifier_matches(timestamp: f64, identifier: &str) -> bool {
    let trimmed_identifier = identifier.trim_end_matches(".0");
    let seconds = timestamp.trunc() as i64;
    let candidates = [
        timestamp.to_string(),
        seconds.to_string(),
        (seconds * 1000).to_string(),
    ];

    candidates.iter().any(|candidate| {
        candidate.starts_with(identifier) || candidate.starts_with(trimmed_identifier)
    })
}

fn record_timestamp_dir_name(timestamp: f64) -> String {
    let seconds = timestamp.trunc() as i64;
    if (timestamp - seconds as f64).abs() < f64::EPSILON {
        seconds.to_string()
    } else {
        timestamp.to_string()
    }
}

// Helper function to load the backup set
fn load_backup_set(backup_set_path: &Path) -> Result<BackupSet> {
    match BackupSet::from_directory_with_password(backup_set_path, None) {
        Ok(set) => Ok(set),
        Err(arq::error::Error::InvalidFormat(msg))
            if msg == "Encrypted backup requires password" =>
        {
            let password = crate::utils::get_password(|p| rpassword::prompt_password(p))?;
            BackupSet::from_directory_with_password(backup_set_path, Some(&password))
                .map_err(Error::ArqError)
        }
        Err(e) => Err(Error::ArqError(e)),
    }
}

// Helper function to find a record by a unique identifier (e.g., timestamp string)
fn find_record_by_identifier<'a>(
    backup_set: &'a BackupSet,
    identifier: &str,
) -> Result<Option<&'a arq::arq7::Arq7BackupRecord>> {
    let mut matched = None;
    for records in backup_set.backup_records.values() {
        for record in records {
            let arq7_record = match record {
                arq::arq7::GenericBackupRecord::Arq7(record) => record,
                arq::arq7::GenericBackupRecord::Arq5(_) => continue,
            };
            if arq7_record
                .creation_date
                .is_some_and(|timestamp| timestamp_identifier_matches(timestamp, identifier))
            {
                if matched.is_some() {
                    return Err(Error::Generic(format!(
                        "Record identifier '{}' matches multiple backup records; use a more specific identifier",
                        identifier
                    )));
                }
                matched = Some(arq7_record);
            }
        }
    }
    Ok(matched)
}

// Helper function to find a node (file or folder) within a record's tree
fn find_node_in_record_tree<'a>(
    node: &'a Node,
    path_parts: &[&str],
    current_depth: usize,
    backup_set_path: &Path,
    keyset: Option<&EncryptedKeySet>,
) -> Result<Option<std::borrow::Cow<'a, Node>>> {
    if current_depth == path_parts.len() {
        return Ok(Some(std::borrow::Cow::Borrowed(node)));
    }

    let mut current_node = std::borrow::Cow::Borrowed(node);

    for i in current_depth..path_parts.len() {
        if !current_node.is_tree {
            return Ok(None);
        }

        let target_child_name = path_parts[i];

        match current_node.load_tree_with_encryption(backup_set_path, keyset) {
            Ok(Some(mut tree)) => {
                debug_eprintln!(
                    "DEBUG: find_node_in_record_tree: Depth: {}, Target: '{}', Children: {:?}",
                    i,
                    target_child_name,
                    tree.nodes.keys()
                );

                if let Some(child_node) = tree.nodes.remove(target_child_name) {
                    current_node = std::borrow::Cow::Owned(child_node);
                } else {
                    return Ok(None);
                }
            }
            Ok(None) => {
                let current_path_segment = if i > 0 { path_parts[i - 1] } else { "root" };
                return Err(Error::Generic(format!(
                    "Node was expected to be a tree with loadable data, but found none for path part: {}",
                    current_path_segment
                )));
            }
            Err(e) => {
                return Err(Error::ArqError(e)); // Directly use ArqError
            }
        }
    }

    Ok(Some(current_node))
}

pub fn list_backup_records(backup_set_path: &Path) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    println!("Arq 7 Backup Records:");
    println!("---------------------");

    debug_eprintln!("DEBUG: All loaded backup_folder_configs:");
    for (uuid, config) in &backup_set.backup_folder_configs {
        debug_eprintln!(
            "  UUID: {}, Name: {}, LocalPath: {}",
            uuid,
            config.name,
            config.local_path
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

        debug_eprintln!(
            "DEBUG: list_backup_records: Processing folder_uuid: {}, Retrieved local_path: {}",
            folder_uuid,
            folder_local_path
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
                    let timestamp_str = record
                        .creation_date
                        .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
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
                    let timestamp_str = record
                        .creation_date
                        .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
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

pub fn list_files(
    backup_set_path: &Path,
    record_identifier: Option<&str>,
    folder_path_in_backup: Option<&str>,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    let records_to_process: Vec<&arq::arq7::Arq7BackupRecord> =
        if let Some(identifier) = record_identifier {
            find_record_by_identifier(&backup_set, identifier)?
                .map(|r| vec![r])
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "Record with identifier '{}' not found.",
                        identifier
                    ))
                })?
        } else {
            backup_set
                .backup_records
                .values()
                .flatten()
                .filter_map(|gen_rec| match gen_rec {
                    arq::arq7::GenericBackupRecord::Arq7(r) => Some(r),
                    _ => None,
                })
                .collect()
        };

    if records_to_process.is_empty() {
        println!("No matching Arq7 records found.");
        return Ok(());
    }

    for arq7_record in records_to_process {
        let timestamp_str = arq7_record
            .creation_date
            .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
        println!("\nRecord: {}", timestamp_str);

        let path_parts: Vec<&str> = folder_path_in_backup
            .unwrap_or("")
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let start_node =
            find_node_in_record_tree(&arq7_record.node, &path_parts, 0, backup_set_path, keyset)?
                .map(|c| c.into_owned())
                .ok_or_else(|| {
                    Error::NotFound(format!(
                        "Folder '{}' not found in record '{}'.",
                        folder_path_in_backup.unwrap_or("/"),
                        timestamp_str
                    ))
                })?;

        if !start_node.is_tree {
            return Err(Error::Generic(format!(
                "Path '{}' points to a file, not a directory.",
                folder_path_in_backup.unwrap_or("/")
            )));
        }

        list_node_contents_recursive(&start_node, backup_set_path, keyset, 0)?;
    }

    Ok(())
}

fn list_node_contents_recursive(
    node: &Node,
    backup_set_path: &Path,
    keyset: Option<&EncryptedKeySet>,
    depth: usize,
) -> Result<()> {
    if !node.is_tree {
        return Ok(());
    }

    match node.load_tree_with_encryption(backup_set_path, keyset) {
        Ok(Some(tree)) => {
            for (child_name, child_node) in &tree.nodes {
                let indent = "  ".repeat(depth);
                let entry_type = if child_node.is_tree { "D" } else { "F" };
                println!(
                    "{} - {} {} ({} bytes)",
                    indent, entry_type, child_name, child_node.item_size
                );
                if child_node.is_tree {
                    list_node_contents_recursive(child_node, backup_set_path, keyset, depth + 1)?;
                }
            }
        }
        Ok(None) => {
            debug_eprintln!("Warning: Node is a tree but has no loadable tree data.");
        }
        Err(e) => {
            debug_eprintln!("Error loading tree: {}", e);
        }
    }

    Ok(())
}

fn list_versions_internal(
    backup_set_path: &Path,
    path_in_backup: &str,
    is_folder: bool,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();
    let type_str = if is_folder { "folder" } else { "file" };
    println!("Versions for {}: {}", type_str, path_in_backup);
    if is_folder {
        println!("--------------------------------------");
    } else {
        println!("------------------------------------");
    }

    let mut found_versions = 0;

    let results: Vec<_> = backup_set
        .backup_records
        .par_iter()
        .flat_map(|(uuid, vec)| vec.par_iter().map(move |rec| (uuid, rec)))
        .map(|(folder_uuid, gen_record)| {
            let mut output_lines: Vec<String> = Vec::new();
            let mut found = false;
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    let record_local_path_str = record_root_path(
                        &backup_set,
                        folder_uuid,
                        record.local_path.as_deref(),
                    );
                    let effective_path_parts = match folder_parts(path_in_backup, record_local_path_str) {
                        Ok(Some(parts)) if is_folder || !parts.is_empty() => parts,
                        Ok(_) => return (output_lines, found),
                        Err(error) => {
                            output_lines.push(format!("DEBUG: Invalid backup path: {}", error));
                            return (output_lines, found);
                        }
                    };

                    match find_node_in_record_tree(
                        &record.node,
                        &effective_path_parts,
                        0,
                        backup_set_path,
                        keyset,
                    ) {
                        Ok(Some(node_cow)) if node_cow.is_tree == is_folder => {
                            let node = node_cow.as_ref();
                            if !is_folder {
                                debug_eprintln!(
                                    "DEBUG list_file_versions: Found file node: {:?}, size: {}",
                                    node.data_blob_locs.first().map(|b| &b.blob_identifier),
                                    node.item_size
                                );
                            }
                            let timestamp_str = record
                                .creation_date
                                .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
                            if is_folder {
                                output_lines.push(format!(
                                    "  - Record Timestamp: {} (Arq7, Raw: {:?}), Items: ~{}, Modified: {}",
                                    timestamp_str,
                                    record.creation_date.unwrap_or(0.0),
                                    node.contained_files_count.unwrap_or(0),
                                    format_epoch_secs(node.modification_time_sec),
                                ));
                            } else {
                                output_lines.push(format!(
                                    "  - Record Timestamp: {} (Arq7, Raw: {:?}), Size: {} bytes, Modified: {}",
                                    timestamp_str,
                                    record.creation_date.unwrap_or(0.0),
                                    node.item_size,
                                    format_epoch_secs(node.modification_time_sec),
                                ));
                            }
                            found = true;
                        }
                        Ok(_) => {}
                        Err(e) => {
                            output_lines.push(format!(
                                "DEBUG: Warning: Error processing Arq7 record {:?}: {}",
                                record.creation_date,
                                e
                            ));
                        }
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    let timestamp_str = record
                        .creation_date
                        .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
                    let info_not_supported = if is_folder {
                        "detailed folder version info not supported"
                    } else {
                        "detailed file version info not supported"
                    };
                    output_lines.push(format!(
                        "  - Record Timestamp: {} (Arq5, Raw: {:?})\n    (Arq5 record - {})",
                        timestamp_str,
                        record.creation_date.unwrap_or(0.0),
                        info_not_supported
                    ));
                    found = true;
                }
            }
        (output_lines, found)
    }).collect();

    for (lines, found) in results {
        for line in lines {
            if line.starts_with("DEBUG:") {
                debug_eprintln!("{}", line.trim_start_matches("DEBUG: ").trim());
            } else {
                println!("{}", line);
            }
        }
        if found {
            found_versions += 1;
        }
    }

    if found_versions == 0 {
        if is_folder {
            println!("No versions found for this folder.");
        } else {
            println!("No versions found for this file."); // Reverted to expect "file"
        }
    }
    Ok(())
}

pub fn list_file_versions(backup_set_path: &Path, file_path_in_backup: &str) -> Result<()> {
    list_versions_internal(backup_set_path, file_path_in_backup, false)
}

/// Resolve exact absolute paths against the historical record root, or relative
/// paths against every root. A current folder config is only a missing-root fallback.
fn folder_parts<'a>(target: &'a str, root: &str) -> Result<Option<Vec<&'a str>>> {
    let parts: Vec<_> = target.split('/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == "." || *p == "..") {
        return Err(Error::CliInputError(
            "Folder paths cannot contain . or ..".into(),
        ));
    }
    if target.is_empty() || target == "/" {
        return Ok(Some(Vec::new()));
    }
    if target.starts_with('/') && !root.is_empty() {
        let root_parts: Vec<_> = root.split('/').filter(|p| !p.is_empty()).collect();
        if !parts.starts_with(&root_parts) {
            return Ok(None);
        }
        return Ok(Some(parts[root_parts.len()..].to_vec()));
    }
    Ok(Some(parts))
}

struct FolderVersion {
    folder_uuid: String,
    timestamp: String,
    directory: String,
    local_path: String,
    complete: bool,
    backup_errors: usize,
    node: Node,
}

fn record_root_path<'a>(
    set: &'a BackupSet,
    folder_uuid: &str,
    record_root: Option<&'a str>,
) -> &'a str {
    record_root
        .filter(|path| !path.is_empty())
        .or_else(|| {
            set.backup_folder_configs
                .get(folder_uuid)
                .map(|config| config.local_path.as_str())
        })
        .unwrap_or("")
}

fn query_folder_versions(set: &BackupSet, target: &str) -> Result<Vec<FolderVersion>> {
    folder_parts(target, "")?;
    let mut folders: Vec<_> = set.backup_records.iter().collect();
    folders.sort_by_key(|(uuid, _)| *uuid);
    let mut versions = Vec::new();
    for (uuid, records) in folders {
        for record in records {
            let record = match record {
                arq::arq7::GenericBackupRecord::Arq7(record) => record,
                arq::arq7::GenericBackupRecord::Arq5(_) => return Err(Error::Generic(
                    "Folder history contains imported Arq 5 records, which cannot yet be queried or restored; refusing an incomplete result".into())),
            };
            let root = record_root_path(set, uuid, record.local_path.as_deref());
            let Some(parts) = folder_parts(target, root)? else {
                continue;
            };
            let node = find_node_in_record_tree(
                &record.node,
                &parts,
                0,
                &set.root_path,
                set.encryption_keyset(),
            )
            .map_err(|e| {
                Error::Generic(format!(
                    "Cannot query folder {} record {:?}: {}",
                    uuid, record.creation_date, e
                ))
            })?;
            if let Some(node) = node.filter(|n| n.is_tree) {
                let timestamp = record
                    .creation_date
                    .map(format_timestamp_rfc3339)
                    .unwrap_or_else(|| "unknown_timestamp".into());
                versions.push(FolderVersion {
                    folder_uuid: uuid.clone(),
                    timestamp: timestamp.clone(),
                    directory: timestamp,
                    local_path: root.into(),
                    complete: record.is_complete.unwrap_or(false),
                    backup_errors: record.backup_record_errors.as_ref().map_or(0, |e| e.len()),
                    node: node.into_owned(),
                });
            }
        }
    }
    // Never let records sharing a timestamp share an output directory.
    let mut counts = std::collections::HashMap::new();
    for version in &versions {
        *counts.entry(version.timestamp.clone()).or_insert(0usize) += 1;
    }
    for (index, version) in versions.iter_mut().enumerate() {
        if counts[&version.timestamp] > 1 {
            version.directory = format!("{}__record_{}", version.timestamp, index + 1);
        }
    }
    Ok(versions)
}

pub fn list_folder_versions(backup_set_path: &Path, folder_path_in_backup: &str) -> Result<()> {
    let set = load_backup_set(backup_set_path)?;
    let versions = query_folder_versions(&set, folder_path_in_backup)?;
    println!("Versions for folder: {}", folder_path_in_backup);
    for v in &versions {
        println!(
            "  - Record Timestamp: {}, Folder UUID: {}, Source: {}, Items: ~{}, Complete: {}, Backup errors: {}, Output: {}",
            v.timestamp,
            v.folder_uuid,
            v.local_path,
            v.node.contained_files_count.unwrap_or(0),
            v.complete,
            v.backup_errors,
            v.directory
        );
    }
    if versions.is_empty() {
        println!("No versions found for this folder.");
    } else {
        println!(
            "Found {} folder versions (one per matching record).",
            versions.len()
        );
    }
    Ok(())
}

/// Reject output paths inside the backup and resolve symlinked existing parents
/// before creating any files. This prevents a restore from modifying backup data.
fn ensure_output_outside_backup(backup_set_path: &Path, output_path: &Path) -> Result<()> {
    let absolute_output = if output_path.is_absolute() {
        output_path.to_path_buf()
    } else {
        std::env::current_dir()?.join(output_path)
    };
    if absolute_output
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::CliInputError(
            "Restore destination cannot contain ..".into(),
        ));
    }

    let mut existing_parent = absolute_output.as_path();
    while !existing_parent.try_exists()? {
        existing_parent = existing_parent
            .parent()
            .ok_or_else(|| Error::Generic("Cannot resolve restore destination".into()))?;
    }
    let resolved_parent = std::fs::canonicalize(existing_parent)?;
    let resolved_backup = std::fs::canonicalize(backup_set_path)?;
    if resolved_parent.starts_with(resolved_backup) {
        return Err(Error::Generic(
            "Restore destination must be outside the backup set".into(),
        ));
    }
    Ok(())
}

fn reject_existing_output(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Generic(format!(
            "Restore destination already exists: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::IoError(error)),
    }
}

pub fn restore_full_record(
    backup_set_path: &Path,
    record_identifier: &str,
    destination: &Path,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    if destination.exists() && !destination.is_dir() {
        return Err(Error::Generic(format!(
            "Destination '{}' is not a directory.",
            destination.display()
        )));
    }

    match find_record_by_identifier(&backup_set, record_identifier)? {
        Some(arq7_record) => {
            let timestamp_str = arq7_record
                .creation_date
                .map_or_else(|| record_identifier.to_string(), record_timestamp_dir_name);
            let record_dest_name = format!("record_{}", timestamp_str);
            let final_destination = destination.join(record_dest_name);
            ensure_output_outside_backup(backup_set_path, &final_destination)?;
            reject_existing_output(&final_destination)?;
            std::fs::create_dir_all(&final_destination)?;

            println!(
                "Restoring record (Timestamp: {}) to {}...",
                timestamp_str,
                final_destination.display()
            );

            let mut stats = ExtractionStats::default();
            let mut ctx = ExtractionContext {
                backup_set_path,
                keyset,
                stats: &mut stats,
            };
            extract_node_to_destination_recursive(
                &arq7_record.node, // Access node from arq7_record
                &final_destination,
                "",
                &mut ctx,
            )?;
            println!(
                "Successfully restored record. Files: {}, Dirs: {}, Total Size: {} bytes.",
                stats.files_restored, stats.dirs_created, stats.bytes_restored
            );
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
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier)?.ok_or_else(|| {
            Error::NotFound(format!(
                "Record with identifier '{}' not found.",
                record_identifier
            ))
        })?;

    let record_local_path = record_root_path(
        &backup_set,
        &arq7_record.backup_folder_uuid,
        arq7_record.local_path.as_deref(),
    );
    let effective_path_parts = folder_parts(file_path_in_backup, record_local_path)?
        .filter(|parts| !parts.is_empty())
        .ok_or_else(|| {
            Error::NotFound(format!(
                "File path '{}' is outside the record source root '{}'",
                file_path_in_backup, record_local_path
            ))
        })?;

    let target_node = find_node_in_record_tree(
        &arq7_record.node,
        &effective_path_parts,
        0,
        backup_set_path,
        keyset,
    )?
    .map(|c| c.into_owned())
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

    ensure_output_outside_backup(backup_set_path, &output_path)?;
    reject_existing_output(&output_path)?;
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    println!(
        "Restoring file '{}' from record (Timestamp: {:?}) to {}...",
        file_path_in_backup,
        arq7_record.creation_date,
        output_path.display()
    );
    let file_data = target_node.reconstruct_file_data_with_encryption(backup_set_path, keyset)?;
    if file_data.len() as u64 != target_node.item_size {
        return Err(Error::Generic(format!(
            "Restored size mismatch: expected {} bytes, got {}",
            target_node.item_size,
            file_data.len()
        )));
    }
    use std::io::Write;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    output.write_all(&file_data)?;
    filetime::set_file_mtime(
        &output_path,
        filetime::FileTime::from_unix_time(target_node.modification_time_sec, 0),
    )?;

    println!("Successfully restored file to {}.", output_path.display());
    Ok(())
}

pub fn restore_specific_folder_from_record(
    backup_set_path: &Path,
    record_identifier: &str,
    folder_path_in_backup: &str,
    destination: &Path,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier)?.ok_or_else(|| {
            Error::NotFound(format!(
                "Record with identifier '{}' not found.",
                record_identifier
            ))
        })?;

    let record_local_path = record_root_path(
        &backup_set,
        &arq7_record.backup_folder_uuid,
        arq7_record.local_path.as_deref(),
    );
    let effective_path_parts =
        folder_parts(folder_path_in_backup, record_local_path)?.ok_or_else(|| {
            Error::NotFound(format!(
                "Folder path '{}' is outside the record source root '{}'",
                folder_path_in_backup, record_local_path
            ))
        })?;

    let target_node = find_node_in_record_tree(
        &arq7_record.node,
        &effective_path_parts,
        0,
        backup_set_path,
        keyset,
    )?
    .map(|c| c.into_owned())
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

    let base_folder_name = effective_path_parts.last().map_or("root_content", |n| *n);
    let final_destination_for_folder_content = destination.join(base_folder_name);
    ensure_output_outside_backup(backup_set_path, &final_destination_for_folder_content)?;
    reject_existing_output(&final_destination_for_folder_content)?;
    if destination.exists() && !destination.is_dir() {
        return Err(Error::Generic(format!(
            "Destination '{}' is not a directory.",
            destination.display()
        )));
    }

    std::fs::create_dir_all(&final_destination_for_folder_content)?;

    println!(
        "Restoring folder '{}' from record (Timestamp: {:?}) to {}...",
        folder_path_in_backup,
        arq7_record.creation_date,
        final_destination_for_folder_content.display()
    );

    let mut stats = ExtractionStats::default();
    let mut ctx = ExtractionContext {
        backup_set_path,
        keyset,
        stats: &mut stats,
    };
    extract_node_to_destination_recursive(
        &target_node,
        &final_destination_for_folder_content,
        "",
        &mut ctx,
    )?;

    println!(
        "Successfully restored folder. Files: {}, Dirs: {}, Total Size: {} bytes.",
        stats.files_restored, stats.dirs_created, stats.bytes_restored
    );
    Ok(())
}

pub fn restore_all_folder_versions(
    backup_set_path: &Path,
    folder_path_in_backup: &str,
    destination_root: &Path,
) -> Result<()> {
    let set = load_backup_set(backup_set_path)?;
    // Finish discovery before writing anything, including detecting unreadable records.
    let versions = query_folder_versions(&set, folder_path_in_backup)?;
    if versions.is_empty() {
        return Err(Error::NotFound(format!(
            "No versions of folder '{}' found to restore.",
            folder_path_in_backup
        )));
    }
    ensure_output_outside_backup(backup_set_path, destination_root)?;
    std::fs::create_dir_all(destination_root)?;
    for v in &versions {
        if std::fs::symlink_metadata(destination_root.join(&v.directory)).is_ok() {
            return Err(Error::Generic(format!(
                "Restore destination already exists: {}",
                destination_root.join(&v.directory).display()
            )));
        }
    }
    println!(
        "Restoring all versions of folder '{}' to root '{}'",
        folder_path_in_backup,
        destination_root.display()
    );
    for v in &versions {
        let version_dir = destination_root.join(&v.directory);
        std::fs::create_dir(&version_dir)?;
        let folder_name = folder_path_in_backup
            .split('/')
            .filter(|s| !s.is_empty())
            .last()
            .unwrap_or("root_content");
        let content_dir = version_dir.join(folder_name);
        let manifest = serde_json::json!({
            "folder": folder_path_in_backup, "folder_uuid": v.folder_uuid,
            "source_root": v.local_path, "timestamp": v.timestamp,
            "backup_complete": v.complete, "backup_errors": v.backup_errors,
            "status": "in_progress"
        });
        // A backed-up folder may itself be named restore.json.
        let manifest_path = version_dir.join(if folder_name == "restore.json" {
            "restore-manifest.json"
        } else {
            "restore.json"
        });
        std::fs::write(&manifest_path, manifest.to_string())?;
        println!(
            "  Restoring version from record (Timestamp: {}) to {}...",
            v.timestamp,
            content_dir.display()
        );
        let mut stats = ExtractionStats::default();
        let result = extract_node_to_destination_recursive(
            &v.node,
            &content_dir,
            "",
            &mut ExtractionContext {
                backup_set_path,
                keyset: set.encryption_keyset(),
                stats: &mut stats,
            },
        );
        let mut manifest = manifest;
        manifest["status"] = serde_json::json!(if result.is_ok() { "complete" } else { "failed" });
        manifest["files_restored"] = serde_json::json!(stats.files_restored);
        manifest["bytes_restored"] = serde_json::json!(stats.bytes_restored);
        if let Err(ref e) = result {
            manifest["error"] = serde_json::json!(e.to_string());
        }
        std::fs::write(manifest_path, manifest.to_string())?;
        result?;
    }
    println!(
        "Finished restoring {} versions of folder '{}'.",
        versions.len(),
        folder_path_in_backup
    );
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct ExtractionStats {
    files_restored: usize,
    dirs_created: usize,
    bytes_restored: u64,
}

struct ExtractionContext<'a> {
    backup_set_path: &'a Path,
    keyset: Option<&'a EncryptedKeySet>,
    stats: &'a mut ExtractionStats,
}

fn extract_node_to_destination_recursive(
    node: &Node,
    current_materialized_path: &Path,
    relative_path_for_node: &str,
    ctx: &mut ExtractionContext<'_>,
) -> Result<()> {
    let node_output_path = if relative_path_for_node.is_empty() {
        current_materialized_path.to_path_buf()
    } else {
        let mut components = Path::new(relative_path_for_node).components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            return Err(Error::Generic(format!(
                "Unsafe backup entry name: {:?}",
                relative_path_for_node
            )));
        }
        current_materialized_path.join(relative_path_for_node)
    };

    if node.is_tree {
        if let Ok(metadata) = std::fs::symlink_metadata(&node_output_path) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(Error::Generic(format!(
                    "Unsafe destination directory: {}",
                    node_output_path.display()
                )));
            }
        }
        if !node_output_path.exists() {
            std::fs::create_dir_all(&node_output_path).map_err(Error::IoError)?;
            ctx.stats.dirs_created += 1;
        }

        let tree = node
            .load_tree_with_encryption(ctx.backup_set_path, ctx.keyset)?
            .ok_or_else(|| {
                Error::Generic(format!(
                    "Missing tree data for {}",
                    node_output_path.display()
                ))
            })?;
        for (child_name, child_node) in &tree.nodes {
            extract_node_to_destination_recursive(child_node, &node_output_path, child_name, ctx)?;
        }
    } else {
        if let Some(parent_dir) = node_output_path.parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir).map_err(Error::IoError)?;
            }
        }

        let file_data =
            node.reconstruct_file_data_with_encryption(ctx.backup_set_path, ctx.keyset)?;
        if file_data.len() as u64 != node.item_size {
            return Err(Error::Generic(format!(
                "Restored size mismatch for {}: expected {}, got {}",
                node_output_path.display(),
                node.item_size,
                file_data.len()
            )));
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&node_output_path)?;
        file.write_all(&file_data)?;
        ctx.stats.files_restored += 1;
        ctx.stats.bytes_restored += file_data.len() as u64;
        filetime::set_file_mtime(
            &node_output_path,
            filetime::FileTime::from_unix_time(node.modification_time_sec, 0),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_paths_are_component_aware() {
        assert_eq!(folder_parts("/Photos-old/sub", "/Photos").unwrap(), None);
        assert_eq!(
            folder_parts("/Photos/sub/", "/Photos/").unwrap(),
            Some(vec!["sub"])
        );
        assert_eq!(
            folder_parts("sub/nested", "/Photos").unwrap(),
            Some(vec!["sub", "nested"])
        );
        assert_eq!(folder_parts("/Photos", "/Photos").unwrap(), Some(vec![]));
        assert_eq!(folder_parts("/", "/Photos").unwrap(), Some(vec![]));
        assert!(folder_parts("sub/../other", "").is_err());
    }

    #[test]
    fn duplicate_timestamps_have_distinct_destinations() {
        let mut set = BackupSet::from_directory_with_password(
            "../arq/tests/arq_storage_location/2E7BB0B6-BE5B-4A86-9E51-10FE730E1104",
            None,
        )
        .unwrap();
        let records = set.backup_records.values_mut().next().unwrap();
        records.push(records[0].clone());
        let versions = query_folder_versions(&set, "subfolder").unwrap();
        assert_eq!(versions.len(), 2);
        assert_ne!(versions[0].directory, versions[1].directory);
    }

    #[test]
    fn test_record_timestamp_dir_name() {
        // Whole integer timestamps
        assert_eq!(record_timestamp_dir_name(10.0), "10");
        assert_eq!(record_timestamp_dir_name(0.0), "0");

        // Fractional timestamps
        assert_eq!(record_timestamp_dir_name(10.5), "10.5");
        assert_eq!(record_timestamp_dir_name(12345.678), "12345.678");

        // Fractional part within epsilon
        let near_ten = 10.0 + (f64::EPSILON / 2.0);
        assert_eq!(record_timestamp_dir_name(near_ten), "10");

        // Negative values
        assert_eq!(record_timestamp_dir_name(-10.0), "-10");
        assert_eq!(record_timestamp_dir_name(-10.5), "-10.5");

        // NaN and Infinity
        assert_eq!(record_timestamp_dir_name(f64::NAN), "NaN");
        assert_eq!(record_timestamp_dir_name(f64::INFINITY), "inf");
        assert_eq!(record_timestamp_dir_name(f64::NEG_INFINITY), "-inf");
    }

    #[test]
    fn test_format_epoch_secs() {
        // Known epoch 0
        assert_eq!(format_epoch_secs(0), "1970-01-01 00:00:00");

        // Known positive epoch
        assert_eq!(format_epoch_secs(1700000000), "2023-11-14 22:13:20");

        // Known negative epoch (1 day before epoch)
        assert_eq!(format_epoch_secs(-86400), "1969-12-31 00:00:00");

        // Out of bounds / invalid epoch that triggers the unwrap_or_else fallback
        // i64::MAX is valid i64 but beyond valid DateTime bounds usually
        assert_eq!(format_epoch_secs(i64::MAX), i64::MAX.to_string());
    }

    #[test]
    fn test_format_timestamp_rfc3339() {
        // Standard epoch: 1970-01-01T00:00:00+00:00
        assert_eq!(format_timestamp_rfc3339(0.0), "1970-01-01T00:00:00+00:00");

        // Positive timestamp without fractions: 2023-01-01T00:00:00+00:00
        // 1672531200
        assert_eq!(
            format_timestamp_rfc3339(1672531200.0),
            "2023-01-01T00:00:00+00:00"
        );

        // Positive timestamp with fractional seconds
        // 1672531200.5
        assert_eq!(
            format_timestamp_rfc3339(1672531200.5),
            "2023-01-01T00:00:00.500+00:00"
        );

        // Negative timestamp (before 1970)
        // -31536000 (1969-01-01T00:00:00+00:00)
        assert_eq!(
            format_timestamp_rfc3339(-31536000.0),
            "1969-01-01T00:00:00+00:00"
        );

        // Extreme out-of-bounds timestamps (fallback to string representation)
        // chrono::DateTime limits seconds to i64 limits in naive date time but may reject very large f64
        // Let's test f64::MAX which is definitely out of bounds.
        assert_eq!(
            format_timestamp_rfc3339(std::f64::MAX),
            std::f64::MAX.to_string()
        );
    }
}
