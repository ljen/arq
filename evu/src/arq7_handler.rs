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
) -> Option<&'a arq::arq7::Arq7BackupRecord> {
    for records_vec in backup_set.backup_records.values() {
        for gen_record in records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(arq7_record) => {
                    if let Some(creation_date_val) = arq7_record.creation_date {
                        if timestamp_identifier_matches(creation_date_val, identifier) {
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
                        if timestamp_identifier_matches(creation_date_val, identifier) {
                            // Cannot return arq5_record as Arq7BackupRecord.
                            // This function is now specific to finding Arq7 records.
                        }
                    }
                }
            }
        }
    }
    None
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
            find_record_by_identifier(&backup_set, identifier)
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

fn get_effective_path_parts<'a>(
    target_path: &'a str,
    record_local_path: &str,
    folder_uuid: &str,
    backup_set: &arq::arq7::BackupSet,
    default_parts: &'a [&'a str],
    is_folder: bool,
) -> std::borrow::Cow<'a, [&'a str]> {
    let mut effective_path_parts = std::borrow::Cow::Borrowed(default_parts);

    if is_folder && (target_path == "/" || target_path.is_empty()) {
        effective_path_parts = std::borrow::Cow::Borrowed(&[]);
    } else if !record_local_path.is_empty() && target_path.starts_with(record_local_path) {
        let relative_path = target_path
            .strip_prefix(record_local_path)
            .unwrap_or(target_path);
        let relative_path_trimmed = relative_path.trim_start_matches('/');
        let mut temp_parts: Vec<&str> = relative_path_trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if is_folder {
            if relative_path_trimmed.is_empty() && !relative_path.is_empty() && target_path != "/" {
                temp_parts = Vec::new();
            }
        } else {
            if temp_parts.is_empty() && !relative_path_trimmed.is_empty() {
                temp_parts = vec![relative_path_trimmed];
            }
        }
        effective_path_parts = std::borrow::Cow::Owned(temp_parts);
    } else if record_local_path.is_empty() {
        if let Some(bf_config) = backup_set.backup_folder_configs.get(folder_uuid) {
            if target_path.starts_with(&bf_config.local_path) {
                let relative_path = target_path
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(target_path);
                let relative_path_trimmed = relative_path.trim_start_matches('/');
                let mut temp_parts: Vec<&str> = relative_path_trimmed
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();

                if is_folder {
                    if relative_path_trimmed.is_empty()
                        && !relative_path.is_empty()
                        && target_path != "/"
                    {
                        temp_parts = Vec::new();
                    }
                } else {
                    if temp_parts.is_empty() && !relative_path_trimmed.is_empty() {
                        temp_parts = vec![relative_path_trimmed];
                    }
                }
                effective_path_parts = std::borrow::Cow::Owned(temp_parts);
            }
        }
    }

    effective_path_parts
}

fn process_arq7_record(
    record: &arq::arq7::Arq7BackupRecord,
    effective_path_parts: &[&str],
    backup_set_path: &Path,
    keyset: Option<&arq::arq7::EncryptedKeySet>,
    is_folder: bool,
) -> (Vec<String>, bool) {
    let mut output_lines = Vec::new();
    let mut found = false;

    match find_node_in_record_tree(
        &record.node,
        effective_path_parts,
        0,
        backup_set_path,
        keyset,
    ) {
        Ok(Some(node_cow)) => {
            let node = node_cow.as_ref();
            if is_folder {
                if node.is_tree {
                    let timestamp_str = record
                        .creation_date
                        .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
                    output_lines.push(format!(
                        "  - Record Timestamp: {} (Arq7, Raw: {:?}), Items: ~{}, Modified: {}",
                        timestamp_str,
                        record.creation_date.unwrap_or(0.0),
                        node.contained_files_count.unwrap_or(0),
                        format_epoch_secs(node.modification_time_sec),
                    ));
                    found = true;
                }
            } else {
                if !node.is_tree {
                    debug_eprintln!(
                        "DEBUG list_file_versions: Found file node: {:?}, size: {}",
                        node.data_blob_locs.first().map(|b| &b.blob_identifier),
                        node.item_size
                    );
                    let timestamp_str = record
                        .creation_date
                        .map_or_else(|| "Unknown Timestamp".to_string(), format_timestamp);
                    output_lines.push(format!(
                        "  - Record Timestamp: {} (Arq7, Raw: {:?}), Size: {} bytes, Modified: {}",
                        timestamp_str,
                        record.creation_date.unwrap_or(0.0),
                        node.item_size,
                        format_epoch_secs(node.modification_time_sec),
                    ));
                    found = true;
                }
            }
        }
        Ok(None) => {
            output_lines.push("DEBUG: Node not found in record".to_string());
        }
        Err(e) => {
            output_lines.push(format!(
                "DEBUG: Warning: Error processing Arq7 record {:?}: {}",
                record.creation_date, e
            ));
        }
    }

    (output_lines, found)
}

fn print_versions(results: Vec<(Vec<String>, bool)>, item_name: &str) {
    let mut found_versions = 0;
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
        println!("No versions found for this {}.", item_name);
    }
}

fn adjust_path_parts<'a>(
    path_in_backup: &'a str,
    path_parts: &'a [&'a str],
    record_local_path_str: &str,
    folder_uuid: &str,
    backup_set: &arq::arq7::BackupSet,
    is_folder: bool,
) -> std::borrow::Cow<'a, [&'a str]> {
    let mut effective_path_parts = std::borrow::Cow::Borrowed(path_parts);

    if is_folder && (path_in_backup == "/" || path_in_backup.is_empty()) {
        return std::borrow::Cow::Borrowed(&[]);
    }

    let mut handled = false;
    if !record_local_path_str.is_empty() && path_in_backup.starts_with(record_local_path_str) {
        let relative_path = path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(path_in_backup);
        let relative_path_trimmed = relative_path.trim_start_matches('/');
        let mut temp_parts: Vec<&str> = relative_path_trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        if is_folder
            && relative_path_trimmed.is_empty()
            && !relative_path.is_empty()
            && path_in_backup != "/"
        {
            temp_parts = Vec::new();
        } else if !is_folder && temp_parts.is_empty() && !relative_path_trimmed.is_empty() {
            temp_parts = vec![relative_path_trimmed];
        }
        effective_path_parts = std::borrow::Cow::Owned(temp_parts);
        handled = true;
    }

    if !handled {
        if let Some(bf_config) = backup_set.backup_folder_configs.get(folder_uuid) {
            if path_in_backup.starts_with(&bf_config.local_path) {
                let relative_path = path_in_backup
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(path_in_backup);
                let relative_path_trimmed = relative_path.trim_start_matches('/');
                let mut temp_parts: Vec<&str> = relative_path_trimmed
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if is_folder
                    && relative_path_trimmed.is_empty()
                    && !relative_path.is_empty()
                    && path_in_backup != "/"
                {
                    temp_parts = Vec::new();
                } else if !is_folder && temp_parts.is_empty() && !relative_path_trimmed.is_empty() {
                    temp_parts = vec![relative_path_trimmed];
                }
                effective_path_parts = std::borrow::Cow::Owned(temp_parts);
                handled = true;
            }
        }
    }

    if !handled
        && (!record_local_path_str.is_empty()
            || backup_set.backup_folder_configs.get(folder_uuid).is_some())
    {
        if !is_folder {
            effective_path_parts = std::borrow::Cow::Owned(Vec::new());
        } else {
            effective_path_parts = std::borrow::Cow::Owned(vec!["__arq_internal_no_match__"]);
        }
    }

    effective_path_parts
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

    let path_parts: Vec<&str> = path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    if !is_folder && path_parts.is_empty() {
        return Err(Error::Generic("File path cannot be empty".to_string()));
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
                    let record_local_path_str = record.local_path.as_deref().unwrap_or("");

                    if is_folder {
                        debug_eprintln!(
                            "DEBUG list_folder_versions: Folder: '{}', Record LocalPath: '{}'",
                            path_in_backup,
                            record_local_path_str
                        );
                    }

                    let effective_path_parts = adjust_path_parts(
                        path_in_backup,
                        &path_parts,
                        record_local_path_str,
                        folder_uuid,
                        &backup_set,
                        is_folder,
                    );

                    if !is_folder && effective_path_parts.is_empty() {
                        return (output_lines, found);
                    }

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

pub fn list_folder_versions(backup_set_path: &Path, folder_path_in_backup: &str) -> Result<()> {
    list_versions_internal(backup_set_path, folder_path_in_backup, true)
}

pub fn restore_full_record(
    backup_set_path: &Path,
    record_identifier: &str,
    destination: &Path,
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
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
            let timestamp_str = arq7_record
                .creation_date
                .map_or_else(|| record_identifier.to_string(), record_timestamp_dir_name);
            let record_dest_name = format!("record_{}", timestamp_str);
            let final_destination = destination.join(record_dest_name);
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
                "Successfully restored record. Files: {}, Dirs: {}, Total Size: {} bytes. Errors: {}",
                stats.files_restored, stats.dirs_created, stats.bytes_restored, stats.errors
            );
            if stats.errors > 0 {
                debug_eprintln!(
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
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier).ok_or_else(|| {
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

    let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or("");
    let mut effective_path_parts = std::borrow::Cow::Borrowed(path_parts.as_slice());
    let mut handled = false;

    if !record_local_path_str.is_empty() && file_path_in_backup.starts_with(record_local_path_str) {
        let relative_file_path = file_path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(file_path_in_backup);
        let relative_file_path_trimmed = relative_file_path.trim_start_matches('/');
        let mut temp_parts: Vec<&str> = relative_file_path_trimmed
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if temp_parts.is_empty() && !relative_file_path_trimmed.is_empty() {
            temp_parts = vec![relative_file_path_trimmed];
        }
        effective_path_parts = std::borrow::Cow::Owned(temp_parts);
        handled = true;
    }

    if !handled {
        if let Some(bf_config) = backup_set
            .backup_folder_configs
            .get(&arq7_record.backup_folder_uuid)
        {
            if file_path_in_backup.starts_with(&bf_config.local_path) {
                let relative_file_path = file_path_in_backup
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(file_path_in_backup);
                let relative_file_path_trimmed = relative_file_path.trim_start_matches('/');
                let mut temp_parts: Vec<&str> = relative_file_path_trimmed
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if temp_parts.is_empty() && !relative_file_path_trimmed.is_empty() {
                    temp_parts = vec![relative_file_path_trimmed];
                }
                effective_path_parts = std::borrow::Cow::Owned(temp_parts);
                handled = true;
            }
        }
    }

    if !handled
        && (!record_local_path_str.is_empty()
            || backup_set
                .backup_folder_configs
                .get(&arq7_record.backup_folder_uuid)
                .is_some())
    {
        return Err(Error::NotFound(format!(
            "Adjusted file path is empty for '{}' relative to record's local path '{}'. Cannot restore directory root as a file.",
            file_path_in_backup, record_local_path_str
        )));
    }
    if effective_path_parts.is_empty() {
        return Err(Error::NotFound(format!(
            "Adjusted file path is empty for '{}' relative to record's local path '{}'. Cannot restore directory root as a file.",
            file_path_in_backup, record_local_path_str
        )));
    }

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

    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    println!(
        "Restoring file '{}' from record (Timestamp: {:?}) to {}...",
        file_path_in_backup,
        arq7_record.creation_date,
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
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
    let keyset = backup_set.encryption_keyset();

    let arq7_record =
        find_record_by_identifier(&backup_set, record_identifier).ok_or_else(|| {
            Error::NotFound(format!(
                "Record with identifier '{}' not found.",
                record_identifier
            ))
        })?;

    let path_parts: Vec<&str> = folder_path_in_backup
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let mut effective_path_parts = std::borrow::Cow::Borrowed(path_parts.as_slice());
    let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or("");
    let mut handled = false;

    if folder_path_in_backup == "/" || folder_path_in_backup.is_empty() {
        effective_path_parts = std::borrow::Cow::Borrowed(&[]);
        handled = true;
    } else if !record_local_path_str.is_empty()
        && folder_path_in_backup.starts_with(record_local_path_str)
    {
        let relative_path = folder_path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(folder_path_in_backup);
        let trimmed_relative_path = relative_path.trim_start_matches('/');
        let mut temp_parts: Vec<&str> = trimmed_relative_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if trimmed_relative_path.is_empty()
            && !relative_path.is_empty()
            && folder_path_in_backup != "/"
        {
            temp_parts = Vec::new();
        }
        effective_path_parts = std::borrow::Cow::Owned(temp_parts);
        handled = true;
    }

    if !handled {
        if let Some(bf_config) = backup_set
            .backup_folder_configs
            .get(&arq7_record.backup_folder_uuid)
        {
            if folder_path_in_backup.starts_with(&bf_config.local_path) {
                let relative_path = folder_path_in_backup
                    .strip_prefix(&bf_config.local_path)
                    .unwrap_or(folder_path_in_backup);
                let trimmed_relative_path = relative_path.trim_start_matches('/');
                let mut temp_parts: Vec<&str> = trimmed_relative_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if trimmed_relative_path.is_empty()
                    && !relative_path.is_empty()
                    && folder_path_in_backup != "/"
                {
                    temp_parts = Vec::new();
                }
                effective_path_parts = std::borrow::Cow::Owned(temp_parts);
                handled = true;
            }
        }
    }

    if !handled
        && (!record_local_path_str.is_empty()
            || backup_set
                .backup_folder_configs
                .get(&arq7_record.backup_folder_uuid)
                .is_some())
    {
        return Err(Error::NotFound(format!(
            "Adjusted file path is empty for '{}' relative to record's local path '{}'. Cannot restore directory root as a file.",
            folder_path_in_backup, record_local_path_str
        )));
    }

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
        "Successfully restored folder. Files: {}, Dirs: {}, Total Size: {} bytes. Errors: {}",
        stats.files_restored, stats.dirs_created, stats.bytes_restored, stats.errors
    );
    if stats.errors > 0 {
        debug_eprintln!(
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
) -> Result<()> {
    let backup_set = load_backup_set(backup_set_path)?;
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

    let mut records_to_process = Vec::new();
    let mut ts_idx = 0;
    for (folder_uuid, gen_records_vec) in &backup_set.backup_records {
        for gen_record in gen_records_vec {
            match gen_record {
                arq::arq7::GenericBackupRecord::Arq7(arq7_record) => {
                    let timestamp_str = arq7_record.creation_date.map_or_else(
                        || format!("unknown_ts_{}", ts_idx),
                        format_timestamp_rfc3339,
                    );
                    ts_idx += 1;
                    records_to_process.push((folder_uuid, arq7_record, timestamp_str));
                }
                arq::arq7::GenericBackupRecord::Arq5(_arq5_record) => {
                    debug_eprintln!(
                        "DEBUG restore_all_folder_versions: Skipping Arq5 record for folder version restoration."
                    );
                }
            }
        }
    }

    let versions_restored_count = std::sync::atomic::AtomicUsize::new(0);

    records_to_process.into_par_iter().try_for_each(
        |(folder_uuid, arq7_record, timestamp_str)| -> Result<()> {
            debug_eprintln!(
                "DEBUG: restore_all_folder_versions: Arq7 record timestamp: {}",
                timestamp_str
            );
            let record_local_path_str = arq7_record.local_path.as_deref().unwrap_or("");
            let bf_config_local_path = backup_set
                .backup_folder_configs
                .get(folder_uuid)
                .map(|bf| bf.local_path.as_str());

            let effective_path_parts = resolve_effective_path_parts(
                folder_path_in_backup,
                &path_parts,
                record_local_path_str,
                bf_config_local_path,
            );

            if let Ok(Some(target_node_cow)) = find_node_in_record_tree(
                &arq7_record.node,
                &effective_path_parts,
                0,
                backup_set_path,
                keyset,
            ) {
                restore_version_from_record(
                    target_node_cow.as_ref(),
                    &effective_path_parts,
                    &timestamp_str,
                    destination_root,
                    backup_set_path,
                    keyset,
                    &versions_restored_count,
                )?;
            }
            Ok(())
        },
    )?;

    let final_count = versions_restored_count.load(std::sync::atomic::Ordering::Relaxed);
    if final_count == 0 {
        println!(
            "No versions of folder '{}' found to restore.",
            folder_path_in_backup
        );
    } else {
        println!(
            "Finished restoring {} versions of folder '{}'.",
            final_count, folder_path_in_backup
        );
    }

    Ok(())
}

fn resolve_effective_path_parts<'a>(
    folder_path_in_backup: &'a str,
    path_parts: &'a [&'a str],
    record_local_path_str: &str,
    bf_config_local_path: Option<&str>,
) -> std::borrow::Cow<'a, [&'a str]> {
    let mut effective_path_parts = std::borrow::Cow::Borrowed(path_parts);
    let mut handled = false;

    if folder_path_in_backup == "/" || folder_path_in_backup.is_empty() {
        effective_path_parts = std::borrow::Cow::Borrowed(&[][..]);
        handled = true;
    } else if !record_local_path_str.is_empty()
        && folder_path_in_backup.starts_with(record_local_path_str)
    {
        let relative_path = folder_path_in_backup
            .strip_prefix(record_local_path_str)
            .unwrap_or(folder_path_in_backup);
        let trimmed_relative_path = relative_path.trim_start_matches('/');
        let mut temp_parts: Vec<&str> = trimmed_relative_path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if trimmed_relative_path.is_empty()
            && !relative_path.is_empty()
            && folder_path_in_backup != "/"
        {
            temp_parts = Vec::new();
        }
        effective_path_parts = std::borrow::Cow::Owned(temp_parts);
        handled = true;
    }

    if !handled {
        if let Some(local_path) = bf_config_local_path {
            if folder_path_in_backup.starts_with(local_path) {
                let relative_path = folder_path_in_backup
                    .strip_prefix(local_path)
                    .unwrap_or(folder_path_in_backup);
                let trimmed_relative_path = relative_path.trim_start_matches('/');
                let mut temp_parts: Vec<&str> = trimmed_relative_path
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .collect();
                if trimmed_relative_path.is_empty()
                    && !relative_path.is_empty()
                    && folder_path_in_backup != "/"
                {
                    temp_parts = Vec::new();
                }
                effective_path_parts = std::borrow::Cow::Owned(temp_parts);
            }
        }
    }

    effective_path_parts
}

fn restore_version_from_record(
    target_node: &Node,
    effective_path_parts: &[&str],
    timestamp_str: &str,
    destination_root: &Path,
    backup_set_path: &Path,
    keyset: Option<&EncryptedKeySet>,
    versions_restored_count: &std::sync::atomic::AtomicUsize,
) -> Result<()> {
    if target_node.is_tree {
        let version_dest_dir_name = format!("{}", timestamp_str);
        let version_destination = destination_root.join(version_dest_dir_name);

        let content_dest_dir_name = effective_path_parts.last().map_or("root_content", |n| *n);
        let final_content_destination = version_destination.join(content_dest_dir_name);

        if !final_content_destination.exists() {
            std::fs::create_dir_all(&final_content_destination)?;
        }

        println!(
            "  Restoring version from record (Timestamp: {}) to {}...",
            timestamp_str,
            final_content_destination.display()
        );
        let mut stats = ExtractionStats::default();
        let mut ctx = ExtractionContext {
            backup_set_path,
            keyset,
            stats: &mut stats,
        };
        match extract_node_to_destination_recursive(
            target_node,
            &final_content_destination,
            "",
            &mut ctx,
        ) {
            Ok(_) => {
                println!(
                    "    Successfully restored version. Files: {}, Dirs: {}, Size: {} bytes. Errors: {}",
                    stats.files_restored, stats.dirs_created, stats.bytes_restored, stats.errors
                );
                if stats.errors > 0 {
                    debug_eprintln!(
                        "    Warning: {} errors occurred during this version's restoration.",
                        stats.errors
                    );
                }
                versions_restored_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                debug_eprintln!(
                    "    Error restoring version from record {}: {}",
                    timestamp_str,
                    e
                );
            }
        }
    }
    Ok(())
}

#[derive(Debug, Default, Clone, Copy)]
struct ExtractionStats {
    files_restored: usize,
    dirs_created: usize,
    bytes_restored: u64,
    errors: usize,
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
        let safe_name = std::path::Path::new(relative_path_for_node)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("invalid_node_name"));
        current_materialized_path.join(safe_name)
    };

    if node.is_tree {
        if !node_output_path.exists() {
            std::fs::create_dir_all(&node_output_path).map_err(Error::IoError)?;
            ctx.stats.dirs_created += 1;
        }

        match node.load_tree_with_encryption(ctx.backup_set_path, ctx.keyset) {
            Ok(Some(tree)) => {
                for (child_name, child_node) in &tree.nodes {
                    if let Err(e) = extract_node_to_destination_recursive(
                        child_node,
                        &node_output_path,
                        child_name,
                        ctx,
                    ) {
                        debug_eprintln!("Error processing child '{}': {}", child_name, e);
                        ctx.stats.errors += 1;
                    }
                }
            }
            Ok(None) => {
                debug_eprintln!(
                    "Warning: Node {} is a tree but has no loadable tree data.",
                    node_output_path.display()
                );
            }
            Err(e) => {
                debug_eprintln!(
                    "Error loading tree for {}: {}",
                    node_output_path.display(),
                    e
                );
                ctx.stats.errors += 1;
            }
        }
    } else {
        if let Some(parent_dir) = node_output_path.parent() {
            if !parent_dir.exists() {
                std::fs::create_dir_all(parent_dir).map_err(Error::IoError)?;
            }
        }

        match node.reconstruct_file_data_with_encryption(ctx.backup_set_path, ctx.keyset) {
            Ok(file_data) => {
                std::fs::write(&node_output_path, &file_data).map_err(Error::IoError)?;
                ctx.stats.files_restored += 1;
                ctx.stats.bytes_restored += file_data.len() as u64;

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
                debug_eprintln!(
                    "Error reconstructing file data for {}: {}",
                    node_output_path.display(),
                    e
                );
                ctx.stats.errors += 1;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
