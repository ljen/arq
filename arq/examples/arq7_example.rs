//! Comprehensive example of using the Arq 7 format support
//!
//! This example demonstrates how to load and explore an Arq 7 backup set,
//! including JSON configurations, backup records, and attempting to load
//! binary tree data.

use arq::arq7::BackupSet;
use arq::arq7::DirectoryEntry;
use arq::arq7::DirectoryEntryNode;
use arq::arq7::EncryptedKeySet;
use arq::compression::CompressionType;
use arq::packset::PackSet;
use arq::tree;
use std::path::Path;

fn list_children(
    bs: &mut BackupSet,
    node: &mut DirectoryEntryNode,
    depth: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let indent = "  ".repeat(depth + 2);
    if node.children.is_none() {
        bs.load_directory_children(node)?;
    }

    for child in node.children.as_mut().unwrap() {
        match child {
            DirectoryEntry::File(file) => {
                println!("{}{}", indent, file.name);
            }
            DirectoryEntry::Directory(dir) => {
                println!("{}{}", indent, dir.name);
                list_children(bs, dir, depth + 2)?;
            }
        }
    }
    return Ok(());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Path to an Arq 7 backup set directory
    let backup_set_path = "./tests/arq_storage_location/D1154AC6-01EB-41FE-B115-114464350B92";
    // let backup_set_path =
    // "/Users/ljensen/Projects/2025-06-arq/truenas/97328753-3EEB-4532-B27F-D4814B82405F";
    // let backup_set_path = "./tests/exos/A26237FB-0F74-4383-A86C-8A5BFD4E295B";
    let backup_passowrd = "asdfasdf1234";

    println!("🔍 Loading Arq 7 backup set from: {}", backup_set_path);
    println!("{}", "=".repeat(60));

    // Check if the backup set directory exists
    if !Path::new(backup_set_path).exists() {
        println!("❌ Backup set directory not found!");
        return Ok(());
    }

    let keyset_path = format!("{}/encryptedkeyset.dat", backup_set_path);
    if !Path::new(&keyset_path).exists() {
        println!("❌ Keyset files for Arq7 not found!");
        return Ok(());
    }
    let _keyset = EncryptedKeySet::from_file(keyset_path, backup_passowrd)?;
    // Load the complete backup set
    match BackupSet::from_directory_with_password(backup_set_path, Some(backup_passowrd)) {
        // match BackupSet::from_directory(backup_set_path) {
        Ok(backup_set) => {
            // get_decrypted_blobloc(&backup_set);
            // let mut root_directory = backup_set.get_root_directory()?;
            // list_children(&mut backup_set, &mut root_directory, 2);
            // print_backup_config(&backup_set);
            // print_backup_plan(&backup_set);
            // print_backup_folders_config(&backup_set);
            // print_backup_folder_configs(&backup_set);
            // print_backup_records(&backup_set, backup_set_path);
            // print_backup_statistics(&backup_set);
            list_all_files(&backup_set, backup_set_path);
            // demonstrate_content_extraction(&backup_set, backup_set_path, Some(&keyset));
        }
        Err(e) => {
            println!("❌ Failed to load backup set: {}", e);
        }
    }

    Ok(())
}

fn print_backup_config(backup_set: &BackupSet) {
    println!("\n📋 Backup Configuration");
    println!("{}", "-".repeat(30));
    println!("Name: {}", backup_set.backup_config.backup_name);
    println!("Computer: {}", backup_set.backup_config.computer_name);
    println!("Encrypted: {}", backup_set.backup_config.is_encrypted);
    println!(
        "Blob ID Type: {} ({})",
        backup_set.backup_config.blob_identifier_type,
        match backup_set.backup_config.blob_identifier_type {
            1 => "SHA1",
            2 => "SHA256",
            _ => "Unknown",
        }
    );
    println!(
        "Chunker Version: {}",
        backup_set.backup_config.chunker_version
    );
    println!(
        "Max Packed Item Length: {} bytes",
        backup_set.backup_config.max_packed_item_length
    );
}

fn print_backup_plan(backup_set: &BackupSet) {
    println!("\n📅 Backup Plan");
    println!("{}", "-".repeat(30));
    println!("Plan UUID: {}", backup_set.backup_plan.plan_uuid);
    println!("Active: {}", backup_set.backup_plan.active);
    println!(
        "Schedule Type: {}",
        backup_set.backup_plan.schedule_json.schedule_type
    );
    println!("CPU Usage Limit: {}%", backup_set.backup_plan.cpu_usage);
    println!("Thread Count: {}", backup_set.backup_plan.thread_count);
    println!("Retention:");
    println!("  - Hours: {}", backup_set.backup_plan.retain_hours);
    println!("  - Days: {}", backup_set.backup_plan.retain_days);
    println!("  - Weeks: {}", backup_set.backup_plan.retain_weeks);
    println!("  - Months: {}", backup_set.backup_plan.retain_months);
    println!("Notifications:");
    println!("  - On Error: {}", backup_set.backup_plan.notify_on_error);
    println!(
        "  - On Success: {}",
        backup_set.backup_plan.notify_on_success
    );
}

fn print_backup_folders_config(backup_set: &BackupSet) {
    println!("\n📁 Object Storage Directories");
    println!("{}", "-".repeat(30));
    println!(
        "Standard Objects: {} dirs",
        backup_set.backup_folders.standard_object_dirs.len()
    );
    println!(
        "Standard IA Objects: {} dirs",
        backup_set.backup_folders.standard_ia_object_dirs.len()
    );
    println!(
        "Glacier Objects: {} dirs",
        backup_set.backup_folders.s3_glacier_object_dirs.len()
    );
    println!(
        "Deep Archive Objects: {} dirs",
        backup_set.backup_folders.s3_deep_archive_object_dirs.len()
    );

    if let Some(imported) = &backup_set.backup_folders.imported_from {
        println!("Imported from: {}", imported);
    }
}

fn print_backup_folder_configs(backup_set: &BackupSet) {
    println!("\n📂 Backup Folder Configurations");
    println!("{}", "-".repeat(30));

    for (uuid, folder) in &backup_set.backup_folder_configs {
        println!("Folder: {}", folder.name);
        println!("  UUID: {}", uuid);
        println!("  Local Path: {}", folder.local_path);
        println!("  Mount Point: {}", folder.local_mount_point);
        println!("  Storage Class: {}", folder.storage_class);
        println!("  Disk ID: {:?}", folder.disk_identifier);
        println!("  Migrated from Arq 5: {}", folder.migrated_from_arq5);
        println!("  Migrated from Arq 6: {}", folder.migrated_from_arq60);
    }
}

// get_file_reader is no longer needed here as its functionality for restore_blob_with_sha
// has been moved into a private helper within arq/src/tree.rs.

// restore_blob_with_sha will be moved to arq/src/tree.rs and modified.

fn print_backup_records(backup_set: &BackupSet, backup_set_path: &str) -> Option<()> {
    println!("\n📝 Backup Records");
    println!("{}", "-".repeat(30));
    let backup_set_path = Path::new(backup_set_path);

    if backup_set.backup_records.is_empty() {
        println!("No backup records found or failed to parse.");
        return None;
    }

    for (folder_uuid, generic_records) in &backup_set.backup_records {
        println!("Folder {}: {} records", folder_uuid, generic_records.len());

        for (i, generic_record) in generic_records.iter().enumerate() {
            match generic_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    println!("  Record #{} (Arq7): v{}", i + 1, record.version);
                    println!("    Storage Class: {}", record.storage_class);
                    println!("    Copied from Commit: {}", record.copied_from_commit);
                    println!("    Copied from Snapshot: {}", record.copied_from_snapshot);
                    println!("    Disk Identifier: {}", record.disk_identifier);
                    if let Some(vn) = &record.volume_name {
                        println!("    Volume Name: {}", vn);
                    }

                    if let Some(arq_version) = &record.arq_version {
                        println!("    Arq Version: {}", arq_version);
                    }
                    if let Some(creation_date) = record.creation_date {
                        let dt = chrono::DateTime::from_timestamp(creation_date as i64, 0)
                            .unwrap_or_default();
                        println!("    Creation Date: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                    if let Some(bpj) = &record.backup_plan_json {
                        println!(
                            "    Backup Plan JSON: Present (Plan UUID: {})",
                            bpj.plan_uuid
                        );
                    }

                    // Print node information
                    println!("    Root Node:");
                    println!("      Is Tree: {}", record.node.is_tree);
                    println!("      Item Size: {} bytes", record.node.item_size);
                    println!("      OS Type: {:?}", record.node.computer_os_type); // This was computer_os_type on Node
                    println!("      Deleted: {}", record.node.deleted);
                    if let Some(contained_files) = record.node.contained_files_count {
                        println!("      Contained Files: {}", contained_files);
                    }
                    if record.node.tree_blob_loc.is_some() {
                        println!("      Has Tree Blob Location: Yes");
                    }
                    println!(
                        "      Data Blob Locations: {}",
                        record.node.data_blob_locs.len()
                    );
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    println!("  Record #{} (Arq5 Migrated): v{}", i + 1, record.version);
                    println!("    Storage Class: {}", record.storage_class);
                    println!("    Copied from Commit: {}", record.copied_from_commit);
                    println!("    Copied from Snapshot: {}", record.copied_from_snapshot);
                    if let Some(av) = &record.arq_version {
                        println!("    Arq Version (Original): {}", av);
                    }
                    if let Some(cd) = record.creation_date {
                        let dt = chrono::DateTime::from_timestamp(cd as i64, 0).unwrap_or_default();
                        println!("    Creation Date: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                    if record.arq5_bucket_xml.is_some() {
                        println!("    Arq5 Bucket XML: Present");
                    }
                    if record.arq5_tree_blob_key.is_some() {
                        println!("    Arq5 Tree Blob Key: Present");
                    }
                    let trees_path = backup_set_path
                        .join("packsets/")
                        .join(format!("{}-trees", record.backup_folder_uuid));
                    match record.arq5_tree_blob_key.clone() {
                        Some(key) => {
                            let sha = key.sha1.clone();
                            let keyset_ref = match backup_set.encryption_keyset.as_ref() {
                                Some(ks) => ks,
                                None => {
                                    println!("      ❌ Encryption keyset not available (backup not encrypted or keyset missing) for SHA {}", sha);
                                    return None; // Exit print_backup_records for this record
                                }
                            };

                            let packset = PackSet::new(&trees_path);
                            let data = match packset.restore_blob_with_sha(
                                &sha,
                                keyset_ref, // Pass the reference to EncryptedKeySet
                            ) {
                                Ok(Some(d)) => d,
                                Ok(None) => {
                                    println!(
                                        "      ⚠️ Blob data not found for SHA {} in {}",
                                        sha,
                                        trees_path.display()
                                    );
                                    return None;
                                }
                                Err(e) => {
                                    println!(
                                        "      ❌ Error restoring blob with SHA {}: {}",
                                        sha, e
                                    );
                                    return None;
                                }
                            };
                            // let commit = tree::Commit::new(Cursor::new(data)).ok()?;

                            // let tree_blob = arq::tree::restore_blob_with_sha(
                            //     &trees_path,
                            //     &commit.tree_sha1,
                            //     &backup_set
                            //         .encryption_keyset
                            //         .as_ref()
                            //         .unwrap()
                            //         .encryption_key
                            //         .clone(),
                            // )
                            // .ok()?;
                            let tree = tree::Tree::new_arq5(
                                &data,
                                CompressionType::from(key.compression_type),
                            )
                            .ok()?;

                            // Print node information
                            println!("    Root Node:");
                            println!("      Version: {}", tree.version);

                            let dt = chrono::DateTime::from_timestamp(
                                tree.mtime_sec,
                                tree.mtime_nsec as u32,
                            )
                            .unwrap_or_default();
                            println!(
                                "      Node mtime Date: {}",
                                dt.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                            let dt = chrono::DateTime::from_timestamp(
                                tree.ctime_sec,
                                tree.create_time_nsec as u32,
                            )
                            .unwrap_or_default();
                            println!(
                                "      Node ctime Date: {}",
                                dt.format("%Y-%m-%d %H:%M:%S UTC")
                            );
                            println!("      Missing nodes {}", tree.missing_nodes.len());
                            println!("      Nodes:");
                            for node in tree.nodes.iter() {
                                if node.1.is_tree {
                                    println!("         + 📁{}", node.0);
                                } else {
                                    println!("         - 📄{}", node.0);
                                }
                            }

                            if let Some(errors) = &record.backup_record_errors {
                                println!("    Backup Record Errors: {} errors", errors.len());
                                for err_detail in errors.iter().take(2) {
                                    // Print details of first 2 errors
                                    println!(
                                        "      - {}: {}",
                                        err_detail.local_path,
                                        err_detail.error_message.lines().next().unwrap_or("")
                                    );
                                }
                            } else {
                                println!("    Backup Record Errors: None");
                            }
                        }
                        None => println!("    Backup Record Errors: None"),
                    }
                }
            }
        }
    }
    None
}

fn print_backup_statistics(backup_set: &BackupSet) {
    println!("\n📊 Backup Statistics");
    println!("{}", "-".repeat(30));

    let total_folders = backup_set.backup_folder_configs.len();
    let mut total_records_count = 0;
    let mut total_arq7_records = 0;
    let mut total_arq5_records = 0;

    for records_vec in backup_set.backup_records.values() {
        total_records_count += records_vec.len();
        for generic_record in records_vec {
            match generic_record {
                arq::arq7::GenericBackupRecord::Arq7(_) => total_arq7_records += 1,
                arq::arq7::GenericBackupRecord::Arq5(_) => total_arq5_records += 1,
            }
        }
    }

    println!("Total Folders (in backup plan): {}", total_folders);
    println!(
        "Total Backup Records: {} (Arq7: {}, Arq5: {})",
        total_records_count, total_arq7_records, total_arq5_records
    );

    let mut total_size_arq7 = 0u64; // Corrected variable name
    let mut total_files_arq7 = 0u64; // Corrected variable name

    for records_vec in backup_set.backup_records.values() {
        for generic_record in records_vec {
            if let arq::arq7::GenericBackupRecord::Arq7(record) = generic_record {
                total_size_arq7 += record.node.item_size;
                if let Some(count) = record.node.contained_files_count {
                    total_files_arq7 += count;
                }
            }
            // Statistics for Arq5 records might be calculated differently if needed
        }
    }

    println!(
        "Total Size (Arq7 records node sum): {} bytes ({:.2} MB)", // Clarified it's Arq7 sum
        total_size_arq7,
        total_size_arq7 as f64 / 1_048_576.0
    );
    println!("Total Files (Arq7 records node sum): {}", total_files_arq7); // Clarified
}

#[derive(Default)]
struct FileStats {
    total_files: usize,
    total_directories: usize,
    total_size: u64,
    largest_file_size: u64,
    largest_file_path: String,
}

#[allow(dead_code)]
fn list_all_files(backup_set: &BackupSet, backup_set_path: &str) {
    println!("\n📁 Complete File Listing (from Arq7 Records)"); // Clarified title
    println!("{}", "=".repeat(60));

    for (folder_uuid, generic_records) in &backup_set.backup_records {
        // Renamed records
        println!("\n📂 Folder: {}", folder_uuid);
        let folder_config = backup_set.backup_folder_configs.get(folder_uuid);
        if let Some(config) = folder_config {
            println!("   Name: {}", config.name);
            println!("   Path: {}", config.local_path);
        }
        println!("{}", "-".repeat(50));

        for (record_idx, generic_record) in generic_records.iter().enumerate() {
            match generic_record {
                arq::arq7::GenericBackupRecord::Arq7(record) => {
                    println!(
                        "\n  🕐 Backup Record #{} (Arq7 v{})",
                        record_idx + 1,
                        record.version
                    );

                    if let Some(creation_date) = record.creation_date {
                        let dt = chrono::DateTime::from_timestamp(creation_date as i64, 0)
                            .unwrap_or_default();
                        println!("     Date: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                    if let Some(arq_version) = &record.arq_version {
                        println!("     Arq Version: {}", arq_version);
                    }

                    let mut stats = FileStats::default(); // Correct: use local stats for this record
                    list_files_recursive(
                        &record.node,
                        Path::new(backup_set_path),
                        String::new(),
                        0,
                        folder_config.map(|f| f.name.as_str()).unwrap_or("Unknown"),
                        &mut stats,
                        backup_set.encryption_keyset(),
                    );
                    println!("\n     📊 Record Statistics (Arq7):");
                    println!("        Files: {}", stats.total_files);
                    println!("        Directories: {}", stats.total_directories);
                    println!(
                        "        Total Size: {} bytes ({:.2} MB)",
                        stats.total_size,
                        stats.total_size as f64 / 1_048_576.0
                    );
                    if !stats.largest_file_path.is_empty() {
                        println!(
                            "        Largest File: {} ({} bytes)",
                            stats.largest_file_path, stats.largest_file_size
                        );
                    }
                }
                arq::arq7::GenericBackupRecord::Arq5(record) => {
                    println!(
                        "\n  🕐 Backup Record #{} (Arq5 v{})",
                        record_idx + 1,
                        record.version
                    );
                    if let Some(creation_date) = record.creation_date {
                        let dt = chrono::DateTime::from_timestamp(creation_date as i64, 0)
                            .unwrap_or_default();
                        println!("     Date: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
                    }
                    if let Some(arq_version) = &record.arq_version {
                        println!("     Arq Version: {}", arq_version);
                    }
                    println!("     (File listing from node structure not applicable for Arq5 records in this example)");
                }
            }
        }
    }
}

#[allow(dead_code)]
fn demonstrate_content_extraction(
    backup_set: &BackupSet,
    backup_set_path: &str,
    keyset: Option<&EncryptedKeySet>,
) {
    println!("\n💾 Complete Backup Restoration");
    println!("{}", "=".repeat(60));

    let extraction_root = "extracted_backups";
    if let Err(e) = std::fs::create_dir_all(extraction_root) {
        println!("❌ Failed to create extraction directory: {}", e);
        return;
    }
    println!("📁 Extracting to: {}/", extraction_root);

    let mut total_files_restored = 0;
    let mut total_bytes_restored = 0;
    let mut total_errors = 0;

    for (folder_uuid, generic_records) in &backup_set.backup_records {
        println!("\n📂 Processing folder: {}", folder_uuid);
        let folder_name = backup_set
            .backup_folder_configs
            .get(folder_uuid)
            .map(|config| config.name.clone())
            .unwrap_or_else(|| "unknown_folder".to_string());
        println!("   📝 Folder name: {}", folder_name);

        for (record_idx, generic_record) in generic_records.iter().enumerate() {
            let creation_date_opt = match generic_record {
                arq::arq7::GenericBackupRecord::Arq7(r) => r.creation_date,
                arq::arq7::GenericBackupRecord::Arq5(r) => r.creation_date,
            };
            println!(
                "\n   🕐 Backup Record #{} ({})",
                record_idx + 1,
                chrono::DateTime::from_timestamp(creation_date_opt.unwrap_or(0.0) as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "unknown time".to_string())
            );

            let record_dir = format!(
                "{}/{}_record_{}",
                extraction_root,
                folder_name,
                record_idx + 1
            );
            if let Err(e) = std::fs::create_dir_all(&record_dir) {
                println!("      ❌ Failed to create record directory: {}", e);
                total_errors += 1;
                continue;
            }

            let mut record_stats = ExtractionStats::default(); // Correct: use local record_stats
            extract_backup_record(
                generic_record,
                Path::new(backup_set_path),
                Path::new(&record_dir),
                &mut record_stats,
                keyset,
            );

            total_files_restored += record_stats.files_restored;
            total_bytes_restored += record_stats.bytes_restored;
            total_errors += record_stats.errors;
            // The following print block was correct as it was using record_stats
            // from its local scope. No change needed here based on compiler errors.
            println!("      📊 Record Summary:");
            println!("         Files: {}", record_stats.files_restored);
            println!("         Directories: {}", record_stats.directories_created);
            println!(
                "         Bytes: {} ({:.2} MB)",
                record_stats.bytes_restored,
                record_stats.bytes_restored as f64 / 1_048_576.0
            );
            if record_stats.errors > 0 {
                println!("         ⚠️  Errors: {}", record_stats.errors);
            }
        }
    }

    println!("\n🎯 Total Restoration Summary");
    println!("{}", "=".repeat(40));
    println!("📁 Extraction directory: {}/", extraction_root);
    println!("📄 Files restored: {}", total_files_restored);
    println!(
        "💾 Total bytes: {} ({:.2} MB)",
        total_bytes_restored,
        total_bytes_restored as f64 / 1_048_576.0
    );
    if total_errors > 0 {
        println!("⚠️  Total errors: {}", total_errors);
    } else {
        println!("✅ All files restored successfully!");
    }
}

#[derive(Default)] // Added Default derive
struct ExtractionStats {
    files_restored: usize,
    bytes_restored: u64,
    errors: usize,
    directories_created: usize,
}

#[allow(dead_code)]
fn extract_backup_record(
    generic_record: &arq::arq7::GenericBackupRecord,
    backup_set_path: &Path,
    output_dir: &Path,
    stats: &mut ExtractionStats,
    keyset: Option<&EncryptedKeySet>,
) {
    match generic_record {
        arq::arq7::GenericBackupRecord::Arq7(record) => {
            if record.node.is_tree {
                extract_tree_node(&record.node, backup_set_path, output_dir, "", stats, keyset);
            } else {
                extract_file_node(
                    &record.node,
                    backup_set_path,
                    output_dir,
                    record.local_path.as_deref().unwrap_or("root_file_arq7"),
                    stats,
                    keyset,
                );
            }
        }
        arq::arq7::GenericBackupRecord::Arq5(record) => {
            println!(
                "    ℹ️ Extraction for Arq5 record (version {}) (UUID: {}) is limited in this example.",
                record.version, record.backup_folder_uuid
            );
            if let Some(xml_data) = &record.arq5_bucket_xml {
                let file_path =
                    output_dir.join(format!("{}_arq5Bucket.xml", record.backup_folder_uuid));
                match std::fs::write(&file_path, xml_data) {
                    Ok(_) => {
                        println!(
                            "        📄 Extracted arq5BucketXML to: {}",
                            file_path.display()
                        );
                        stats.files_restored += 1;
                        stats.bytes_restored += xml_data.len() as u64;
                    }
                    Err(e) => {
                        println!("        ❌ Failed to write arq5BucketXML: {}", e);
                        stats.errors += 1;
                    }
                }
            }
        }
    }
}

#[allow(dead_code)]
fn extract_tree_node(
    node: &arq::node::Node,
    backup_set_path: &Path,
    current_output_dir: &Path,
    relative_path: &str,
    stats: &mut ExtractionStats,
    keyset: Option<&EncryptedKeySet>,
) {
    let full_output_path = if relative_path.is_empty() {
        current_output_dir.to_path_buf()
    } else {
        current_output_dir.join(relative_path)
    };

    let full_output_path_obj = Path::new(&full_output_path); // Use a different name to avoid conflict

    if !relative_path.is_empty() {
        if let Err(e) = std::fs::create_dir_all(&full_output_path_obj) {
            // Use renamed variable
            println!(
                "         ❌ Failed to create directory {}: {}",
                relative_path, e
            );
            stats.errors += 1;
            return;
        }
        stats.directories_created += 1;
        //println!("         📁 Created: {}/", relative_path);
    }

    // let tmp =
    //     EncryptedKeySet::from_file(backup_set_path.join("encryptedkeyset.dat"), "asdfasdf1234")
    //         .unwrap();
    // let keyset = Some(&tmp); // keyset is passed in, no need to reload here
    let tree_load_result = match node.tree_blob_loc.as_ref() {
        Some(loc) => loc.load_tree_with_encryption(backup_set_path, keyset),
        None => Ok(None), // Node is not a tree or has no tree blob loc
    };

    match tree_load_result {
        Ok(Some(tree)) => {
            // The unified arq::tree::Tree uses `nodes` (a HashMap) instead of `child_nodes`
            for (child_name, child_node_ref) in &tree.nodes {
                let _child_path = if relative_path.is_empty() {
                    // Prefixed with _
                    child_name.clone()
                } else {
                    format!("{}/{}", relative_path, child_name)
                };

                if child_node_ref.is_tree {
                    extract_tree_node(
                        child_node_ref,
                        backup_set_path,
                        &full_output_path_obj, // Children are extracted into this node's directory
                        child_name,            // Child's name is its relative path from this node
                        stats,
                        keyset,
                    );
                } else {
                    extract_file_node(
                        child_node_ref,
                        backup_set_path,
                        &full_output_path_obj,
                        child_name,
                        stats,
                        keyset,
                    );
                }
            }
        }
        Ok(None) => {
            stats.errors += 1;
        }
        Err(_e) => {
            stats.errors += 1;
            extract_using_json_fallback(
                node,
                backup_set_path,
                &full_output_path_obj, // Use renamed variable
                relative_path,
                stats,
                keyset,
            );
        }
    }
}

#[allow(dead_code)]
fn extract_file_node(
    node: &arq::node::Node,
    backup_set_path: &Path,
    output_dir: &Path,
    filename: &str,
    stats: &mut ExtractionStats,
    keyset: Option<&EncryptedKeySet>,
) {
    let output_file_path = output_dir.join(filename); // Use Path::join for robustness

    let mut content_extracted = false;
    let mut total_size = 0u64;

    let has_real_blobs = node
        .data_blob_locs
        .iter()
        .any(|blob| !blob.relative_path.contains("unknown") && !blob.relative_path.is_empty());

    if has_real_blobs || !node.data_blob_locs.is_empty() {
        let mut reconstructed_content = Vec::new();
        let mut reconstruction_error = false;
        if node.data_blob_locs.is_empty() && node.item_size > 0 {
            reconstruction_error = true;
        } else {
            for blob_loc in &node.data_blob_locs {
                match blob_loc.extract_content(backup_set_path, keyset) {
                    Ok(data) => reconstructed_content.extend(data),
                    Err(_e) => {
                        reconstruction_error = true;
                        break;
                    }
                }
            }
        }

        if reconstruction_error {
            stats.errors += 1;
        } else {
            if let Err(_e) = std::fs::write(&output_file_path, &reconstructed_content) {
                stats.errors += 1;
            } else {
                total_size = reconstructed_content.len() as u64;
                content_extracted = true;
            }
        }
    } else if node.item_size == 0 {
        if let Err(_e) = std::fs::write(&output_file_path, b"") {
            stats.errors += 1;
        } else {
            content_extracted = true; // total_size is already 0
        }
    } else {
        stats.errors += 1;
    }

    if content_extracted {
        stats.files_restored += 1;
        stats.bytes_restored += total_size;
        set_file_metadata(&output_file_path, node); // Pass Path directly
    }
}

#[allow(dead_code)]
fn extract_using_json_fallback(
    node: &arq::node::Node,
    backup_set_path: &Path,
    output_dir: &Path,    // Changed to &Path
    _relative_path: &str, // relative_path is not used here.
    stats: &mut ExtractionStats,
    keyset: Option<&EncryptedKeySet>,
) {
    if !node.data_blob_locs.is_empty() {
        for (blob_idx, _data_blob) in node.data_blob_locs.iter().enumerate() {
            let filename = format!("file_from_json_blob_{}.data", blob_idx);
            // Since extract_file_node is complex, and this is a fallback for tree loading failure,
            // we might simplify this or acknowledge that full file reconstruction from just JSON blobs
            // might not always be feasible if they are part of a packed structure not described by the Node alone.
            // For this example, we'll call extract_file_node, assuming data_blob_locs might be sufficient.
            extract_file_node(node, backup_set_path, output_dir, &filename, stats, keyset);
        }
    }
}

#[allow(dead_code)]
fn set_file_metadata(file_path: &Path, node: &arq::node::Node) {
    // Changed to &Path
    if node.modification_time_sec > 0 {
        // This field exists on arq::node::Node
        use std::time::UNIX_EPOCH;
        if let Some(mtime) = UNIX_EPOCH.checked_add(std::time::Duration::from_secs(
            node.modification_time_sec as u64,
        )) {
            let _ =
                filetime::set_file_mtime(file_path, filetime::FileTime::from_system_time(mtime));
        }
    }
}

fn _try_extract_test_file_content(
    // Prefixed with _
    _filename: &str, // Mark as unused if not used
    _backup_set_path: &Path,
    _keyset: Option<&EncryptedKeySet>,
) -> Option<Vec<u8>> {
    None // Simplified for this round, main extraction relies on node.reconstruct_file_data
}

fn list_files_recursive(
    node: &arq::node::Node,
    backup_set_path: &Path,
    current_path: String,
    depth: usize,
    folder_name: &str,
    stats: &mut FileStats,
    keyset: Option<&EncryptedKeySet>,
) {
    let indent = "  ".repeat(depth + 2);
    let path_display = if current_path.is_empty() {
        format!("/{}", folder_name)
    } else {
        current_path.clone()
    };

    if node.is_tree {
        println!("{}📁 {}/", indent, path_display);
        stats.total_directories += 1;

        let tree_load_result: Result<Option<tree::Tree>, arq::error::Error> =
            match node.tree_blob_loc.as_ref() {
                Some(loc) => {
                    // let data = loc.extract_content(backup_set_path, keyset).unwrap();
                    // let mut file = std::fs::File::create(&loc.blob_identifier).unwrap();
                    // file.write_all(&data);
                    // file.flush();
                    loc.load_tree_with_encryption(backup_set_path, keyset)
                }
                None => Ok(None),
            };

        match tree_load_result {
            Ok(Some(tree)) => {
                // The unified arq::tree::Tree uses `nodes` (a HashMap)
                for (child_name, child_node_ref) in &tree.nodes {
                    let child_path = if current_path.is_empty() {
                        format!("/{}/{}", folder_name, child_name)
                    } else {
                        format!("{}/{}", current_path, child_name)
                    };
                    list_files_recursive(
                        child_node_ref,
                        backup_set_path,
                        child_path,
                        depth + 1,
                        folder_name,
                        stats,
                        keyset,
                    );
                }
            }
            Ok(None) => {
                println!("{}   ⚠️  No tree data available", indent);
            }
            Err(e) => {
                println!("Error with {}", e)
                // ...
            }
        }
    } else {
        let file_icon = get_file_icon(&path_display);
        println!("{}{} {}", indent, file_icon, path_display);
        stats.total_files += 1;
        stats.total_size += node.item_size;
        if node.item_size > stats.largest_file_size {
            stats.largest_file_size = node.item_size;
            stats.largest_file_path = path_display.clone();
        }
        show_file_details(node, &indent);
    }
}

fn _show_node_metadata(node: &arq::node::Node, indent: &str) {
    // Prefixed with _
    println!("{}   Size: {} bytes", indent, node.item_size); // item_size exists on arq::node::Node
                                                             // ...
}

fn show_file_details(node: &arq::node::Node, indent: &str) {
    println!("{}   📊 {} bytes", indent, node.item_size); // item_size exists on arq::node::Node
                                                          // ...
}

fn get_file_icon(path: &str) -> &'static str {
    // ...
    let extension = Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("")
        .to_lowercase();
    match extension.as_str() {
        "txt" | "md" | "readme" => "📝",
        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "java" | "swift" | "kt" => "💻",
        "json" | "xml" | "yaml" | "yml" | "toml" | "plist" => "⚙️",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "svg" | "heic" | "webp" => "🖼️",
        "mp4" | "avi" | "mov" | "mkv" | "webm" | "flv" => "🎬",
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" => "🎵",
        "pdf" | "doc" | "docx" | "ppt" | "pptx" | "xls" | "xlsx" | "odt" | "ods" | "odp" => "📄",
        "zip" | "tar" | "gz" | "bz2" | "rar" | "7z" | "xz" => "📦",
        "exe" | "app" | "dmg" | "deb" | "rpm" | "msi" => "⚙️",
        "db" | "sqlite" | "sql" => "🗃️",
        "iso" | "img" => "💿",
        "bak" | "old" => "💾",
        "log" => "📜",
        _ => "❔", // Default for unknown
    }
}
