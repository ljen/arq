//! Complete Tree Explorer for Arq 7 Backup Records
//!
//! This example recursively explores and prints the complete directory structure
//! of all backup records by following tree blob locations to show all subfolders
//! and files in the backup.

use arq::arq7::*;
use std::path::Path;

const ARQ7_TEST_DATA_DIR: &str =
    "./tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌳 Complete Arq 7 Backup Tree Explorer");
    println!("{}", "=".repeat(60));

    // Load the complete backup set
    let backup_set = BackupSet::from_directory(ARQ7_TEST_DATA_DIR)?;

    let mut total_files = 0;
    let mut total_directories = 0;
    let mut total_size = 0u64;

    for (folder_uuid, records) in &backup_set.backup_records {
        // Get folder name from backup folder configs
        let folder_name = backup_set
            .backup_folder_configs
            .get(folder_uuid)
            .map(|config| config.name.clone())
            .unwrap_or_else(|| "unknown_folder".to_string());

        println!("\n📂 Folder: {} ({})", folder_name, folder_uuid);
        println!("{}", "-".repeat(50));

        for (record_idx, record) in records.iter().enumerate() {
            println!(
                "\n🕐 Backup Record #{} - {}",
                record_idx + 1,
                chrono::DateTime::from_timestamp(
                    record.creation_date.unwrap_or(0) as i64 / 1000,
                    0
                )
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "unknown time".to_string())
            );

            println!(
                "   📊 Expected files: {}",
                record.node.contained_files_count.unwrap_or(0)
            );
            println!("   📏 Total size: {} bytes", record.node.item_size);

            if record.node.is_tree {
                let mut stats = TreeStats {
                    files: 0,
                    directories: 0,
                    total_size: 0,
                    max_depth: 0,
                };

                println!("\n   📁 Complete Directory Tree:");
                explore_tree_recursive(&record.node, ARQ7_TEST_DATA_DIR, "/", 0, &mut stats);

                println!("\n   📊 Tree Statistics:");
                println!("      Files: {}", stats.files);
                println!("      Directories: {}", stats.directories);
                println!(
                    "      Total Size: {} bytes ({:.2} MB)",
                    stats.total_size,
                    stats.total_size as f64 / 1_048_576.0
                );
                println!("      Max Depth: {}", stats.max_depth);

                total_files += stats.files;
                total_directories += stats.directories;
                total_size += stats.total_size;
            } else {
                println!(
                    "   📄 Root is a file: {}",
                    record.local_path.as_deref().unwrap_or("unknown")
                );
                total_files += 1;
                total_size += record.node.item_size;
            }

            println!("\n{}", "·".repeat(50));
        }
    }

    println!("\n🎯 Grand Total Across All Records");
    println!("{}", "=".repeat(40));
    println!("📄 Total Files: {}", total_files);
    println!("📁 Total Directories: {}", total_directories);
    println!(
        "💾 Total Size: {} bytes ({:.2} MB)",
        total_size,
        total_size as f64 / 1_048_576.0
    );

    Ok(())
}

struct TreeStats {
    files: usize,
    directories: usize,
    total_size: u64,
    max_depth: usize,
}

fn explore_tree_recursive(
    node: &Node,
    backup_set_path: &str,
    current_path: &str,
    depth: usize,
    stats: &mut TreeStats,
) {
    let indent = "   ".repeat(depth + 2);

    // Update max depth
    if depth > stats.max_depth {
        stats.max_depth = depth;
    }

    if node.is_tree {
        stats.directories += 1;

        // Print directory info
        let dir_icon = if depth == 0 { "🏠" } else { "📁" };
        println!(
            "{}{} {}/",
            indent,
            dir_icon,
            current_path.trim_end_matches('/')
        );

        if let Some(contained_files) = node.contained_files_count {
            if contained_files > 0 {
                println!("{}   (contains {} items)", indent, contained_files);
            }
        }

        // Try to load and explore the tree contents
        match node.load_tree(Path::new(backup_set_path)) {
            Ok(Some(tree)) => {
                println!(
                    "{}   ✅ Tree loaded with {} children",
                    indent,
                    tree.child_nodes.len()
                );

                // Sort children for consistent output
                let mut children: Vec<_> = tree.child_nodes.iter().collect();
                children.sort_by(|a, b| a.0.cmp(b.0));

                // Debug: Show all children found in tree
                println!(
                    "{}   🔍 Debug: Found {} children in tree:",
                    indent,
                    children.len()
                );
                for (name, node) in &children {
                    let display_name = if name.is_empty() { "<empty>" } else { name };
                    println!(
                        "{}      - '{}': is_tree={}, has_tree_blob={}",
                        indent,
                        display_name,
                        node.is_tree,
                        node.tree_blob_loc.is_some()
                    );
                    if node.is_tree && node.tree_blob_loc.is_some() {
                        let blob_loc = node.tree_blob_loc.as_ref().unwrap();
                        println!("{}        Tree blob: {}", indent, blob_loc.blob_identifier);
                        println!("{}        Path: {}", indent, blob_loc.relative_path);
                    }
                }

                for (child_name, child_node) in children {
                    let child_path = if current_path == "/" {
                        format!("/{}", child_name)
                    } else {
                        format!("{}/{}", current_path, child_name)
                    };

                    // Convert binary node to JSON node for recursive exploration
                    let json_node = Node::from_binary_node(child_node);

                    if child_node.is_tree {
                        // Handle subdirectories - try to load their tree contents
                        println!(
                            "{}   🔍 Exploring subdirectory: '{}'",
                            "   ".repeat(depth + 3),
                            child_name
                        );

                        if child_node.tree_blob_loc.is_some() {
                            println!(
                                "{}   📦 Has tree blob location - attempting to load...",
                                "   ".repeat(depth + 3)
                            );

                            // Try to load the subdirectory tree directly from blob location
                            let blob_loc = child_node.tree_blob_loc.as_ref().unwrap();
                            match load_tree_from_blob_loc(blob_loc, backup_set_path) {
                                Ok(subtree) => {
                                    println!(
                                        "{}   ✅ Loaded subtree with {} children",
                                        "   ".repeat(depth + 3),
                                        subtree.child_nodes.len()
                                    );

                                    // Process all children in the subtree
                                    for (subchild_name, subchild_node) in &subtree.child_nodes {
                                        let subchild_path =
                                            format!("{}/{}", child_path, subchild_name);
                                        let subjson_node = Node::from_binary_node(subchild_node);

                                        if subchild_node.is_tree {
                                            explore_tree_recursive(
                                                &subjson_node,
                                                backup_set_path,
                                                &subchild_path,
                                                depth + 2,
                                                stats,
                                            );
                                        } else {
                                            // Handle files in subdirectory
                                            stats.files += 1;
                                            stats.total_size += subchild_node.item_size;

                                            let file_icon = get_file_icon(subchild_name);
                                            println!(
                                                "{}{} {}",
                                                "   ".repeat(depth + 4),
                                                file_icon,
                                                subchild_name
                                            );
                                            println!(
                                                "{}   📏 {} bytes",
                                                "   ".repeat(depth + 4),
                                                subchild_node.item_size
                                            );

                                            if !subchild_node.data_blob_locs.is_empty() {
                                                println!(
                                                    "{}   💾 {} data blob(s)",
                                                    "   ".repeat(depth + 4),
                                                    subchild_node.data_blob_locs.len()
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!(
                                        "{}   ❌ Failed to load subtree: {}",
                                        "   ".repeat(depth + 3),
                                        e
                                    );
                                }
                            }
                        }

                        // Also try the normal recursive call
                        explore_tree_recursive(
                            &json_node,
                            backup_set_path,
                            &child_path,
                            depth + 1,
                            stats,
                        );
                    } else {
                        // Handle files
                        stats.files += 1;
                        stats.total_size += child_node.item_size;

                        let file_icon = get_file_icon(child_name);
                        println!("{}{} {}", "   ".repeat(depth + 3), file_icon, child_name);
                        println!(
                            "{}   📏 {} bytes",
                            "   ".repeat(depth + 3),
                            child_node.item_size
                        );

                        // Show modification time if available
                        if json_node.modification_time_sec > 0 {
                            if let Some(dt) = chrono::DateTime::from_timestamp(
                                json_node.modification_time_sec as i64,
                                0,
                            ) {
                                println!(
                                    "{}   🕒 {}",
                                    "   ".repeat(depth + 3),
                                    dt.format("%Y-%m-%d %H:%M:%S")
                                );
                            }
                        }

                        // Show blob information
                        if !child_node.data_blob_locs.is_empty() {
                            println!(
                                "{}   💾 {} data blob(s)",
                                "   ".repeat(depth + 3),
                                child_node.data_blob_locs.len()
                            );
                            for (i, blob_loc) in child_node.data_blob_locs.iter().enumerate() {
                                if i < 3 {
                                    // Limit to first 3 blobs to avoid spam
                                    println!(
                                        "{}      📦 Blob {}: {} bytes at offset {}",
                                        "   ".repeat(depth + 3),
                                        i + 1,
                                        blob_loc.length,
                                        blob_loc.offset
                                    );
                                    if !blob_loc.relative_path.is_empty()
                                        && !blob_loc.relative_path.contains("unknown")
                                    {
                                        let path_parts: Vec<&str> =
                                            blob_loc.relative_path.split('/').collect();
                                        if path_parts.len() > 2 {
                                            println!(
                                                "{}         📁 Pack: {}",
                                                "   ".repeat(depth + 3),
                                                path_parts.last().map_or("unknown.pack", |v| *v)
                                            );
                                        }
                                    }
                                }
                            }
                            if child_node.data_blob_locs.len() > 3 {
                                println!(
                                    "{}      ... and {} more blobs",
                                    "   ".repeat(depth + 3),
                                    child_node.data_blob_locs.len() - 3
                                );
                            }
                        }

                        // Try to extract and show content preview for small text files
                        if child_node.item_size <= 200 && is_text_file(child_name) {
                            show_file_content_preview(&json_node, backup_set_path, depth + 3);
                        }
                    }
                }
            }
            Ok(None) => {
                println!("{}   ⚠️  Tree data not available", indent);
            }
            Err(e) => {
                println!("{}   ❌ Failed to load tree: {}", indent, e);

                // Try to show information from JSON metadata
                if !node.data_blob_locs.is_empty() {
                    println!(
                        "{}   📊 Has {} data blob(s) in JSON metadata",
                        indent,
                        node.data_blob_locs.len()
                    );
                }
            }
        }
    } else {
        // This is a file at the root level
        stats.files += 1;
        stats.total_size += node.item_size;

        let file_icon = get_file_icon(current_path);
        println!("{}{} {}", indent, file_icon, current_path);
        println!("{}   📏 {} bytes", indent, node.item_size);

        if !node.data_blob_locs.is_empty() {
            println!("{}   💾 {} data blob(s)", indent, node.data_blob_locs.len());
        }
    }
}

fn show_file_content_preview(node: &Node, backup_set_path: &str, depth: usize) {
    if !node.data_blob_locs.is_empty() {
        let indent = "   ".repeat(depth);

        // Try to extract content from the first blob
        match node.data_blob_locs[0].extract_text_content(Path::new(backup_set_path)) {
            Ok(content) => {
                let preview = if content.len() <= 100 {
                    content.trim().to_string()
                } else {
                    format!("{}...", content.chars().take(97).collect::<String>().trim())
                };

                if !preview.is_empty() {
                    println!("{}   📄 Preview: \"{}\"", indent, preview);
                }
            }
            Err(_) => {
                // Content extraction failed - this is expected for many files
            }
        }
    }
}

fn get_file_icon(filename: &str) -> &'static str {
    let name_lower = filename.to_lowercase();
    if name_lower.ends_with(".txt") {
        "📝"
    } else if name_lower.ends_with(".md") {
        "📄"
    } else if name_lower.ends_with(".json") {
        "🗂️"
    } else if name_lower.ends_with(".rs") {
        "🦀"
    } else if name_lower.ends_with(".py") {
        "🐍"
    } else if name_lower.ends_with(".js") || name_lower.ends_with(".ts") {
        "📜"
    } else if name_lower.ends_with(".jpg")
        || name_lower.ends_with(".png")
        || name_lower.ends_with(".gif")
    {
        "🖼️"
    } else if name_lower.ends_with(".mp4")
        || name_lower.ends_with(".mov")
        || name_lower.ends_with(".avi")
    {
        "🎬"
    } else if name_lower.ends_with(".mp3")
        || name_lower.ends_with(".wav")
        || name_lower.ends_with(".flac")
    {
        "🎵"
    } else if name_lower.ends_with(".pdf") {
        "📕"
    } else if name_lower.ends_with(".zip")
        || name_lower.ends_with(".tar")
        || name_lower.ends_with(".gz")
    {
        "📦"
    } else if name_lower.contains("readme") {
        "📖"
    } else if name_lower.contains("license") {
        "📜"
    } else {
        "📄"
    }
}

fn is_text_file(filename: &str) -> bool {
    let name_lower = filename.to_lowercase();
    name_lower.ends_with(".txt")
        || name_lower.ends_with(".md")
        || name_lower.ends_with(".json")
        || name_lower.ends_with(".yaml")
        || name_lower.ends_with(".yml")
        || name_lower.ends_with(".xml")
        || name_lower.ends_with(".csv")
        || name_lower.ends_with(".log")
        || name_lower.contains("readme")
        || name_lower.contains("license")
}

fn load_tree_from_blob_loc(
    blob_loc: &arq::arq7::binary::BinaryBlobLoc,
    backup_set_path: &str,
) -> Result<arq::arq7::binary::BinaryTree, Box<dyn std::error::Error>> {
    // Convert binary blob loc to JSON blob loc
    let json_blob_loc = BlobLoc::from_binary_blob_loc(blob_loc);

    // Load the tree using the blob location
    let tree = json_blob_loc.load_tree(std::path::Path::new(backup_set_path))?;

    Ok(tree)
}
