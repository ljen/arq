//! Debug Tree Loading
//!
//! This tool focuses on testing the exact tree loading path used in the tests
//! to understand why the comprehensive test is failing.

use arq::arq7::*;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Debug Tree Loading");
    println!("{}", "=".repeat(50));

    let test_data_dir = "./tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9";

    // Step 1: Load the backup set
    println!("Step 1: Loading backup set from directory...");
    let backup_set = match BackupSet::from_directory(test_data_dir) {
        Ok(set) => {
            println!("✅ Backup set loaded successfully");
            set
        }
        Err(e) => {
            println!("❌ Failed to load backup set: {}", e);
            return Err(e.into());
        }
    };

    // Step 2: Get backup records
    println!("\nStep 2: Checking backup records...");
    let records = backup_set
        .backup_records
        .get("29F6E502-2737-4417-8023-4940D61BA375");

    let records = match records {
        Some(records) => {
            println!("✅ Found {} backup records", records.len());
            records
        }
        None => {
            println!("❌ No backup records found");
            return Ok(());
        }
    };

    // Step 3: Get first record
    println!("\nStep 3: Examining first backup record...");
    let record = match records.first() {
        Some(record) => {
            println!("✅ Got first backup record");
            record
        }
        None => {
            println!("❌ No backup records available");
            return Ok(());
        }
    };

    // Step 4: Check the node and tree blob location
    println!("\nStep 4: Checking node tree blob location...");
    match &record.node.tree_blob_loc {
        Some(tree_blob_loc) => {
            println!("✅ Node has tree blob location:");
            println!("  Blob ID: {}", tree_blob_loc.blob_identifier);
            println!("  Relative path: {}", tree_blob_loc.relative_path);
            println!("  Offset: {}", tree_blob_loc.offset);
            println!("  Length: {}", tree_blob_loc.length);
            println!("  Is packed: {}", tree_blob_loc.is_packed);
            println!("  Compression type: {}", tree_blob_loc.compression_type);
            println!(
                "  Stretch encryption key: {}",
                tree_blob_loc.stretch_encryption_key
            );
        }
        None => {
            println!("❌ Node has no tree blob location");
            return Ok(());
        }
    }

    // Step 5: Try to load the tree
    println!("\nStep 5: Attempting to load binary tree...");
    match record.node.load_tree(Path::new(test_data_dir)) {
        Ok(Some(tree)) => {
            println!("✅ Successfully loaded binary tree!");
            println!("  Tree version: {}", tree.version);
            println!("  Child nodes count: {}", tree.child_nodes.len());

            println!("\nChild nodes:");
            for (name, node) in &tree.child_nodes {
                println!(
                    "  - '{}': {}",
                    name,
                    if node.is_tree { "directory" } else { "file" }
                );
                if node.is_tree {
                    if let Some(tree_loc) = &node.tree_blob_loc {
                        println!("    Tree blob: {}", tree_loc.blob_identifier);
                    }
                }
                if !node.data_blob_locs.is_empty() {
                    println!("    Data blobs: {}", node.data_blob_locs.len());
                    for (i, blob_loc) in node.data_blob_locs.iter().enumerate() {
                        println!(
                            "      [{}]: {} ({})",
                            i, blob_loc.blob_identifier, blob_loc.length
                        );
                    }
                }
            }
        }
        Ok(None) => {
            println!("❌ Tree loading returned None");
        }
        Err(e) => {
            println!("❌ Tree loading failed: {}", e);
            println!("Error type: {:?}", e);

            // Let's try to debug the pack file directly
            if let Some(tree_blob_loc) = &record.node.tree_blob_loc {
                println!("\nDebugging pack file access...");
                // The relative path includes the backup set UUID, but we need to strip it
                let path_parts: Vec<&str> = tree_blob_loc.relative_path.split('/').collect();
                let path_without_uuid = if path_parts.len() > 2 && !path_parts[1].is_empty() {
                    // Skip the UUID part (first non-empty component)
                    path_parts[2..].join("/")
                } else {
                    // Fallback to removing just the leading slash
                    tree_blob_loc
                        .relative_path
                        .trim_start_matches('/')
                        .to_string()
                };
                let pack_path = Path::new(test_data_dir).join(&path_without_uuid);
                println!("Pack file path: {}", pack_path.display());

                if pack_path.exists() {
                    let metadata = std::fs::metadata(&pack_path)?;
                    println!("Pack file size: {} bytes", metadata.len());
                    println!(
                        "Trying to read offset {} length {}",
                        tree_blob_loc.offset, tree_blob_loc.length
                    );

                    if tree_blob_loc.offset + tree_blob_loc.length <= metadata.len() {
                        println!("✅ Offset and length are within file bounds");

                        // Try to extract the raw data
                        match tree_blob_loc.extract_content(Path::new(test_data_dir)) {
                            Ok(raw_data) => {
                                println!(
                                    "✅ Successfully extracted {} bytes of raw data",
                                    raw_data.len()
                                );

                                // Show first few bytes
                                let preview_len = std::cmp::min(32, raw_data.len());
                                println!(
                                    "First {} bytes: {:02X?}",
                                    preview_len,
                                    &raw_data[..preview_len]
                                );

                                // Try to parse as compressed tree
                                use arq::arq7::binary::BinaryTree;

                                // Debug the decompression step by step
                                println!("Debugging decompression...");

                                // Extract decompressed length
                                if raw_data.len() >= 4 {
                                    let decompressed_length = u32::from_be_bytes([
                                        raw_data[0],
                                        raw_data[1],
                                        raw_data[2],
                                        raw_data[3],
                                    ]);
                                    println!("Decompressed length: {}", decompressed_length);

                                    // Try LZ4 decompression
                                    let compressed_data = &raw_data[4..];
                                    println!("Compressed data length: {}", compressed_data.len());

                                    match lz4_flex::decompress(
                                        compressed_data,
                                        decompressed_length as usize,
                                    ) {
                                        Ok(decompressed) => {
                                            println!(
                                                "✅ LZ4 decompression successful, got {} bytes",
                                                decompressed.len()
                                            );

                                            // Show first few bytes of decompressed data
                                            let preview_len =
                                                std::cmp::min(200, decompressed.len());
                                            println!(
                                                "First {} bytes of decompressed data:",
                                                preview_len
                                            );

                                            // Print in hex dump format for easier reading
                                            for (i, chunk) in
                                                decompressed[..preview_len].chunks(16).enumerate()
                                            {
                                                print!("{:04X}: ", i * 16);
                                                for byte in chunk {
                                                    print!("{:02X} ", byte);
                                                }
                                                // Pad if chunk is less than 16 bytes
                                                for _ in chunk.len()..16 {
                                                    print!("   ");
                                                }
                                                print!(" |");
                                                for &byte in chunk {
                                                    if byte.is_ascii_graphic() || byte == b' ' {
                                                        print!("{}", byte as char);
                                                    } else {
                                                        print!(".");
                                                    }
                                                }
                                                println!("|");
                                            }

                                            // Try to parse the decompressed data as a tree
                                            let mut cursor = std::io::Cursor::new(&decompressed);
                                            match BinaryTree::from_reader(&mut cursor) {
                                                Ok(tree) => {
                                                    println!("✅ Successfully parsed binary tree from decompressed data!");
                                                    println!("  Version: {}", tree.version);
                                                    println!(
                                                        "  Children: {}",
                                                        tree.child_nodes.len()
                                                    );
                                                }
                                                Err(tree_parse_err) => {
                                                    println!("❌ Failed to parse tree from decompressed data: {}", tree_parse_err);

                                                    // Let's do detailed manual parsing to find where it breaks
                                                    println!("Starting detailed manual parse:");

                                                    let mut pos = 0;

                                                    // Parse tree header
                                                    if decompressed.len() >= pos + 12 {
                                                        let version = u32::from_be_bytes([
                                                            decompressed[pos],
                                                            decompressed[pos + 1],
                                                            decompressed[pos + 2],
                                                            decompressed[pos + 3],
                                                        ]);
                                                        pos += 4;
                                                        println!(
                                                            "  Version: {} (pos now {})",
                                                            version, pos
                                                        );

                                                        let child_count = u64::from_be_bytes([
                                                            decompressed[pos],
                                                            decompressed[pos + 1],
                                                            decompressed[pos + 2],
                                                            decompressed[pos + 3],
                                                            decompressed[pos + 4],
                                                            decompressed[pos + 5],
                                                            decompressed[pos + 6],
                                                            decompressed[pos + 7],
                                                        ]);
                                                        pos += 8;
                                                        println!(
                                                            "  Child count: {} (pos now {})",
                                                            child_count, pos
                                                        );

                                                        // Parse first child
                                                        if decompressed.len() > pos {
                                                            let name_not_null = decompressed[pos];
                                                            pos += 1;
                                                            println!("  Child 0 name not null: {} (pos now {})", name_not_null, pos);

                                                            if name_not_null != 0
                                                                && decompressed.len() >= pos + 8
                                                            {
                                                                let name_length =
                                                                    u64::from_be_bytes([
                                                                        decompressed[pos],
                                                                        decompressed[pos + 1],
                                                                        decompressed[pos + 2],
                                                                        decompressed[pos + 3],
                                                                        decompressed[pos + 4],
                                                                        decompressed[pos + 5],
                                                                        decompressed[pos + 6],
                                                                        decompressed[pos + 7],
                                                                    ]);
                                                                pos += 8;
                                                                println!("  Child 0 name length: {} (pos now {})", name_length, pos);

                                                                if name_length > 0
                                                                    && name_length < 100
                                                                    && decompressed.len()
                                                                        >= pos
                                                                            + name_length as usize
                                                                {
                                                                    let name_bytes = &decompressed
                                                                        [pos..pos
                                                                            + name_length as usize];
                                                                    let name =
                                                                        String::from_utf8_lossy(
                                                                            name_bytes,
                                                                        );
                                                                    pos += name_length as usize;
                                                                    println!("  Child 0 name: '{}' (pos now {})", name, pos);

                                                                    // Parse node header
                                                                    if decompressed.len() > pos {
                                                                        let is_tree =
                                                                            decompressed[pos] != 0;
                                                                        pos += 1;
                                                                        println!("  Child 0 is_tree: {} (pos now {})", is_tree, pos);

                                                                        // Skip tree blob location if this is a tree
                                                                        if is_tree {
                                                                            println!("  Skipping tree blob location parsing for now");
                                                                        }

                                                                        // Parse computer OS type
                                                                        if decompressed.len()
                                                                            >= pos + 4
                                                                        {
                                                                            let os_type = u32::from_be_bytes([
                                                                                decompressed[pos],
                                                                                decompressed[pos + 1],
                                                                                decompressed[pos + 2],
                                                                                decompressed[pos + 3],
                                                                            ]);
                                                                            pos += 4;
                                                                            println!("  Child 0 OS type: {} (pos now {})", os_type, pos);

                                                                            // Parse data blob count
                                                                            if decompressed.len()
                                                                                >= pos + 8
                                                                            {
                                                                                let blob_count = u64::from_be_bytes([
                                                                                    decompressed[pos],
                                                                                    decompressed[pos + 1],
                                                                                    decompressed[pos + 2],
                                                                                    decompressed[pos + 3],
                                                                                    decompressed[pos + 4],
                                                                                    decompressed[pos + 5],
                                                                                    decompressed[pos + 6],
                                                                                    decompressed[pos + 7],
                                                                                ]);
                                                                                pos += 8;
                                                                                println!("  Child 0 blob count: {} (pos now {})", blob_count, pos);

                                                                                // Try to parse first blob location
                                                                                if blob_count > 0 {
                                                                                    println!("  Parsing first blob location at position {}", pos);

                                                                                    if decompressed
                                                                                        .len()
                                                                                        > pos
                                                                                    {
                                                                                        let blob_id_not_null = decompressed[pos];
                                                                                        pos += 1;
                                                                                        println!("    Blob ID not null: {} (pos now {})", blob_id_not_null, pos);

                                                                                        if blob_id_not_null != 0 && decompressed.len() >= pos + 8 {
                                                                                            let blob_id_length = u64::from_be_bytes([
                                                                                                decompressed[pos],
                                                                                                decompressed[pos + 1],
                                                                                                decompressed[pos + 2],
                                                                                                decompressed[pos + 3],
                                                                                                decompressed[pos + 4],
                                                                                                decompressed[pos + 5],
                                                                                                decompressed[pos + 6],
                                                                                                decompressed[pos + 7],
                                                                                            ]);
                                                                                            pos += 8;
                                                                                            println!("    Blob ID length: {} (pos now {})", blob_id_length, pos);

                                                                                            if blob_id_length > 0 && blob_id_length < 200 && decompressed.len() >= pos + blob_id_length as usize {
                                                                                                pos += blob_id_length as usize;
                                                                                                println!("    Skipped blob ID, pos now {}", pos);

                                                                                                // isPacked
                                                                                                if decompressed.len() > pos {
                                                                                                    let is_packed = decompressed[pos];
                                                                                                    pos += 1;
                                                                                                    println!("    isPacked: {} (pos now {})", is_packed, pos);

                                                                                                    // Path null flag
                                                                                                    if decompressed.len() > pos {
                                                                                                        let path_not_null = decompressed[pos];
                                                                                                        pos += 1;
                                                                                                        println!("    Path not null: {} (pos now {})", path_not_null, pos);

                                                                                                        if path_not_null != 0 {
                                                                                                            // Read path length and data
                                                                                                            if decompressed.len() >= pos + 8 {
                                                                                                                let path_length = u64::from_be_bytes([
                                                                                                                    decompressed[pos],
                                                                                                                    decompressed[pos + 1],
                                                                                                                    decompressed[pos + 2],
                                                                                                                    decompressed[pos + 3],
                                                                                                                    decompressed[pos + 4],
                                                                                                                    decompressed[pos + 5],
                                                                                                                    decompressed[pos + 6],
                                                                                                                    decompressed[pos + 7],
                                                                                                                ]);
                                                                                                                pos += 8;
                                                                                                                println!("    Path length: {} (pos now {})", path_length, pos);

                                                                                                                if path_length > 0 && path_length < 500 && decompressed.len() >= pos + path_length as usize {
                                                                                                                    let path_bytes = &decompressed[pos..pos + path_length as usize];
                                                                                                                    let path = String::from_utf8_lossy(path_bytes);
                                                                                                                    pos += path_length as usize;
                                                                                                                    println!("    Path: '{}' (pos now {})", path, pos);
                                                                                                                }
                                                                                                            }
                                                                                                        } else {
                                                                                                            println!("    Path is null, skipping path data");
                                                                                                        }

                                                                                                        // Show next few bytes for offset/length debugging
                                                                                                        if decompressed.len() >= pos + 16 {
                                                                                                            println!("    Next 16 bytes for offset/length: {:02X?}", &decompressed[pos..pos + 16]);
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(decomp_err) => {
                                            println!("❌ LZ4 decompression failed: {}", decomp_err);
                                        }
                                    }
                                } else {
                                    println!(
                                        "❌ Raw data too short for decompressed length header"
                                    );
                                }

                                match BinaryTree::from_compressed_data(&raw_data) {
                                    Ok(tree) => {
                                        println!(
                                            "✅ Successfully parsed binary tree from raw data!"
                                        );
                                        println!("  Version: {}", tree.version);
                                        println!("  Children: {}", tree.child_nodes.len());
                                    }
                                    Err(parse_err) => {
                                        println!("❌ Failed to parse binary tree: {}", parse_err);
                                    }
                                }
                            }
                            Err(extract_err) => {
                                println!("❌ Failed to extract content: {}", extract_err);
                            }
                        }
                    } else {
                        println!("❌ Offset/length exceed file bounds");
                    }
                } else {
                    println!("❌ Pack file does not exist");
                }
            }
        }
    }

    Ok(())
}
