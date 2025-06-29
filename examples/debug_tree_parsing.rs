//! Debug Tree Parsing Example
//!
//! This example provides detailed debugging information about the binary tree parsing
//! process to help identify where parsing failures occur.

use arq::arq7::*;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backup_set_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9";

    println!("🔍 Debug Tree Parsing");
    println!("{}", "=".repeat(50));

    // Load the backup set
    let backup_set = BackupSet::from_directory(backup_set_path)?;

    for (folder_uuid, records) in &backup_set.backup_records {
        println!("\n📂 Folder: {}", folder_uuid);

        for (record_idx, record) in records.iter().enumerate() {
            println!("\n📝 Record #{}", record_idx + 1);
            println!(
                "   📊 Expected contained files: {}",
                record.node.contained_files_count.unwrap_or(0)
            );

            if let Some(tree_blob_loc) = &record.node.tree_blob_loc {
                println!("🌳 Tree blob location found:");
                println!("   Path: {}", tree_blob_loc.relative_path);
                println!("   Offset: {}", tree_blob_loc.offset);
                println!("   Length: {}", tree_blob_loc.length);
                println!("   Compression: {}", tree_blob_loc.compression_type);
                println!("   Is packed: {}", tree_blob_loc.is_packed);

                // Step 1: Try to load raw data
                println!("\n🔧 Step 1: Loading raw data...");
                match tree_blob_loc.load_data(Path::new(backup_set_path), None) {
                    Ok(raw_data) => {
                        println!("   ✅ Raw data loaded: {} bytes", raw_data.len());
                        print_hex_dump("Raw data", &raw_data, 64);

                        // Step 2: Try LZ4 decompression if needed
                        println!("\n🔧 Step 2: Decompressing data...");
                        let decompressed_data = if tree_blob_loc.compression_type == 2 {
                            match decompress_lz4_data(&raw_data) {
                                Ok(data) => {
                                    println!("   ✅ LZ4 decompressed: {} bytes", data.len());
                                    print_hex_dump("Decompressed data", &data, 128);
                                    data
                                }
                                Err(e) => {
                                    println!("   ❌ LZ4 decompression failed: {}", e);
                                    continue;
                                }
                            }
                        } else {
                            println!("   ℹ️  No compression, using raw data");
                            raw_data
                        };

                        // Step 3: Parse tree header
                        println!("\n🔧 Step 3: Parsing tree header...");
                        match parse_tree_header(&decompressed_data) {
                            Ok((version, node_count)) => {
                                println!("   ✅ Tree header parsed:");
                                println!("      Version: {}", version);
                                println!("      Node count: {}", node_count);

                                // Step 4: Parse ALL node names
                                println!("\n🔧 Step 4: Parsing all node names...");
                                match parse_all_node_names(&decompressed_data, node_count) {
                                    Ok(names) => {
                                        println!("   ✅ Node names parsed:");
                                        for (i, name) in names.iter().enumerate() {
                                            if name.is_empty() {
                                                println!("      {}: <empty string>", i);
                                            } else {
                                                println!("      {}: '{}'", i, name);
                                            }
                                        }

                                        // Step 5: Try our actual binary parsing
                                        println!("\n🔧 Step 5: Testing actual binary parsing...");
                                        let mut cursor = std::io::Cursor::new(&decompressed_data);
                                        match arq::arq7::binary::BinaryTree::from_reader(
                                            &mut cursor,
                                        ) {
                                            Ok(tree) => {
                                                println!("   ✅ Binary tree parsed successfully!");
                                                println!("      Version: {}", tree.version);
                                                println!(
                                                    "      Child nodes: {}",
                                                    tree.child_nodes.len()
                                                );
                                                for (name, node) in &tree.child_nodes {
                                                    let display_name = if name.is_empty() {
                                                        "<empty>".to_string()
                                                    } else {
                                                        name.clone()
                                                    };
                                                    println!(
                                                        "         '{}': is_tree={}, data_blobs={}",
                                                        display_name,
                                                        node.is_tree,
                                                        node.data_blob_locs.len()
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                println!("   ❌ Binary tree parsing failed: {}", e);
                                            }
                                        }

                                        // Step 6: Test the actual load_tree method
                                        println!("\n🔧 Step 6: Testing actual load_tree method...");
                                        match tree_blob_loc
                                            .load_tree(std::path::Path::new(backup_set_path))
                                        {
                                            Ok(tree) => {
                                                println!("   ✅ load_tree() method worked!");
                                                println!("      Version: {}", tree.version);
                                                println!(
                                                    "      Child nodes: {}",
                                                    tree.child_nodes.len()
                                                );
                                                for (name, node) in &tree.child_nodes {
                                                    let display_name = if name.is_empty() {
                                                        "<empty>".to_string()
                                                    } else if name.len() > 50 {
                                                        format!("{}...", &name[..50])
                                                    } else {
                                                        name.clone()
                                                    };
                                                    println!(
                                                        "         '{}': is_tree={}, size={}",
                                                        display_name, node.is_tree, node.item_size
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                println!("   ❌ load_tree() method failed: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => println!("   ❌ Node name parsing failed: {}", e),
                                }
                            }
                            Err(e) => println!("   ❌ Tree header parsing failed: {}", e),
                        }
                    }
                    Err(e) => {
                        println!("   ❌ Raw data loading failed: {}", e);
                    }
                }
            }

            println!("\n{}", "=".repeat(50));
        }
    }

    Ok(())
}

fn print_hex_dump(label: &str, data: &[u8], max_bytes: usize) {
    let len = std::cmp::min(data.len(), max_bytes);
    println!("   {} (first {} bytes):", label, len);

    for (i, chunk) in data[..len].chunks(16).enumerate() {
        print!("   {:04X}: ", i * 16);

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02X} ", byte);
            if j == 7 {
                print!(" ");
            }
        }

        // Pad if needed
        for _ in chunk.len()..16 {
            print!("   ");
            if chunk.len() <= 8 {
                print!(" ");
            }
        }

        print!(" |");

        // ASCII representation
        for byte in chunk {
            if *byte >= 32 && *byte <= 126 {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }

        println!("|");
    }
}

fn decompress_lz4_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if data.len() < 4 {
        return Err("Data too short for LZ4 format".into());
    }

    // First 4 bytes are decompressed length
    let decompressed_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    // Remaining data is LZ4 compressed
    let compressed_data = &data[4..];
    let decompressed = lz4_flex::decompress(compressed_data, decompressed_length as usize)?;

    Ok(decompressed)
}

fn parse_tree_header(data: &[u8]) -> Result<(u32, u64), Box<dyn std::error::Error>> {
    if data.len() < 12 {
        return Err("Data too short for tree header".into());
    }

    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let node_count = u64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    println!(
        "   📊 Raw header bytes: version={}, node_count={}",
        version, node_count
    );

    Ok((version, node_count))
}

fn parse_all_node_names(
    data: &[u8],
    node_count: u64,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut names = Vec::new();
    let mut offset = 12; // Skip tree header (version + unknown + node_count)

    println!(
        "   🔍 Parsing {} node names starting at offset {}",
        node_count, offset
    );

    for i in 0..node_count {
        if offset >= data.len() {
            println!(
                "   ⚠️  Not enough data for node {} name at offset {}",
                i, offset
            );
            break;
        }

        println!("   📍 Node {} starts at offset {}", i, offset);

        // Read isNotNull flag
        let is_not_null = data[offset] != 0;
        offset += 1;
        println!("   📝 Node {} isNotNull: {}", i, is_not_null);

        if !is_not_null {
            names.push(String::new());
            println!("   📝 Node {} has null name", i);
            continue;
        }

        // Read string length
        if offset + 8 > data.len() {
            println!(
                "   ⚠️  Not enough data for node {} string length at offset {}",
                i, offset
            );
            break;
        }

        let string_length = u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8;
        println!("   📝 Node {} string length: {}", i, string_length);

        // Safety check
        if string_length > 1024 {
            println!(
                "   ⚠️  Node {} string length too large: {}",
                i, string_length
            );
            break;
        }

        // Read string data
        if offset + string_length as usize > data.len() {
            println!(
                "   ⚠️  Not enough data for node {} string content at offset {}",
                i, offset
            );
            break;
        }

        let string_bytes = &data[offset..offset + string_length as usize];
        let name = String::from_utf8_lossy(string_bytes).to_string();
        names.push(name.clone());
        println!("   📝 Node {} name: '{}'", i, name);

        offset += string_length as usize;
        println!("   📍 Next node will start at offset {}", offset);
    }

    println!("   📊 Total names parsed: {}", names.len());
    Ok(names)
}

fn debug_parse_first_node(data: &[u8], node_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate offset to first node data
    let mut offset = 12; // Skip tree header

    // Skip first node name
    let is_not_null = data[offset] != 0;
    offset += 1;

    if is_not_null {
        let string_length = u64::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        offset += 8 + string_length as usize;
    }

    println!(
        "   📍 First node '{}' data starts at offset: {}",
        node_name, offset
    );

    if offset >= data.len() {
        return Err("No data available for first node".into());
    }

    // Show the raw bytes where node parsing should start
    let remaining_data = &data[offset..];
    print_hex_dump("First node raw data", remaining_data, 32);

    // Try to parse node fields step by step
    let mut node_offset = offset;

    // 1. Is tree flag
    if node_offset >= data.len() {
        return Err("No data for is_tree flag".into());
    }
    let is_tree = data[node_offset] != 0;
    node_offset += 1;
    println!("   🌳 is_tree: {}", is_tree);

    // 2. Tree blob location (if is_tree)
    if is_tree {
        println!("   📦 Parsing tree blob location...");
        match parse_blob_location_debug(&data, &mut node_offset) {
            Ok(()) => println!("   ✅ Tree blob location parsed"),
            Err(e) => return Err(format!("Tree blob location parsing failed: {}", e).into()),
        }
    }

    // 3. Computer OS type
    if node_offset + 4 > data.len() {
        return Err("No data for computer OS type".into());
    }
    let os_type = u32::from_be_bytes([
        data[node_offset],
        data[node_offset + 1],
        data[node_offset + 2],
        data[node_offset + 3],
    ]);
    node_offset += 4;
    println!("   💻 Computer OS type: {}", os_type);

    // 4. Data blob count
    if node_offset + 8 > data.len() {
        return Err("No data for data blob count".into());
    }
    let data_blob_count = u64::from_be_bytes([
        data[node_offset],
        data[node_offset + 1],
        data[node_offset + 2],
        data[node_offset + 3],
        data[node_offset + 4],
        data[node_offset + 5],
        data[node_offset + 6],
        data[node_offset + 7],
    ]);
    node_offset += 8;
    println!("   📊 Data blob count: {}", data_blob_count);

    // Show remaining data
    if node_offset < data.len() {
        let remaining = &data[node_offset..];
        print_hex_dump("Remaining node data", remaining, 32);
    }

    Ok(())
}

fn parse_blob_location_debug(
    data: &[u8],
    offset: &mut usize,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse BlobLocation step by step with debugging

    // 1. Blob identifier string
    if *offset >= data.len() {
        return Err("No data for blob identifier".into());
    }

    let is_not_null = data[*offset] != 0;
    *offset += 1;

    if is_not_null {
        if *offset + 8 > data.len() {
            return Err("No data for blob identifier length".into());
        }

        let string_length = u64::from_be_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        *offset += 8;

        if string_length > 1024 {
            return Err(format!("Blob identifier too long: {}", string_length).into());
        }

        if *offset + string_length as usize > data.len() {
            return Err("No data for blob identifier content".into());
        }

        let identifier = String::from_utf8_lossy(&data[*offset..*offset + string_length as usize]);
        *offset += string_length as usize;

        println!("      🔖 Blob identifier: '{}'", identifier);
    } else {
        println!("      🔖 Blob identifier: null");
    }

    // 2. Is packed flag
    if *offset >= data.len() {
        return Err("No data for is_packed flag".into());
    }
    let is_packed = data[*offset] != 0;
    *offset += 1;
    println!("      📦 Is packed: {}", is_packed);

    // 3. Relative path string
    if *offset >= data.len() {
        return Err("No data for relative path".into());
    }

    let is_not_null = data[*offset] != 0;
    *offset += 1;

    if is_not_null {
        if *offset + 8 > data.len() {
            return Err("No data for relative path length".into());
        }

        let string_length = u64::from_be_bytes([
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        *offset += 8;

        if string_length > 1024 {
            return Err(format!("Relative path too long: {}", string_length).into());
        }

        if *offset + string_length as usize > data.len() {
            return Err("No data for relative path content".into());
        }

        let path = String::from_utf8_lossy(&data[*offset..*offset + string_length as usize]);
        *offset += string_length as usize;

        println!("      📁 Relative path: '{}'", path);
    } else {
        println!("      📁 Relative path: null");
    }

    // 4. Offset and length
    if *offset + 16 > data.len() {
        return Err("No data for offset and length".into());
    }

    let blob_offset = u64::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;

    let blob_length = u64::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    *offset += 8;

    println!("      📍 Offset: {}, Length: {}", blob_offset, blob_length);

    // 5. Stretch encryption key flag
    if *offset >= data.len() {
        return Err("No data for stretch encryption key flag".into());
    }
    let stretch_key = data[*offset] != 0;
    *offset += 1;
    println!("      🔐 Stretch encryption key: {}", stretch_key);

    // 6. Compression type
    if *offset + 4 > data.len() {
        return Err("No data for compression type".into());
    }
    let compression_type = u32::from_be_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    println!("      🗜️ Compression type: {}", compression_type);

    Ok(())
}
