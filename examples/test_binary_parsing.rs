//! Detailed Binary Tree Parsing Test
//!
//! This test specifically focuses on parsing the binary tree data we know exists
//! in the pack files, using the insights from the pack file analyzer.

use arq::arq7::binary::ArqBinaryReader;
use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Binary Tree Parsing");
    println!("{}", "=".repeat(50));

    let pack_file_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/89/88F120-159A-4AFF-A047-1C59ED169CE8.pack";
    let offset = 311;
    let length = 512;

    // Step 1: Extract and decompress the data
    let decompressed_data = extract_and_decompress(pack_file_path, offset, length)?;

    // Step 2: Analyze the decompressed data structure
    analyze_binary_structure(&decompressed_data);

    // Step 3: Try manual parsing
    manual_tree_parsing(&decompressed_data)?;

    // Step 4: Test our binary parsing utilities
    test_binary_parsing_utilities(&decompressed_data)?;

    Ok(())
}

fn extract_and_decompress(
    path: &str,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = BufReader::new(File::open(path)?);

    // Seek to the known offset
    file.seek(SeekFrom::Start(offset))?;

    // Read the data
    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer)?;

    println!("📦 Raw data from pack file:");
    println!("   Offset: {}, Length: {}", offset, length);
    println!("   First 32 bytes: {:02X?}", &buffer[0..32]);

    // Extract decompressed length
    let decompressed_length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    println!("   Indicated decompressed length: {}", decompressed_length);

    // Decompress with LZ4
    let decompressed = lz4_flex::decompress(&buffer[4..], decompressed_length as usize)?;
    println!(
        "   ✅ Decompressed {} bytes successfully",
        decompressed.len()
    );

    Ok(decompressed)
}

fn analyze_binary_structure(data: &[u8]) {
    println!("\n🔬 Analyzing Decompressed Binary Structure");
    println!("{}", "-".repeat(40));

    println!("Total length: {} bytes", data.len());
    println!(
        "First 64 bytes: {:02X?}",
        &data[0..std::cmp::min(64, data.len())]
    );

    // Try interpreting the beginning as tree structure
    if data.len() >= 12 {
        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let child_count = u64::from_be_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        println!("Tree version: {}", version);
        println!("Child count: {}", child_count);

        if child_count > 0 && child_count < 100 {
            println!("Child count seems reasonable, analyzing children...");

            let mut offset = 12;
            for i in 0..std::cmp::min(child_count, 5) {
                if offset + 8 < data.len() {
                    // Try to read string length
                    let str_len = u64::from_be_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);

                    if str_len > 0 && str_len < 256 && offset + 8 + str_len as usize <= data.len() {
                        let name_bytes = &data[offset + 8..offset + 8 + str_len as usize];
                        if let Ok(name) = String::from_utf8(name_bytes.to_vec()) {
                            println!("  Child {}: '{}' (len={})", i, name, str_len);
                            offset += 8 + str_len as usize;
                        } else {
                            println!("  Child {}: Invalid UTF-8 at offset {}", i, offset);
                            break;
                        }
                    } else {
                        println!(
                            "  Child {}: Invalid string length {} at offset {}",
                            i, str_len, offset
                        );
                        break;
                    }
                } else {
                    println!("  Child {}: Not enough data remaining", i);
                    break;
                }
            }
        }
    }
}

fn manual_tree_parsing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🔧 Manual Tree Parsing");
    println!("{}", "-".repeat(40));

    let mut cursor = std::io::Cursor::new(data);

    // Read tree version
    let version = cursor.read_u32::<BigEndian>()?;
    println!("Tree version: {}", version);

    // Read child count
    let child_count = cursor.read_u64::<BigEndian>()?;
    println!("Child count: {}", child_count);

    if child_count > 0 && child_count < 10 {
        for i in 0..child_count {
            println!("  Parsing child {}...", i);

            // Read child name using Arq string format
            let name_is_not_null = cursor.read_u8()? == 1;
            if !name_is_not_null {
                println!("    Child {} has null name", i);
                continue;
            }

            let name_length = cursor.read_u64::<BigEndian>()?;
            println!("    Name length: {}", name_length);

            if name_length > 0 && name_length < 256 {
                let mut name_bytes = vec![0u8; name_length as usize];
                cursor.read_exact(&mut name_bytes)?;

                // Handle null termination
                let end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                let name = String::from_utf8(name_bytes[..end].to_vec())?;
                println!("    Child name: '{}'", name);

                // Try to read node data
                println!("    Reading node for '{}'...", name);
                match parse_node_header(&mut cursor) {
                    Ok(node_info) => {
                        println!(
                            "      Node type: {}",
                            if node_info.is_tree {
                                "directory"
                            } else {
                                "file"
                            }
                        );
                        println!("      Computer OS: {}", node_info.computer_os_type);
                        println!("      Item size: {}", node_info.item_size);
                        println!("      Data blob count: {}", node_info.data_blob_count);
                    }
                    Err(e) => {
                        println!("      ❌ Failed to parse node: {}", e);
                        break;
                    }
                }
            } else {
                println!("    Invalid name length: {}", name_length);
                break;
            }
        }
    } else {
        println!("Invalid child count: {}", child_count);
    }

    Ok(())
}

#[derive(Debug)]
struct NodeInfo {
    is_tree: bool,
    computer_os_type: u32,
    item_size: u64,
    data_blob_count: u64,
}

fn parse_node_header(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<NodeInfo, Box<dyn std::error::Error>> {
    // Node format according to Arq docs:
    // [Bool:isTree]
    // [BlobLoc:treeBlobLoc] /* present if isTree is true */
    // [UInt32:computerOSType]
    // [UInt64:dataBlobLocsCount]

    let is_tree = cursor.read_u8()? == 1;

    // If it's a tree, skip the tree blob loc for now
    if is_tree {
        // Skip tree blob loc parsing for now - it's complex
        // Just skip some bytes to get to the OS type
        skip_blob_loc(cursor)?;
    }

    let computer_os_type = cursor.read_u32::<BigEndian>()?;
    let data_blob_count = cursor.read_u64::<BigEndian>()?;

    // Skip data blob locs for now
    for _ in 0..data_blob_count {
        skip_blob_loc(cursor)?;
    }

    // Skip ACL blob loc
    let acl_present = cursor.read_u8()? == 1;
    if acl_present {
        skip_blob_loc(cursor)?;
    }

    // Read xattrs count and skip them
    let xattrs_count = cursor.read_u64::<BigEndian>()?;
    for _ in 0..xattrs_count {
        skip_blob_loc(cursor)?;
    }

    // Read item size
    let item_size = cursor.read_u64::<BigEndian>()?;

    Ok(NodeInfo {
        is_tree,
        computer_os_type,
        item_size,
        data_blob_count,
    })
}

fn skip_blob_loc(cursor: &mut std::io::Cursor<&[u8]>) -> Result<(), Box<dyn std::error::Error>> {
    // BlobLoc format:
    // [String:blobIdentifier]
    // [Bool:isPacked]
    // [String:relativePath]
    // [UInt64:offset]
    // [UInt64:length]
    // [Bool:stretchEncryptionKey]
    // [UInt32:compressionType]

    // Skip blob identifier string
    skip_arq_string(cursor)?;

    // Skip isPacked bool
    cursor.read_u8()?;

    // Skip relative path string
    skip_arq_string(cursor)?;

    // Skip offset and length
    cursor.read_u64::<BigEndian>()?;
    cursor.read_u64::<BigEndian>()?;

    // Skip stretch encryption key
    cursor.read_u8()?;

    // Skip compression type
    cursor.read_u32::<BigEndian>()?;

    Ok(())
}

fn skip_arq_string(cursor: &mut std::io::Cursor<&[u8]>) -> Result<(), Box<dyn std::error::Error>> {
    let is_not_null = cursor.read_u8()? == 1;
    if is_not_null {
        let length = cursor.read_u64::<BigEndian>()?;
        cursor.seek(SeekFrom::Current(length as i64))?;
    }
    Ok(())
}

fn test_binary_parsing_utilities(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🛠️ Testing Binary Parsing Utilities");
    println!("{}", "-".repeat(40));

    let mut cursor = std::io::Cursor::new(data);

    // Test ArqBinaryReader methods
    println!("Testing ArqBinaryReader methods:");

    // Reset cursor
    cursor.set_position(0);

    let version = cursor.read_arq_u32()?;
    println!("  Version: {}", version);

    let child_count = cursor.read_arq_u64()?;
    println!("  Child count: {}", child_count);

    if child_count > 0 && child_count < 5 {
        for i in 0..child_count {
            match cursor.read_arq_string()? {
                Some(name) => println!("  Child {}: '{}'", i, name),
                None => println!("  Child {}: null name", i),
            }

            // For now, just skip the rest of the node data
            // In a real implementation, we'd parse the full node
            break; // Stop after first child to avoid parsing errors
        }
    }

    Ok(())
}
