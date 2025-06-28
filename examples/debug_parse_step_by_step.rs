//! Step-by-step binary parsing debug tool
//!
//! This tool parses the tree data byte by byte to understand exactly
//! where the parsing is going wrong and what the correct structure should be.

use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Step-by-Step Binary Parsing Debug");
    println!("{}", "=".repeat(50));

    let pack_file_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/89/88F120-159A-4AFF-A047-1C59ED169CE8.pack";
    let offset = 311;
    let length = 512;

    // Extract and decompress the data
    let data = extract_and_decompress(pack_file_path, offset, length)?;

    // Parse step by step
    parse_tree_step_by_step(&data)?;

    Ok(())
}

fn extract_and_decompress(
    path: &str,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = BufReader::new(File::open(path)?);
    file.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer)?;

    let decompressed_length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let decompressed = lz4_flex::decompress(&buffer[4..], decompressed_length as usize)?;

    println!("Successfully decompressed {} bytes", decompressed.len());
    Ok(decompressed)
}

fn parse_tree_step_by_step(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 Step-by-Step Tree Parsing");
    println!("{}", "-".repeat(40));

    let mut pos = 0;

    // Parse tree header
    println!("=== TREE HEADER ===");
    let version = read_u32_at(data, pos)?;
    println!(
        "Pos {}: Version = {} (bytes: {:02X?})",
        pos,
        version,
        &data[pos..pos + 4]
    );
    pos += 4;

    let child_count = read_u64_at(data, pos)?;
    println!(
        "Pos {}: Child Count = {} (bytes: {:02X?})",
        pos,
        child_count,
        &data[pos..pos + 8]
    );
    pos += 8;

    // Parse each child
    for i in 0..child_count {
        println!("\n=== CHILD {} ===", i);
        pos = parse_child_at_position(data, pos, i)?;
    }

    println!("\n=== REMAINING DATA ===");
    if pos < data.len() {
        println!(
            "Remaining {} bytes from position {}:",
            data.len() - pos,
            pos
        );
        print_hex_section(&data[pos..], pos);
    } else {
        println!("All data consumed.");
    }

    Ok(())
}

fn parse_child_at_position(
    data: &[u8],
    mut pos: usize,
    child_index: u64,
) -> Result<usize, Box<dyn std::error::Error>> {
    println!("Starting child {} at position {}", child_index, pos);

    // Parse child name
    let name_not_null = data[pos];
    println!(
        "Pos {}: Name not null flag = {} (0x{:02X})",
        pos, name_not_null, name_not_null
    );
    pos += 1;

    let child_name = if name_not_null != 0 {
        let name_length = read_u64_at(data, pos)?;
        println!(
            "Pos {}: Name length = {} (bytes: {:02X?})",
            pos,
            name_length,
            &data[pos..pos + 8]
        );
        pos += 8;

        if name_length > 0 && name_length < 256 {
            let name_bytes = &data[pos..pos + name_length as usize];
            let name = String::from_utf8_lossy(name_bytes);
            println!(
                "Pos {}: Name = '{}' (bytes: {:02X?})",
                pos, name, name_bytes
            );
            pos += name_length as usize;
            Some(name.to_string())
        } else {
            println!("Invalid name length: {}", name_length);
            None
        }
    } else {
        println!("Child has null/empty name");
        None
    };

    // Parse node
    println!("--- NODE DATA ---");
    let node_start = pos;

    // Node: [Bool:isTree]
    let is_tree = data[pos] != 0;
    println!("Pos {}: isTree = {} (0x{:02X})", pos, is_tree, data[pos]);
    pos += 1;

    // Node: [BlobLoc:treeBlobLoc] /* present if isTree is true */
    if is_tree {
        println!("Parsing tree blob location:");
        pos = parse_blob_loc_at_position(data, pos, "treeBlobLoc")?;
    }

    // Node: [UInt32:computerOSType]
    let os_type = read_u32_at(data, pos)?;
    println!(
        "Pos {}: computerOSType = {} (bytes: {:02X?})",
        pos,
        os_type,
        &data[pos..pos + 4]
    );
    pos += 4;

    // Node: [UInt64:dataBlobLocsCount]
    let data_blob_count = read_u64_at(data, pos)?;
    println!(
        "Pos {}: dataBlobLocsCount = {} (bytes: {:02X?})",
        pos,
        data_blob_count,
        &data[pos..pos + 8]
    );
    pos += 8;

    // Parse data blob locations
    for j in 0..data_blob_count {
        println!("Parsing data blob location {}:", j);
        pos = parse_blob_loc_at_position(data, pos, &format!("dataBlobLoc[{}]", j))?;
    }

    // Show what we've parsed so far
    let node_bytes_consumed = pos - node_start;
    println!(
        "Node parsing consumed {} bytes (from {} to {})",
        node_bytes_consumed, node_start, pos
    );

    // Try to parse a few more fields to see the structure
    if pos + 16 < data.len() {
        println!("Next few fields preview:");

        // [Bool:aclBlobLocIsNotNil]
        let acl_not_nil = data[pos] != 0;
        println!(
            "Pos {}: aclBlobLocIsNotNil = {} (0x{:02X})",
            pos, acl_not_nil, data[pos]
        );
        let mut preview_pos = pos + 1;

        if acl_not_nil {
            println!("Would parse ACL blob location here");
            // Skip ACL blob loc parsing for preview
        }

        // [UInt64:xattrsBlobLocCount]
        if preview_pos + 8 <= data.len() {
            let xattrs_count = read_u64_at(data, preview_pos)?;
            println!(
                "Pos {}: xattrsBlobLocCount = {} (bytes: {:02X?})",
                preview_pos,
                xattrs_count,
                &data[preview_pos..preview_pos + 8]
            );
        }
    }

    println!("Child {} summary:", child_index);
    println!("  Name: {:?}", child_name);
    println!("  Is tree: {}", is_tree);
    println!("  OS type: {}", os_type);
    println!("  Data blob count: {}", data_blob_count);
    println!(
        "  Consumed {} bytes total",
        pos - (node_start
            - if child_name.is_some() {
                9 + child_name.as_ref().unwrap().len()
            } else {
                1
            })
    );

    // For debugging, let's not try to parse the complete node
    // Instead, let's see where the next child should start
    println!("Current position after partial parsing: {}", pos);

    // Look ahead to find the next child
    if child_index == 0 {
        // After the first child, look for the second child's name
        println!(
            "Looking for second child starting around position {}...",
            pos
        );

        // Search for potential child name patterns
        for search_pos in pos..std::cmp::min(pos + 200, data.len() - 20) {
            // Look for string pattern: non-zero byte (not null flag) followed by reasonable length
            if data[search_pos] != 0 {
                if search_pos + 8 < data.len() {
                    if let Ok(potential_length) = read_u64_at(data, search_pos + 1) {
                        if potential_length > 0 && potential_length < 50 {
                            if search_pos + 9 + potential_length as usize <= data.len() {
                                let potential_name_bytes = &data
                                    [search_pos + 9..search_pos + 9 + potential_length as usize];
                                if let Ok(potential_name) =
                                    String::from_utf8(potential_name_bytes.to_vec())
                                {
                                    if potential_name
                                        .chars()
                                        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                                    {
                                        println!(
                                            "  Potential child name at pos {}: '{}' (length: {})",
                                            search_pos, potential_name, potential_length
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(pos)
}

fn parse_blob_loc_at_position(
    data: &[u8],
    mut pos: usize,
    name: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    println!("  Parsing {} at position {}", name, pos);

    // [String:blobIdentifier] /* can't be null */
    let id_not_null = data[pos];
    println!(
        "  Pos {}: Blob ID not null flag = {} (0x{:02X})",
        pos, id_not_null, id_not_null
    );
    pos += 1;

    if id_not_null != 0 {
        let id_length = read_u64_at(data, pos)?;
        println!(
            "  Pos {}: Blob ID length = {} (bytes: {:02X?})",
            pos,
            id_length,
            &data[pos..pos + 8]
        );
        pos += 8;

        if id_length > 0 && id_length < 256 {
            let id_bytes = &data[pos..pos + id_length as usize];
            let id = String::from_utf8_lossy(id_bytes);
            println!(
                "  Pos {}: Blob ID = '{}' (first 32 chars)",
                pos,
                &id.chars().take(32).collect::<String>()
            );
            pos += id_length as usize;
        } else if id_length > 0 {
            println!("  Skipping very long blob ID of {} bytes", id_length);
            pos += id_length as usize;
        }
    }

    // [Bool:isPacked]
    let is_packed = data[pos] != 0;
    println!(
        "  Pos {}: isPacked = {} (0x{:02X})",
        pos, is_packed, data[pos]
    );
    pos += 1;

    // [String:relativePath]
    let path_not_null = data[pos];
    println!(
        "  Pos {}: Path not null flag = {} (0x{:02X})",
        pos, path_not_null, path_not_null
    );
    pos += 1;

    if path_not_null != 0 {
        let path_length = read_u64_at(data, pos)?;
        println!(
            "  Pos {}: Path length = {} (bytes: {:02X?})",
            pos,
            path_length,
            &data[pos..pos + 8]
        );
        pos += 8;

        if path_length > 0 && path_length < 1000 {
            let path_bytes = &data[pos..pos + path_length as usize];
            let path = String::from_utf8_lossy(path_bytes);
            println!("  Pos {}: Path = '{}'", pos, path);
            pos += path_length as usize;
        } else if path_length > 0 {
            println!("  Skipping very long path of {} bytes", path_length);
            pos += path_length as usize;
        }
    } else {
        println!("  Path is null, skipping path data");
    }

    // [UInt64:offset]
    let offset = read_u64_at(data, pos)?;
    println!(
        "  Pos {}: Offset = {} (bytes: {:02X?})",
        pos,
        offset,
        &data[pos..pos + 8]
    );
    pos += 8;

    // [UInt64:length]
    let length = read_u64_at(data, pos)?;
    println!(
        "  Pos {}: Length = {} (bytes: {:02X?})",
        pos,
        length,
        &data[pos..pos + 8]
    );
    pos += 8;

    // [Bool:stretchEncryptionKey]
    let stretch_key = data[pos] != 0;
    println!(
        "  Pos {}: stretchEncryptionKey = {} (0x{:02X})",
        pos, stretch_key, data[pos]
    );
    pos += 1;

    // [UInt32:compressionType]
    let compression = read_u32_at(data, pos)?;
    println!(
        "  Pos {}: compressionType = {} (bytes: {:02X?})",
        pos,
        compression,
        &data[pos..pos + 4]
    );
    pos += 4;

    println!("  {} parsing complete, now at position {}", name, pos);

    Ok(pos)
}

fn read_u32_at(data: &[u8], pos: usize) -> Result<u32, Box<dyn std::error::Error>> {
    if pos + 4 > data.len() {
        return Err("Not enough data for u32".into());
    }
    Ok(u32::from_be_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
    ]))
}

fn read_u64_at(data: &[u8], pos: usize) -> Result<u64, Box<dyn std::error::Error>> {
    if pos + 8 > data.len() {
        return Err("Not enough data for u64".into());
    }
    Ok(u64::from_be_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ]))
}

fn print_hex_section(data: &[u8], start_offset: usize) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04X}: ", start_offset + i * 16);
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
}
