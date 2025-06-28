//! Debug Tree Format
//!
//! This tool focuses specifically on understanding the exact binary format
//! used in Arq 7 tree data by examining the decompressed data byte by byte.

use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Debug Tree Format Analysis");
    println!("{}", "=".repeat(50));

    let pack_file_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/89/88F120-159A-4AFF-A047-1C59ED169CE8.pack";
    let offset = 311;
    let length = 512;

    // Extract and decompress the data
    let data = extract_and_decompress(pack_file_path, offset, length)?;

    // Analyze byte by byte
    analyze_tree_format(&data)?;

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

fn analyze_tree_format(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n📊 Tree Format Analysis");
    println!("{}", "-".repeat(30));

    let mut cursor = std::io::Cursor::new(data);
    let mut pos = 0;

    // Read tree header
    println!("Tree Header:");
    let version = cursor.read_u32::<BigEndian>()?;
    pos += 4;
    println!("  Version: {} (bytes 0-3: {:02X?})", version, &data[0..4]);

    let child_count = cursor.read_u64::<BigEndian>()?;
    pos += 8;
    println!(
        "  Child Count: {} (bytes 4-11: {:02X?})",
        child_count,
        &data[4..12]
    );

    // Analyze each child
    for i in 0..std::cmp::min(child_count, 3) {
        println!("\nChild {}:", i);
        println!("  Starting at byte offset: {}", pos);

        // Read string format (should be: bool + length + data)
        let string_not_null = cursor.read_u8()?;
        println!("  String not null flag: {} (byte {})", string_not_null, pos);
        pos += 1;

        if string_not_null != 0 {
            let string_length = cursor.read_u64::<BigEndian>()?;
            println!(
                "  String length: {} (bytes {}-{})",
                string_length,
                pos,
                pos + 7
            );
            pos += 8;

            if string_length > 0 && string_length < 256 {
                let mut string_bytes = vec![0u8; string_length as usize];
                cursor.read_exact(&mut string_bytes)?;

                // Find null terminator if any
                let end = string_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(string_bytes.len());
                let name = String::from_utf8(string_bytes[..end].to_vec())?;

                println!(
                    "  Child name: '{}' (bytes {}-{})",
                    name,
                    pos,
                    pos + string_length as usize - 1
                );
                println!("  Name bytes: {:02X?}", &string_bytes);
                pos += string_length as usize;

                // Now analyze the node structure
                println!("  Node structure starting at byte {}:", pos);

                // Show the next 64 bytes to understand the node format
                let remaining = &data[pos..std::cmp::min(pos + 64, data.len())];
                println!("  Next 64 bytes: {:02X?}", remaining);

                // Try to parse node header manually
                if let Ok(node_info) = parse_node_manually(&data[pos..]) {
                    println!("  Node info: {:?}", node_info);
                    pos += node_info.bytes_consumed;
                } else {
                    println!("  Failed to parse node - analyzing structure:");

                    // Show interpretation of first bytes as different types
                    if remaining.len() >= 4 {
                        println!(
                            "    As u32 BE: {}",
                            u32::from_be_bytes([
                                remaining[0],
                                remaining[1],
                                remaining[2],
                                remaining[3]
                            ])
                        );
                        println!(
                            "    As bool + u24: {} + {}",
                            remaining[0],
                            u32::from_be_bytes([0, remaining[1], remaining[2], remaining[3]])
                        );
                    }
                    break;
                }
            }
        }
    }

    // Show hex dump of entire structure
    println!("\n📄 Complete Hex Dump:");
    for (i, chunk) in data.chunks(16).enumerate() {
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

    Ok(())
}

#[derive(Debug)]
struct NodeInfo {
    is_tree: bool,
    has_tree_blob_loc: bool,
    computer_os_type: u32,
    data_blob_count: u64,
    bytes_consumed: usize,
}

fn parse_node_manually(data: &[u8]) -> Result<NodeInfo, Box<dyn std::error::Error>> {
    let mut cursor = std::io::Cursor::new(data);
    let start_pos = cursor.position();

    // Parse according to Arq 7 Node format:
    // [Bool:isTree]
    let is_tree = cursor.read_u8()? != 0;

    let mut has_tree_blob_loc = false;
    // [BlobLoc:treeBlobLoc] /* present if isTree is true */
    if is_tree {
        has_tree_blob_loc = true;
        // Skip tree blob loc for now - it's complex
        skip_blob_loc(&mut cursor)?;
    }

    // [UInt32:computerOSType]
    let computer_os_type = cursor.read_u32::<BigEndian>()?;

    // [UInt64:dataBlobLocsCount]
    let data_blob_count = cursor.read_u64::<BigEndian>()?;

    let bytes_consumed = (cursor.position() - start_pos) as usize;

    Ok(NodeInfo {
        is_tree,
        has_tree_blob_loc,
        computer_os_type,
        data_blob_count,
        bytes_consumed,
    })
}

fn skip_blob_loc(cursor: &mut std::io::Cursor<&[u8]>) -> Result<(), Box<dyn std::error::Error>> {
    // [String:blobIdentifier] /* can't be null */
    let identifier_not_null = cursor.read_u8()?;
    if identifier_not_null != 0 {
        let identifier_length = cursor.read_u64::<BigEndian>()?;
        cursor.seek(SeekFrom::Current(identifier_length as i64))?;
    }

    // [Bool:isPacked]
    cursor.read_u8()?;

    // [String:relativePath]
    let path_not_null = cursor.read_u8()?;
    if path_not_null != 0 {
        let path_length = cursor.read_u64::<BigEndian>()?;
        cursor.seek(SeekFrom::Current(path_length as i64))?;
    }

    // [UInt64:offset]
    cursor.read_u64::<BigEndian>()?;

    // [UInt64:length]
    cursor.read_u64::<BigEndian>()?;

    // [Bool:stretchEncryptionKey]
    cursor.read_u8()?;

    // [UInt32:compressionType]
    cursor.read_u32::<BigEndian>()?;

    Ok(())
}
