//! Complete Node Structure Parser
//!
//! This tool implements a complete parser for Arq 7 binary node structures,
//! handling all fields according to the documentation to correctly parse
//! the entire tree structure.

use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Complete Node Structure Parser");
    println!("{}", "=".repeat(50));

    let pack_file_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/89/88F120-159A-4AFF-A047-1C59ED169CE8.pack";
    let offset = 311;
    let length = 512;

    // Extract and decompress the data
    let data = extract_and_decompress(pack_file_path, offset, length)?;

    // Parse the complete tree structure
    parse_complete_tree(&data)?;

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

fn parse_complete_tree(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🌳 Complete Tree Parsing");
    println!("{}", "-".repeat(30));

    let mut cursor = std::io::Cursor::new(data);

    // Parse tree header
    let version = cursor.read_u32::<BigEndian>()?;
    let child_count = cursor.read_u64::<BigEndian>()?;

    println!("Tree version: {}", version);
    println!("Child count: {}", child_count);

    // Parse each child
    for i in 0..child_count {
        println!("\n--- Child {} ---", i);
        let start_pos = cursor.position();

        match parse_tree_child(&mut cursor) {
            Ok(child) => {
                let end_pos = cursor.position();
                println!("✅ Child '{}' parsed successfully", child.name);
                println!(
                    "   Type: {}",
                    if child.is_tree { "directory" } else { "file" }
                );
                println!("   Size: {} bytes", child.item_size);
                println!("   Data blobs: {}", child.data_blob_count);
                println!("   Bytes consumed: {}", end_pos - start_pos);

                if let Some(username) = &child.username {
                    println!("   Owner: {}", username);
                }
                if let Some(group) = &child.group_name {
                    println!("   Group: {}", group);
                }
            }
            Err(e) => {
                println!("❌ Failed to parse child {}: {}", i, e);
                println!("   Position: {}", cursor.position());
                println!("   Started at: {}", start_pos);

                // Show hex dump around current position
                let current_pos = cursor.position() as usize;
                if current_pos < data.len() {
                    let end = std::cmp::min(current_pos + 32, data.len());
                    println!("   Next 32 bytes: {:02X?}", &data[current_pos..end]);
                }
                break;
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct TreeChild {
    name: String,
    is_tree: bool,
    item_size: u64,
    data_blob_count: u64,
    username: Option<String>,
    group_name: Option<String>,
    mtime_sec: i64,
    mtime_nsec: i64,
}

fn parse_tree_child(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<TreeChild, Box<dyn std::error::Error>> {
    // Parse child name (Arq string format)
    let name = read_arq_string(cursor)?;

    // Parse the node structure according to Arq 7 documentation
    let node = parse_complete_node(cursor)?;

    Ok(TreeChild {
        name,
        is_tree: node.is_tree,
        item_size: node.item_size,
        data_blob_count: node.data_blob_count,
        username: node.username,
        group_name: node.group_name,
        mtime_sec: node.mtime_sec,
        mtime_nsec: node.mtime_nsec,
    })
}

#[derive(Debug)]
struct CompleteNode {
    is_tree: bool,
    computer_os_type: u32,
    data_blob_count: u64,
    item_size: u64,
    contained_files_count: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    create_time_sec: i64,
    create_time_nsec: i64,
    username: Option<String>,
    group_name: Option<String>,
    deleted: bool,
    mac_st_dev: i32,
    mac_st_ino: u64,
    mac_st_mode: u32,
    mac_st_nlink: u32,
    mac_st_uid: u32,
    mac_st_gid: u32,
    mac_st_rdev: i32,
    mac_st_flags: i32,
    win_attrs: u32,
}

fn parse_complete_node(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<CompleteNode, Box<dyn std::error::Error>> {
    // Node binary format according to Arq 7 docs:
    // [Bool:isTree]
    // [BlobLoc:treeBlobLoc] /* present if isTree is true */
    // [UInt32:computerOSType]
    // [UInt64:dataBlobLocsCount]
    // ... (many more fields)

    let is_tree = cursor.read_u8()? != 0;

    // If it's a tree, parse the tree blob location
    if is_tree {
        parse_blob_loc(cursor)?;
    }

    let computer_os_type = cursor.read_u32::<BigEndian>()?;

    // Parse data blob locations
    let data_blob_count = cursor.read_u64::<BigEndian>()?;
    for _ in 0..data_blob_count {
        parse_blob_loc(cursor)?;
    }

    // Parse ACL blob location
    let acl_blob_loc_is_not_nil = cursor.read_u8()? != 0;
    if acl_blob_loc_is_not_nil {
        parse_blob_loc(cursor)?;
    }

    // Parse xattrs blob locations
    let xattrs_blob_loc_count = cursor.read_u64::<BigEndian>()?;
    for _ in 0..xattrs_blob_loc_count {
        parse_blob_loc(cursor)?;
    }

    // Parse remaining node fields
    let item_size = cursor.read_u64::<BigEndian>()?;
    let contained_files_count = cursor.read_u64::<BigEndian>()?;
    let mtime_sec = cursor.read_i64::<BigEndian>()?;
    let mtime_nsec = cursor.read_i64::<BigEndian>()?;
    let ctime_sec = cursor.read_i64::<BigEndian>()?;
    let ctime_nsec = cursor.read_i64::<BigEndian>()?;
    let create_time_sec = cursor.read_i64::<BigEndian>()?;
    let create_time_nsec = cursor.read_i64::<BigEndian>()?;

    let username = read_arq_string_optional(cursor)?;
    let group_name = read_arq_string_optional(cursor)?;

    let deleted = cursor.read_u8()? != 0;
    let mac_st_dev = cursor.read_i32::<BigEndian>()?;
    let mac_st_ino = cursor.read_u64::<BigEndian>()?;
    let mac_st_mode = cursor.read_u32::<BigEndian>()?;
    let mac_st_nlink = cursor.read_u32::<BigEndian>()?;
    let mac_st_uid = cursor.read_u32::<BigEndian>()?;
    let mac_st_gid = cursor.read_u32::<BigEndian>()?;
    let mac_st_rdev = cursor.read_i32::<BigEndian>()?;
    let mac_st_flags = cursor.read_i32::<BigEndian>()?;
    let win_attrs = cursor.read_u32::<BigEndian>()?;

    // Note: Windows reparse fields (win_reparse_tag, win_reparse_point_is_directory)
    // are only present if tree version >= 2, but we'll skip them for now

    Ok(CompleteNode {
        is_tree,
        computer_os_type,
        data_blob_count,
        item_size,
        contained_files_count,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        create_time_sec,
        create_time_nsec,
        username,
        group_name,
        deleted,
        mac_st_dev,
        mac_st_ino,
        mac_st_mode,
        mac_st_nlink,
        mac_st_uid,
        mac_st_gid,
        mac_st_rdev,
        mac_st_flags,
        win_attrs,
    })
}

fn parse_blob_loc(cursor: &mut std::io::Cursor<&[u8]>) -> Result<(), Box<dyn std::error::Error>> {
    // BlobLoc format:
    // [String:blobIdentifier] /* can't be null */
    // [Bool:isPacked]
    // [String:relativePath]
    // [UInt64:offset]
    // [UInt64:length]
    // [Bool:stretchEncryptionKey]
    // [UInt32:compressionType]

    let _blob_identifier = read_arq_string_optional(cursor)?;
    let _is_packed = cursor.read_u8()? != 0;
    let _relative_path = read_arq_string_optional(cursor)?;
    let _offset = cursor.read_u64::<BigEndian>()?;
    let _length = cursor.read_u64::<BigEndian>()?;
    let _stretch_encryption_key = cursor.read_u8()? != 0;
    let _compression_type = cursor.read_u32::<BigEndian>()?;

    Ok(())
}

fn read_arq_string(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<String, Box<dyn std::error::Error>> {
    let is_not_null = cursor.read_u8()? != 0;
    if !is_not_null {
        return Err("String is null".into());
    }

    let length = cursor.read_u64::<BigEndian>()?;
    if length == 0 {
        return Ok(String::new());
    }

    let mut buffer = vec![0u8; length as usize];
    cursor.read_exact(&mut buffer)?;

    // Handle null termination
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    let string = String::from_utf8(buffer[..end].to_vec())?;

    Ok(string)
}

fn read_arq_string_optional(
    cursor: &mut std::io::Cursor<&[u8]>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let is_not_null = cursor.read_u8()? != 0;
    if !is_not_null {
        return Ok(None);
    }

    let length = cursor.read_u64::<BigEndian>()?;
    if length == 0 {
        return Ok(Some(String::new()));
    }

    let mut buffer = vec![0u8; length as usize];
    cursor.read_exact(&mut buffer)?;

    // Handle null termination
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    let string = String::from_utf8(buffer[..end].to_vec())?;

    Ok(Some(string))
}
