use crate::arq7_types::{BlobLoc, Node, Tree};
use crate::error::ArqError;
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Cursor, Seek, SeekFrom}; // Removed 'self'
use std::path::Path;

// Helper function to read a specified length of data from a pack file, decompress if necessary.
// For Arq7, blobs inside pack files are individually compressed.
// The BlobLoc gives the offset and length of the *compressed* data.
fn read_compressed_blob_from_pack<P: AsRef<Path>>(
    pack_file_path: P,
    blob_loc: &BlobLoc,
) -> Result<Vec<u8>, ArqError> {
    if !blob_loc.is_packed {
        // This function is for packed blobs; standalone blobs would be handled differently.
        return Err(ArqError::Generic("BlobLoc indicates blob is not packed, but attempting to read from pack.".to_string()));
    }

    let mut file = File::open(pack_file_path.as_ref()).map_err(ArqError::Io)?; // Use .as_ref()
    file.seek(SeekFrom::Start(blob_loc.offset)).map_err(ArqError::Io)?;

    let mut compressed_data = vec![0u8; blob_loc.length as usize];
    file.read_exact(&mut compressed_data).map_err(ArqError::Io)?;

    // According to Arq7 dataFormat.html:
    // "Data described in this document as “LZ4-compressed” is stored as a
    // 4-byte big-endian length followed by the compressed data in LZ4 block format."
    // However, for blobs *within* pack files, the BlobLoc.length refers to the already compressed size.
    // The 4-byte length prefix is for standalone LZ4 files (e.g. backup records), AND
    // for blobs within pack files according to existing lz4.rs and arq7_format.rs logic.
    // The BlobLoc.length includes this prefix.

    match blob_loc.compression_type {
        2 => { // LZ4
            if compressed_data.len() < 4 {
                return Err(ArqError::Generic("LZ4 blob data too short for length prefix.".to_string()));
            }
            // let prefix_reader = Cursor::new(&compressed_data[0..4]); // Unused, as lz4::decompress handles prefix reading
            // Removed debug file logging
            // Let's use the crate's own lz4::decompress which handles the prefix and uses lz4_flex::decompress.
            // The `compressed_data` variable already holds the [prefix + actual_compressed_data].
            // crate::lz4::decompress returns Result<Vec<u8>, ArqError> directly.
            crate::lz4::decompress(&compressed_data)
        }
        0 => { // No compression (reused from Arq 5)
            // If no compression, there should be no 4-byte length prefix.
            // The blob_loc.length is the actual data length.
            Ok(compressed_data)
        }
        1 => { // Gzip (reused from Arq 5)
            // Gzip decompression would be needed here.
            // For now, let's focus on LZ4 as it's the primary for Arq7.
            Err(ArqError::NotImplemented("Gzip decompression for packed blobs not yet implemented".to_string()))
        }
        _ => Err(ArqError::Generic(format!("Unknown compression type: {}", blob_loc.compression_type))),
    }
}


// Placeholder for parsing a Tree object from its decompressed data
pub fn parse_tree_from_data(data: &[u8]) -> Result<Tree, ArqError> {
    let mut cursor = Cursor::new(data);

    let version = cursor.read_u32::<BigEndian>().map_err(ArqError::Io)?;
    let child_nodes_count = cursor.read_u64::<BigEndian>().map_err(ArqError::Io)?;

    let mut child_nodes_by_name = HashMap::new();

    for _ in 0..child_nodes_count {
        let child_name = read_arq_string(&mut cursor)?;
        let child_node = parse_node_from_data_stream(&mut cursor, version)?; // Pass tree version for conditional node fields
        child_nodes_by_name.insert(child_name, child_node);
    }

    Ok(Tree {
        version,
        child_nodes_by_name,
    })
}

// Placeholder for parsing a Node object from its decompressed data stream
// `tree_version` is needed because some Node fields depend on the parent Tree's version.
pub fn parse_node_from_data_stream<R: Read>(reader: &mut R, tree_version: u32) -> Result<Node, ArqError> {
    let is_tree = read_bool(reader)?;

    let tree_blob_loc = if is_tree {
        Some(read_blob_loc(reader)?)
    } else {
        None
    };

    let computer_os_type = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;

    let data_blob_locs_count = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let mut data_blob_locs = Vec::new();
    for _ in 0..data_blob_locs_count {
        data_blob_locs.push(read_blob_loc(reader)?);
    }

    let acl_blob_loc_is_not_nil = read_bool(reader)?;
    let acl_blob_loc = if acl_blob_loc_is_not_nil {
        Some(read_blob_loc(reader)?)
    } else {
        None
    };

    let xattrs_blob_loc_count = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let mut xattrs_blob_locs = Vec::new();
    for _ in 0..xattrs_blob_loc_count {
        xattrs_blob_locs.push(read_blob_loc(reader)?);
    }

    let item_size = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let contained_files_count = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let mtime_sec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;
    let mtime_nsec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;
    let ctime_sec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;
    let ctime_nsec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;
    let create_time_sec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;
    let create_time_nsec = reader.read_i64::<BigEndian>().map_err(ArqError::Io)?;

    let username = read_arq_string(reader)?;
    let group_name = read_arq_string(reader)?;
    let deleted = read_bool(reader)?;

    let mac_st_dev = reader.read_i32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_ino = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_mode = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_nlink = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_uid = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_gid = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_rdev = reader.read_i32::<BigEndian>().map_err(ArqError::Io)?;
    let mac_st_flags = reader.read_i32::<BigEndian>().map_err(ArqError::Io)?; // Signed as per docs, could be u32 too.

    let win_attrs = reader.read_u32::<BigEndian>().map_err(ArqError::Io)?;

    let mut win_reparse_tag = None;
    let mut win_reparse_point_is_directory = None;

    if tree_version >= 2 {
        win_reparse_tag = Some(reader.read_u32::<BigEndian>().map_err(ArqError::Io)?);
        win_reparse_point_is_directory = Some(read_bool(reader)?);
    }

    Ok(Node {
        is_tree,
        tree_blob_loc,
        computer_os_type,
        data_blob_locs,
        acl_blob_loc_is_not_nil,
        acl_blob_loc,
        xattrs_blob_locs,
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
        win_reparse_tag,
        win_reparse_point_is_directory,
    })
}

// Helper to read Arq's string format
fn read_arq_string<R: Read>(reader: &mut R) -> Result<String, ArqError> {
    let is_not_null_byte = reader.read_u8().map_err(ArqError::Io)?;
    if is_not_null_byte == 0 {
        return Ok(String::new()); // Or handle as Option<String>::None if appropriate
    }

    let len = reader.read_u64::<BigEndian>().map_err(ArqError::Io)?;
    let mut str_data = vec![0u8; len as usize];
    reader.read_exact(&mut str_data).map_err(ArqError::Io)?;
    String::from_utf8(str_data).map_err(|e| ArqError::Generic(format!("String UTF8 error: {}", e)))
}

// Helper to read Arq's bool format
fn read_bool<R: Read>(reader: &mut R) -> Result<bool, ArqError> {
    let val = reader.read_u8().map_err(ArqError::Io)?;
    Ok(val == 1)
}

// Helper to read a BlobLoc structure from a stream
fn read_blob_loc<R: Read>(reader: &mut R) -> Result<BlobLoc, ArqError> {
    Ok(BlobLoc {
        blob_identifier: read_arq_string(reader)?,
        is_packed: read_bool(reader)?,
        relative_path: read_arq_string(reader)?,
        offset: reader.read_u64::<BigEndian>().map_err(ArqError::Io)?,
        length: reader.read_u64::<BigEndian>().map_err(ArqError::Io)?,
        stretch_encryption_key: read_bool(reader)?,
        compression_type: reader.read_u32::<BigEndian>().map_err(ArqError::Io)?,
    })
}

// Main function to load a Tree object given its BlobLoc
pub fn load_tree<P: AsRef<Path>>(
    backup_set_root_path: P, // e.g., tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/
    tree_blob_loc: &BlobLoc,
) -> Result<Tree, ArqError> {
    let relative_path = tree_blob_loc.relative_path.trim_start_matches('/');
    // The relative_path in BlobLoc seems to be relative to the storage location root,
    // which is the parent of the specific backup_set_root_path (which includes the UUID).
    let storage_location_root = backup_set_root_path.as_ref().parent()
        .ok_or_else(|| ArqError::Generic(format!("Failed to get parent of backup set root: {:?}", backup_set_root_path.as_ref())))?;
    let pack_file_path = storage_location_root.join(relative_path);

    let decompressed_data = read_compressed_blob_from_pack(pack_file_path, tree_blob_loc)?;
    parse_tree_from_data(&decompressed_data)
}

// Main function to load a Node object referenced by a Tree.
// This is slightly different as Nodes are part of a Tree's binary data, not usually loaded standalone from a BlobLoc.
// However, the structure of parsing is similar if a Node *were* stored standalone.
// This function is more illustrative of how parse_node_from_data_stream would be used.
// In practice, Nodes are parsed as part of their parent Tree.
pub fn load_node_from_blob_loc<P: AsRef<Path>>(
    backup_set_root_path: P,
    node_blob_loc: &BlobLoc,
    tree_version: u32, // Needed for conditional fields in Node
) -> Result<Node, ArqError> {
    let relative_path = node_blob_loc.relative_path.trim_start_matches('/');
    let storage_location_root = backup_set_root_path.as_ref().parent()
        .ok_or_else(|| ArqError::Generic(format!("Failed to get parent of backup set root: {:?}", backup_set_root_path.as_ref())))?;
    let pack_file_path = storage_location_root.join(relative_path);
    let decompressed_data = read_compressed_blob_from_pack(pack_file_path, node_blob_loc)?;
    let mut cursor = Cursor::new(decompressed_data);
    parse_node_from_data_stream(&mut cursor, tree_version)
}

// Function to get the content of a file (concatenating its data blobs)
pub fn get_file_content<P: AsRef<Path>>(
    backup_set_root_path: P,
    node: &Node, // The file Node
) -> Result<Vec<u8>, ArqError> {
    if node.is_tree {
        return Err(ArqError::Generic("Cannot get file content from a tree node.".to_string()));
    }

    let mut file_content = Vec::new();
    let storage_location_root = backup_set_root_path.as_ref().parent()
        .ok_or_else(|| ArqError::Generic(format!("Failed to get parent of backup set root: {:?}", backup_set_root_path.as_ref())))?;
    for blob_loc in &node.data_blob_locs {
        let relative_path = blob_loc.relative_path.trim_start_matches('/');
        let pack_file_path = storage_location_root.join(relative_path);
        let mut decompressed_blob_data = read_compressed_blob_from_pack(pack_file_path, blob_loc)?;
        file_content.append(&mut decompressed_blob_data);
    }

    Ok(file_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // Helper to create a dummy LZ4 compressed blob with a size prefix
    fn create_dummy_lz4_blob(original_data: &[u8]) -> Vec<u8> {
        lz4_flex::compress_size_prepended(original_data)
    }

    #[test]
    fn test_read_arq_string_simple() {
        let data: &[u8] = &[
            1, // isNotNull
            0,0,0,0,0,0,0,5, // length = 5
            b'H', b'e', b'l', b'l', b'o' // Corrected: removed extra commas and ensured single bytes
        ];
        let mut cursor = Cursor::new(data);
        let result = read_arq_string(&mut cursor).unwrap();
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_read_arq_string_empty() {
        let data: &[u8] = &[
            0 // isNull
        ];
        let mut cursor = Cursor::new(data);
        let result = read_arq_string(&mut cursor).unwrap();
        assert_eq!(result, "");
    }

     #[test]
    fn test_read_bool_true() {
        let data: &[u8] = &[1];
        let mut cursor = Cursor::new(data);
        assert_eq!(read_bool(&mut cursor).unwrap(), true);
    }

    #[test]
    fn test_read_bool_false() {
        let data: &[u8] = &[0];
        let mut cursor = Cursor::new(data);
        assert_eq!(read_bool(&mut cursor).unwrap(), false);
    }

    #[test]
    fn test_read_blob_loc_example() {
        // Construct byte stream for a BlobLoc
        // blobIdentifier: "testblobid" (10 chars)
        // isPacked: true
        // relativePath: "test/path" (9 chars)
        // offset: 12345
        // length: 67890
        // stretchEncryptionKey: true
        // compressionType: 2 (LZ4)
        let mut data = Vec::new();
        data.write_all(&[1]).unwrap(); // blobIdentifier isNotNull
        data.write_u64::<BigEndian>(10).unwrap(); // blobIdentifier length
        data.write_all(b"testblobid").unwrap(); // blobIdentifier value
        data.write_all(&[1]).unwrap(); // isPacked = true
        data.write_all(&[1]).unwrap(); // relativePath isNotNull
        data.write_u64::<BigEndian>(9).unwrap(); // relativePath length
        data.write_all(b"test/path").unwrap(); // relativePath value
        data.write_u64::<BigEndian>(12345).unwrap(); // offset
        data.write_u64::<BigEndian>(67890).unwrap(); // length
        data.write_all(&[1]).unwrap(); // stretchEncryptionKey = true
        data.write_u32::<BigEndian>(2).unwrap(); // compressionType = 2

        let mut cursor = Cursor::new(data);
        let blob_loc = read_blob_loc(&mut cursor).unwrap();

        assert_eq!(blob_loc.blob_identifier, "testblobid");
        assert_eq!(blob_loc.is_packed, true);
        assert_eq!(blob_loc.relative_path, "test/path");
        assert_eq!(blob_loc.offset, 12345);
        assert_eq!(blob_loc.length, 67890);
        assert_eq!(blob_loc.stretch_encryption_key, true);
        assert_eq!(blob_loc.compression_type, 2);
    }

    // More tests will be needed for parse_tree_from_data and parse_node_from_data_stream
    // once we have actual pack file data to test against or more complex mock data.
    // Test for read_compressed_blob_from_pack requires a dummy pack file.
}
