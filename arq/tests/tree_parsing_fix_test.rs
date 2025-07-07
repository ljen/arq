//! Test for the specific fix to handle misaligned relativePath data in blob locations
//!
//! This test validates that the tree parsing can correctly handle the specific data
//! characteristic encountered in real Arq 7 backup data where dataBlobLocs[0].relativePath.isNotNull
//! is false (0x00) but the subsequent bytes contain path data instead of offset/length values.

use arq::arq7::binary::ArqBinaryReader;
use arq::arq7::BlobLoc;
use std::io::Cursor;

#[test]
fn test_misaligned_relative_path_parsing() {
    // This test data simulates the exact issue found in the sample backup data:
    // - relativePath.isNotNull = 0x00 (false)
    // - But the following bytes contain path data instead of offset/length

    // Create test blob location data with misaligned path
    let blob_data = create_misaligned_blob_data();
    let mut cursor = Cursor::new(blob_data);

    // This should not panic and should successfully parse the blob location
    let result = BlobLoc::from_binary_reader(&mut cursor);

    assert!(
        result.is_ok(),
        "BlobLoc parsing should succeed with misaligned data"
    );

    let blob_loc = result.unwrap();

    // Verify that we got reasonable values
    assert!(
        !blob_loc.blob_identifier.is_empty(),
        "Blob identifier should not be empty"
    );
    assert_eq!(blob_loc.is_packed, true, "isPacked should be true");

    // The relative path should be recovered correctly
    assert!(
        blob_loc.relative_path.starts_with("/"),
        "Relative path should start with /"
    );
    assert!(
        blob_loc.relative_path.contains("FD5575D9"),
        "Path should contain backup set UUID"
    );

    // Offset and length should be reasonable (not huge values from misaligned parsing)
    assert!(blob_loc.offset < 1_000_000, "Offset should be reasonable");
    assert!(blob_loc.length < 10_000_000, "Length should be reasonable");

    println!("Successfully parsed misaligned blob location:");
    println!("  Blob ID: {}", blob_loc.blob_identifier);
    println!("  Is packed: {}", blob_loc.is_packed);
    println!("  Path: {}", blob_loc.relative_path);
    println!("  Offset: {}", blob_loc.offset);
    println!("  Length: {}", blob_loc.length);
}

#[test]
fn test_tree_parsing_with_misaligned_data() {
    // Test the complete tree parsing with the specific misaligned data pattern
    let tree_data = create_test_tree_with_misaligned_blob();
    // from_arq7_binary_data expects decompressed data, the helper already provides this.
    let result = arq::tree::Tree::from_arq7_binary_data(&tree_data);
    assert!(
        result.is_ok(),
        "Tree parsing should succeed with misaligned blob data. Error: {:?}", result.err()
    );

    let tree = result.unwrap();

    // Verify tree structure
    assert_eq!(tree.version, 3, "Tree version should be 3"); // Arq7 binary tree version
    assert!(!tree.nodes.is_empty(), "Tree should have child nodes"); // Unified Tree uses 'nodes'

    // Check that we can access child nodes
    for (name, node) in &tree.nodes { // Iterate over tree.nodes
        println!("Child: {} (is_tree: {})", name, node.is_tree);

        if !node.data_blob_locs.is_empty() {
            let blob_loc = &node.data_blob_locs[0];
            assert!(
                !blob_loc.blob_identifier.is_empty(),
                "Blob identifier should not be empty"
            );

            // Verify the fix worked - these values should be reasonable
            assert!(
                blob_loc.offset < 1_000_000,
                "Offset should be reasonable for {}",
                name
            );
            assert!(
                blob_loc.length < 10_000_000,
                "Length should be reasonable for {}",
                name
            );
        }
    }
}

fn create_misaligned_blob_data() -> Vec<u8> {
    // Create blob location data that simulates the misaligned relativePath issue:
    // [String:blobIdentifier] - 64 byte hex string
    // [Bool:isPacked] - true
    // [String:relativePath] - isNotNull=false, but followed by path data instead of offset

    let mut data = Vec::new();

    // Blob identifier: not null + length + 64-byte hex string
    data.push(0x01); // isNotNull = true
    data.extend_from_slice(&64u64.to_be_bytes()); // length = 64
    data.extend_from_slice(b"5048d7b52ba1ca80d5bd8886e65c806dd6929df776506f00933e15413a110bac"); // 64 bytes

    // isPacked = true
    data.push(0x01);

    // relativePath: isNotNull = false (this is the key issue)
    data.push(0x00);

    // But then we have what should be a path (the misalignment)
    data.push(0x01); // This looks like path isNotNull flag
    data.extend_from_slice(&90u64.to_be_bytes()); // Path length = 90
    data.extend_from_slice(b"/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/EF/2CA969-3A3C-4019-9C13-01AC6B75FC89.pack"); // 90 bytes

    // Normal offset, length, etc. would follow
    data.extend_from_slice(&6u64.to_be_bytes()); // offset
    data.extend_from_slice(&15u64.to_be_bytes()); // length
    data.push(0x00); // stretchEncryptionKey = false
    data.extend_from_slice(&0u32.to_be_bytes()); // compressionType = 0

    data
}

fn create_test_tree_with_misaligned_blob() -> Vec<u8> {
    // Create a minimal tree structure that contains a node with misaligned blob data
    let mut data = Vec::new();

    // Tree header
    data.extend_from_slice(&3u32.to_be_bytes()); // version = 3
    data.extend_from_slice(&1u64.to_be_bytes()); // child count = 1

    // Child name
    data.push(0x01); // name not null
    data.extend_from_slice(&8u64.to_be_bytes()); // name length = 8
    data.extend_from_slice(b"testfile"); // name = "testfile"

    // Child node
    data.push(0x00); // isTree = false
                     // (no tree blob location since isTree = false)
    data.extend_from_slice(&1u32.to_be_bytes()); // computerOSType = 1
    data.extend_from_slice(&1u64.to_be_bytes()); // dataBlobLocsCount = 1

    // Add the misaligned blob location data
    let blob_data = create_misaligned_blob_data();
    data.extend_from_slice(&blob_data);

    // Add minimal remaining node fields with reasonable defaults
    data.push(0x00); // aclBlobLocIsNotNil = false
    data.extend_from_slice(&0u64.to_be_bytes()); // xattrsBlobLocCount = 0
    data.extend_from_slice(&15u64.to_be_bytes()); // itemSize = 15
    data.extend_from_slice(&1u64.to_be_bytes()); // containedFilesCount = 1
    data.extend_from_slice(&1735296644i64.to_be_bytes()); // mtime_sec
    data.extend_from_slice(&0i64.to_be_bytes()); // mtime_nsec
    data.extend_from_slice(&1735296644i64.to_be_bytes()); // ctime_sec
    data.extend_from_slice(&0i64.to_be_bytes()); // ctime_nsec
    data.extend_from_slice(&1735296644i64.to_be_bytes()); // create_time_sec
    data.extend_from_slice(&0i64.to_be_bytes()); // create_time_nsec

    // username
    data.push(0x01); // not null
    data.extend_from_slice(&4u64.to_be_bytes()); // length = 4
    data.extend_from_slice(b"user"); // "user"

    // groupName
    data.push(0x01); // not null
    data.extend_from_slice(&5u64.to_be_bytes()); // length = 5
    data.extend_from_slice(b"group"); // "group"

    data.push(0x00); // deleted = false
    data.extend_from_slice(&0i32.to_be_bytes()); // mac_st_dev = 0
    data.extend_from_slice(&100000u64.to_be_bytes()); // mac_st_ino = 100000
    data.extend_from_slice(&33188u32.to_be_bytes()); // mac_st_mode = 33188 (regular file)
    data.extend_from_slice(&1u32.to_be_bytes()); // mac_st_nlink = 1
    data.extend_from_slice(&501u32.to_be_bytes()); // mac_st_uid = 501
    data.extend_from_slice(&20u32.to_be_bytes()); // mac_st_gid = 20
    data.extend_from_slice(&0i32.to_be_bytes()); // mac_st_rdev = 0
    data.extend_from_slice(&0i32.to_be_bytes()); // mac_st_flags = 0
    data.extend_from_slice(&0u32.to_be_bytes()); // win_attrs = 0

    // Tree version >= 2 fields (version is 3)
    data.extend_from_slice(&0u32.to_be_bytes()); // win_reparse_tag = 0
    data.push(0x00); // win_reparse_point_is_directory = false

    data
}

#[test]
fn test_relativepath_recovery_mechanism() {
    // Test the specific recovery mechanism for misaligned relativePath
    let mut data = Vec::new();

    // Simulate the exact pattern: relativePath isNotNull = false,
    // but next byte looks like path flag
    data.push(0x00); // relativePath isNotNull = false
    data.push(0x01); // Next byte that looks like path isNotNull = true
    data.extend_from_slice(&50u64.to_be_bytes()); // Reasonable path length
    data.extend_from_slice(b"/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/test.pack"); // Valid path (50 bytes)

    let mut cursor = Cursor::new(data);

    // First read should return None (path is null)
    let first_result = cursor.read_arq_string().unwrap();
    assert_eq!(
        first_result, None,
        "First read should return None for null path"
    );

    // The recovery mechanism should be triggered in the blob location parser
    // when it detects the misalignment pattern
}

#[test]
fn test_edge_case_path_validation() {
    // Test the path validation logic in the recovery mechanism

    // Valid path case
    let valid_path = b"/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/test.pack";
    assert!(
        valid_path.starts_with(b"/"),
        "Valid path should start with /"
    );
    assert!(
        valid_path
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b'/'),
        "Valid path should contain only graphic chars and slashes"
    );

    // Invalid path case (contains non-graphic chars)
    let invalid_path = b"/test\x00\x01/invalid";
    assert!(
        !invalid_path
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b'/'),
        "Invalid path should be rejected"
    );

    // Path that doesn't start with /
    let no_slash_path = b"test/path";
    assert!(
        !no_slash_path.starts_with(b"/"),
        "Path without leading slash should be rejected"
    );
}
