//! Diagnostic test to analyze BlobLoc parsing issues and format variations
//!
//! This test helps identify and fix the remaining BlobLoc ParseError issues
//! by examining different binary formats and implementing robust recovery mechanisms.

use arq::arq7::binary::ArqBinaryReader;
use arq::arq7::BlobLoc as Arq7BlobLoc;
use arq::blob_location::BlobLoc;
use arq::error::{Error, Result};
use std::io::Cursor;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test data representing different BlobLoc format variations
    fn create_test_blob_loc_data() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            // Format 1: Standard Arq7 format
            ("standard_format", create_standard_blob_loc_data()),
            // Format 2: Misaligned relativePath (common issue)
            ("misaligned_path", create_misaligned_path_data()),
            // Format 3: Pack file format variation
            ("pack_format", create_pack_format_data()),
            // Format 4: Legacy format with different field order
            ("legacy_format", create_legacy_format_data()),
        ]
    }

    fn create_standard_blob_loc_data() -> Vec<u8> {
        let mut data = Vec::new();

        // blobIdentifier: required string
        data.push(0x01); // isNotNull = true
        let identifier = b"abc123def456";
        data.extend_from_slice(&(identifier.len() as u64).to_be_bytes());
        data.extend_from_slice(identifier);

        // isPacked: bool
        data.push(0x01); // true

        // isLargePack: bool (Arq7 specific)
        data.push(0x00); // false

        // relativePath: optional string
        data.push(0x01); // isNotNull = true
        let path = b"/test/path/to/pack.pack";
        data.extend_from_slice(&(path.len() as u64).to_be_bytes());
        data.extend_from_slice(path);

        // offset: u64
        data.extend_from_slice(&1024u64.to_be_bytes());

        // length: u64
        data.extend_from_slice(&2048u64.to_be_bytes());

        // stretchEncryptionKey: bool
        data.push(0x01); // true

        // compressionType: u32
        data.extend_from_slice(&2u32.to_be_bytes()); // LZ4

        data
    }

    fn create_misaligned_path_data() -> Vec<u8> {
        let mut data = Vec::new();

        // blobIdentifier: required string
        data.push(0x01); // isNotNull = true
        let identifier = b"misaligned123";
        data.extend_from_slice(&(identifier.len() as u64).to_be_bytes());
        data.extend_from_slice(identifier);

        // isPacked: bool
        data.push(0x01); // true

        // isLargePack: bool
        data.push(0x00); // false

        // relativePath: This is where misalignment occurs
        data.push(0x00); // isNotNull = false (but path data follows!)

        // Hidden path data that should have been detected
        let hidden_path = b"/hidden/path/data.pack";
        data.extend_from_slice(hidden_path);
        data.push(0x00); // null terminator

        // This causes offset/length to be misread
        data.extend_from_slice(&512u64.to_be_bytes());
        data.extend_from_slice(&1024u64.to_be_bytes());
        data.push(0x01); // stretchEncryptionKey
        data.extend_from_slice(&2u32.to_be_bytes()); // compressionType

        data
    }

    fn create_pack_format_data() -> Vec<u8> {
        let mut data = Vec::new();

        // Pack format might have different field ordering or additional fields
        data.push(0x01); // isNotNull for identifier
        let identifier = b"pack_format_blob";
        data.extend_from_slice(&(identifier.len() as u64).to_be_bytes());
        data.extend_from_slice(identifier);

        data.push(0x01); // isPacked = true
        data.push(0x01); // isLargePack = true (different from standard)

        // Pack format might have additional metadata here
        data.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // Mystery field

        data.push(0x01); // relativePath isNotNull
        let path = b"/large/pack/file.largepack";
        data.extend_from_slice(&(path.len() as u64).to_be_bytes());
        data.extend_from_slice(path);

        data.extend_from_slice(&8192u64.to_be_bytes()); // offset
        data.extend_from_slice(&16384u64.to_be_bytes()); // length
        data.push(0x01); // stretchEncryptionKey
        data.extend_from_slice(&2u32.to_be_bytes()); // compressionType

        data
    }

    fn create_legacy_format_data() -> Vec<u8> {
        let mut data = Vec::new();

        // Legacy format might have different field order
        data.push(0x01); // identifier isNotNull
        let identifier = b"legacy_blob_id";
        data.extend_from_slice(&(identifier.len() as u64).to_be_bytes());
        data.extend_from_slice(identifier);

        // Legacy might not have isLargePack field
        data.push(0x01); // isPacked

        // relativePath comes before other fields in legacy
        data.push(0x01); // relativePath isNotNull
        let path = b"/legacy/path/format.blob";
        data.extend_from_slice(&(path.len() as u64).to_be_bytes());
        data.extend_from_slice(path);

        data.extend_from_slice(&256u64.to_be_bytes()); // offset
        data.extend_from_slice(&512u64.to_be_bytes()); // length
        data.push(0x00); // stretchEncryptionKey = false
        data.extend_from_slice(&1u32.to_be_bytes()); // compressionType = Gzip

        data
    }

    #[test]
    fn test_blob_loc_format_variations() {
        let test_data = create_test_blob_loc_data();

        for (format_name, data) in test_data {
            println!("\n=== Testing {} format ===", format_name);

            // Test with arq7::BlobLoc
            let mut cursor = Cursor::new(&data);
            match Arq7BlobLoc::from_binary_reader(&mut cursor) {
                Ok(blob_loc) => {
                    println!("✓ arq7::BlobLoc parsed successfully:");
                    println!("  identifier: {}", blob_loc.blob_identifier);
                    println!("  path: {}", blob_loc.relative_path);
                    println!("  offset: {}, length: {}", blob_loc.offset, blob_loc.length);
                    println!(
                        "  isPacked: {}, isLargePack: {:?}",
                        blob_loc.is_packed, blob_loc.is_large_pack
                    );
                }
                Err(e) => {
                    println!("✗ arq7::BlobLoc failed: {:?}", e);

                    // Try with recovery mechanisms
                    test_recovery_mechanisms(format_name, &data);
                }
            }

            // Test with blob_location::BlobLoc
            let mut cursor = Cursor::new(&data);
            match BlobLoc::from_binary_reader(&mut cursor) {
                Ok(blob_loc) => {
                    println!("✓ blob_location::BlobLoc parsed successfully:");
                    println!("  identifier: {}", blob_loc.blob_identifier);
                    println!("  path: {}", blob_loc.relative_path);
                    println!("  offset: {}, length: {}", blob_loc.offset, blob_loc.length);
                }
                Err(e) => {
                    println!("✗ blob_location::BlobLoc failed: {:?}", e);
                }
            }
        }
    }

    fn test_recovery_mechanisms(format_name: &str, data: &[u8]) {
        println!("  Attempting recovery for {} format...", format_name);

        // Try reading with different starting positions
        for skip_bytes in 1..=8 {
            if skip_bytes >= data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[skip_bytes..]);
            match Arq7BlobLoc::from_binary_reader(&mut cursor) {
                Ok(blob_loc) => {
                    println!("  ✓ Recovery successful by skipping {} bytes:", skip_bytes);
                    println!("    identifier: {}", blob_loc.blob_identifier);
                    println!("    path: {}", blob_loc.relative_path);
                    return;
                }
                Err(_) => continue,
            }
        }

        println!("  ✗ All recovery attempts failed");
    }

    #[test]
    fn test_pack_file_abnormal_counts() {
        // Test the abnormal data_blob_locs_count issue mentioned in context
        println!("\n=== Testing abnormal blob counts ===");

        let abnormal_counts = vec![
            7885894706840955694u64, // From context
            0xFFFFFFFFFFFFFFFFu64,  // Max u64
            0x0123456789ABCDEFu64,  // Random large number
        ];

        for count in abnormal_counts {
            println!("Testing count: {}", count);

            let mut data = Vec::new();
            data.push(0x00); // isTree = false
            data.extend_from_slice(&0u32.to_be_bytes()); // computerOSType
            data.extend_from_slice(&count.to_be_bytes()); // data_blob_locs_count

            let mut cursor = Cursor::new(&data);

            // Simulate the node parsing that encounters this
            match cursor.read_arq_bool() {
                Ok(is_tree) => {
                    println!("  isTree: {}", is_tree);
                    match cursor.read_arq_u32() {
                        Ok(os_type) => {
                            println!("  computerOSType: {}", os_type);
                            match cursor.read_arq_u64() {
                                Ok(blob_count) => {
                                    println!("  data_blob_locs_count: {}", blob_count);

                                    if blob_count > 1000000 {
                                        println!("  ⚠️  Abnormally large blob count detected!");
                                        println!("  This would cause excessive memory allocation");
                                    }
                                }
                                Err(e) => println!("  ✗ Failed to read count: {:?}", e),
                            }
                        }
                        Err(e) => println!("  ✗ Failed to read OS type: {:?}", e),
                    }
                }
                Err(e) => println!("  ✗ Failed to read isTree: {:?}", e),
            }
        }
    }

    #[test]
    fn test_enhanced_blob_loc_validation() {
        println!("\n=== Testing enhanced BlobLoc validation ===");

        let test_paths = vec![
            ("/valid/path/to/pack.pack", true),
            ("invalid_path_no_slash", false),
            ("/path/with\x00null", false),
            ("/extremely/long/path/that/exceeds/reasonable/limits/and/should/be/rejected/because/it/is/way/too/long/for/any/reasonable/filesystem/path/and/probably/indicates/corrupted/data/or/a/parsing/error/in/the/binary/format/which/needs/to/be/handled/gracefully", false),
            ("", false),
            ("/treepacks/valid.pack", true),
            ("/blobpacks/valid.pack", true),
            ("random_non_path_data_12345", false),
        ];

        for (path, should_be_valid) in test_paths {
            let is_valid = validate_blob_path(path);
            println!(
                "Path: '{}' -> Valid: {} (expected: {})",
                path, is_valid, should_be_valid
            );

            if is_valid != should_be_valid {
                println!("  ⚠️  Validation mismatch!");
            }
        }
    }

    fn validate_blob_path(path: &str) -> bool {
        // Enhanced validation combining both implementations
        if path.is_empty() || path.len() > 4096 {
            return false;
        }

        // Check for backup-specific patterns
        let has_backup_patterns = path.contains("treepacks")
            || path.contains("blobpacks")
            || path.contains("largeblobpacks")
            || path.contains(".pack")
            || path.contains("standardobjects");

        // Must start with / or contain backup patterns
        let has_valid_start = path.starts_with('/') || has_backup_patterns;

        // Check for valid characters
        let has_valid_chars = path.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '/'
                || c == '-'
                || c == '_'
                || c == '.'
                || c == ' '
                || c == '('
                || c == ')'
                || c == ':'
        });

        // No null bytes or other control characters
        let no_control_chars = !path.chars().any(|c| c.is_control());

        has_valid_start && has_valid_chars && no_control_chars
    }

    #[test]
    fn test_blob_loc_memory_safety() {
        println!("\n=== Testing BlobLoc memory safety ===");

        // Test with various malformed data that could cause issues
        let malformed_data_sets = vec![
            // Extremely large string length
            create_malformed_large_string(),
            // Truncated data
            vec![0x01, 0x00, 0x00], // Incomplete
            // All zeros
            vec![0x00; 100],
            // Random data
            (0..50).map(|i| (i * 7) as u8).collect::<Vec<u8>>(),
        ];

        for (i, data) in malformed_data_sets.iter().enumerate() {
            println!("Testing malformed data set {}", i + 1);

            let mut cursor = Cursor::new(data);

            // This should not panic or cause memory issues
            match Arq7BlobLoc::from_binary_reader(&mut cursor) {
                Ok(_) => println!("  Unexpectedly parsed successfully"),
                Err(e) => println!("  Correctly rejected: {:?}", e),
            }

            let mut cursor = Cursor::new(data);
            match BlobLoc::from_binary_reader(&mut cursor) {
                Ok(_) => println!("  blob_location::BlobLoc unexpectedly parsed successfully"),
                Err(e) => println!("  blob_location::BlobLoc correctly rejected: {:?}", e),
            }
        }
    }

    fn create_malformed_large_string() -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x01); // isNotNull = true
                         // Claim the string is 1GB long (should be rejected)
        data.extend_from_slice(&(1024u64 * 1024 * 1024).to_be_bytes());
        data.extend_from_slice(b"actual_short_string");
        data
    }

    #[test]
    fn test_unified_blob_loc_parsing() {
        println!("\n=== Testing unified BlobLoc parsing approach ===");

        // Test a complete, real-world-like BlobLoc
        let complete_data = create_complete_blob_loc_data();

        println!(
            "Testing complete BlobLoc data ({} bytes)",
            complete_data.len()
        );

        // Try both implementations
        let mut cursor1 = Cursor::new(&complete_data);
        let arq7_result = Arq7BlobLoc::from_binary_reader(&mut cursor1);

        let mut cursor2 = Cursor::new(&complete_data);
        let blob_location_result = BlobLoc::from_binary_reader(&mut cursor2);

        match (arq7_result, blob_location_result) {
            (Ok(arq7_blob), Ok(blob_location_blob)) => {
                println!("✓ Both implementations parsed successfully");

                // Compare results
                if arq7_blob.blob_identifier == blob_location_blob.blob_identifier
                    && arq7_blob.relative_path == blob_location_blob.relative_path
                    && arq7_blob.offset == blob_location_blob.offset
                    && arq7_blob.length == blob_location_blob.length
                {
                    println!("✓ Results are identical");
                } else {
                    println!("⚠️  Results differ:");
                    println!(
                        "  arq7: id={}, path={}, offset={}, length={}",
                        arq7_blob.blob_identifier,
                        arq7_blob.relative_path,
                        arq7_blob.offset,
                        arq7_blob.length
                    );
                    println!(
                        "  blob_location: id={}, path={}, offset={}, length={}",
                        blob_location_blob.blob_identifier,
                        blob_location_blob.relative_path,
                        blob_location_blob.offset,
                        blob_location_blob.length
                    );
                }
            }
            (Ok(_), Err(e)) => {
                println!(
                    "✓ arq7::BlobLoc parsed, blob_location::BlobLoc failed: {:?}",
                    e
                );
            }
            (Err(e), Ok(_)) => {
                println!(
                    "✗ arq7::BlobLoc failed: {:?}, blob_location::BlobLoc parsed",
                    e
                );
            }
            (Err(e1), Err(e2)) => {
                println!("✗ Both failed: arq7={:?}, blob_location={:?}", e1, e2);
            }
        }
    }

    fn create_complete_blob_loc_data() -> Vec<u8> {
        let mut data = Vec::new();

        // Complete, realistic BlobLoc data
        data.push(0x01); // blobIdentifier isNotNull
        let id = b"a1b2c3d4e5f6789012345678901234567890abcdef";
        data.extend_from_slice(&(id.len() as u64).to_be_bytes());
        data.extend_from_slice(id);

        data.push(0x01); // isPacked = true
        data.push(0x00); // isLargePack = false

        data.push(0x01); // relativePath isNotNull
        let path = b"/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/12/3456789A-BCDE-4F01-2345-6789ABCDEF01.pack";
        data.extend_from_slice(&(path.len() as u64).to_be_bytes());
        data.extend_from_slice(path);

        data.extend_from_slice(&4096u64.to_be_bytes()); // offset
        data.extend_from_slice(&8192u64.to_be_bytes()); // length
        data.push(0x01); // stretchEncryptionKey = true
        data.extend_from_slice(&2u32.to_be_bytes()); // compressionType = LZ4

        data
    }
}
