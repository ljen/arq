//! Test Blob Content Extraction Fix
//!
//! This test verifies that the blob pack format parsing fix correctly
//! extracts file content without extra bytes at start or missing bytes at end.

use arq::arq7::*;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Blob Content Extraction Fix");
    println!("{}", "=".repeat(50));

    let test_data_dir = "./tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9";

    // Test known blob locations from the pack file analysis
    // Blob pack: /FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/EF/2CA969-3A3C-4019-9C13-01AC6B75FC89.pack
    // Blob 0: offset 0, length should include 4-byte header + compressed data
    // Blob 1: offset 21, length should include 4-byte header + compressed data

    println!("Testing blob extraction with corrected format parsing...\n");

    // Create test blob locations based on our analysis
    let test_blobs = vec![
        (
            "first test file",
            BlobLoc {
                blob_identifier: "test_blob_0".to_string(),
                compression_type: 2, // LZ4
                is_packed: true,
                length: 21, // 4-byte header + 17 bytes compressed
                offset: 0,
                relative_path: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/EF/2CA969-3A3C-4019-9C13-01AC6B75FC89.pack".to_string(),
                stretch_encryption_key: false,
                is_large_pack: None,
            }
        ),
        (
            "this a file 2\n",
            BlobLoc {
                blob_identifier: "test_blob_1".to_string(),
                compression_type: 2, // LZ4
                is_packed: true,
                length: 19, // 4-byte header + 15 bytes compressed
                offset: 21,
                relative_path: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/EF/2CA969-3A3C-4019-9C13-01AC6B75FC89.pack".to_string(),
                stretch_encryption_key: false,
                is_large_pack: None,
            }
        ),
    ];

    for (i, (expected_content, blob_loc)) in test_blobs.iter().enumerate() {
        println!("--- Test Blob {} ---", i);
        println!("Expected content: {:?}", expected_content);
        println!("Blob offset: {}", blob_loc.offset);
        println!("Blob length: {}", blob_loc.length);

        match blob_loc.extract_content(Path::new(test_data_dir)) {
            Ok(extracted) => {
                let extracted_text = String::from_utf8_lossy(&extracted);

                println!("✅ Extraction successful!");
                println!("Extracted content: {:?}", extracted_text);
                println!("Extracted length: {} bytes", extracted.len());
                println!("Expected length: {} bytes", expected_content.len());

                // Check for exact match
                if extracted_text == *expected_content {
                    println!("✅ Content matches exactly!");
                } else {
                    println!("❌ Content mismatch!");

                    // Analyze the differences
                    let expected_bytes = expected_content.as_bytes();
                    let extracted_bytes = extracted.as_slice();

                    if extracted_bytes.len() > expected_bytes.len() {
                        let extra_count = extracted_bytes.len() - expected_bytes.len();
                        println!("   Extra {} bytes detected", extra_count);

                        if &extracted_bytes[extra_count..] == expected_bytes {
                            println!(
                                "   ❌ Extra bytes at START: {:02X?}",
                                &extracted_bytes[..extra_count]
                            );
                        } else if &extracted_bytes[..expected_bytes.len()] == expected_bytes {
                            println!(
                                "   ❌ Extra bytes at END: {:02X?}",
                                &extracted_bytes[expected_bytes.len()..]
                            );
                        }
                    } else if extracted_bytes.len() < expected_bytes.len() {
                        let missing_count = expected_bytes.len() - extracted_bytes.len();
                        println!("   Missing {} bytes", missing_count);

                        if expected_bytes.starts_with(extracted_bytes) {
                            println!(
                                "   ❌ Missing bytes at END: {:02X?}",
                                &expected_bytes[extracted_bytes.len()..]
                            );
                        }
                    }

                    // Byte-by-byte comparison
                    println!("   Byte-by-byte comparison:");
                    let max_len = std::cmp::max(expected_bytes.len(), extracted_bytes.len());
                    for j in 0..std::cmp::min(max_len, 20) {
                        let exp = if j < expected_bytes.len() {
                            Some(expected_bytes[j])
                        } else {
                            None
                        };
                        let ext = if j < extracted_bytes.len() {
                            Some(extracted_bytes[j])
                        } else {
                            None
                        };

                        match (exp, ext) {
                            (Some(e), Some(a)) if e == a => {
                                println!(
                                    "     {}: {:02X} '{}' ✅",
                                    j,
                                    e,
                                    if e.is_ascii_graphic() { e as char } else { '.' }
                                );
                            }
                            (Some(e), Some(a)) => {
                                println!(
                                    "     {}: expected {:02X} '{}', got {:02X} '{}' ❌",
                                    j,
                                    e,
                                    if e.is_ascii_graphic() { e as char } else { '.' },
                                    a,
                                    if a.is_ascii_graphic() { a as char } else { '.' }
                                );
                            }
                            (Some(e), None) => {
                                println!(
                                    "     {}: expected {:02X} '{}', but missing ❌",
                                    j,
                                    e,
                                    if e.is_ascii_graphic() { e as char } else { '.' }
                                );
                            }
                            (None, Some(a)) => {
                                println!(
                                    "     {}: unexpected {:02X} '{}' ❌",
                                    j,
                                    a,
                                    if a.is_ascii_graphic() { a as char } else { '.' }
                                );
                            }
                            (None, None) => break,
                        }
                    }
                }

                // Save extracted content to file for inspection
                let output_file = format!("test_blob_{}_extracted.txt", i);
                std::fs::write(&output_file, &extracted)?;
                println!("💾 Saved extracted content to: {}", output_file);
            }
            Err(e) => {
                println!("❌ Extraction failed: {}", e);
            }
        }

        println!();
    }

    println!("{}", "=".repeat(50));
    println!("Test Summary:");
    println!("- If content matches exactly: ✅ Fix is working correctly");
    println!("- If extra bytes at start: ❌ Length prefix not being stripped");
    println!("- If missing bytes at end: ❌ Length calculation or extraction incomplete");
    println!("- Check the saved files for manual verification");

    Ok(())
}
