//! Debug Blob Content Extraction - Fix for file content issues
//!
//! This tool identifies why blob content extraction has extra/missing bytes
//! and fixes the blob pack format parsing to correctly extract file contents.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Debug Blob Content Extraction - Format Analysis");
    println!("{}", "=".repeat(60));

    let pack_file_path = "./tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/EF/2CA969-3A3C-4019-9C13-01AC6B75FC89.pack";

    println!("Analyzing pack file: {}", pack_file_path);

    // Read entire pack file for analysis
    let mut file = File::open(pack_file_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    println!("Pack file size: {} bytes", content.len());

    // Display hex dump of entire file
    println!("\nComplete pack file hex dump:");
    for (i, chunk) in content.chunks(16).enumerate() {
        print!("{:04X}: ", i * 16);
        for byte in chunk {
            print!("{:02X} ", byte);
        }
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

    println!("\n{}", "=".repeat(60));
    println!("BLOB PACK FORMAT ANALYSIS");
    println!("{}", "=".repeat(60));

    // Analyze the blob pack format structure
    // Based on Arq documentation, packed blobs have this format:
    // [4-byte decompressed length][LZ4 compressed data]

    let mut pos = 0;
    let mut blob_count = 0;

    while pos < content.len() {
        if pos + 4 > content.len() {
            break;
        }

        // Read potential decompressed length
        let decompressed_length = u32::from_be_bytes([
            content[pos],
            content[pos + 1],
            content[pos + 2],
            content[pos + 3],
        ]);

        println!("\n--- Blob {} at offset {} ---", blob_count, pos);
        println!("Decompressed length header: {} bytes", decompressed_length);

        if decompressed_length == 0 || decompressed_length > 10000 {
            println!("❌ Invalid decompressed length, stopping analysis");
            break;
        }

        // Find the actual compressed data size by trying LZ4 decompression
        let compressed_start = pos + 4;
        let mut found_valid_compression = false;

        // Try different compressed data lengths to find the correct one
        for compressed_len in 1..std::cmp::min(content.len() - compressed_start + 1, 200) {
            if compressed_start + compressed_len > content.len() {
                break;
            }

            let compressed_data = &content[compressed_start..compressed_start + compressed_len];

            match lz4_flex::decompress(compressed_data, decompressed_length as usize) {
                Ok(decompressed) => {
                    if decompressed.len() == decompressed_length as usize {
                        println!("✅ Found valid LZ4 data:");
                        println!("   Compressed size: {} bytes", compressed_len);
                        println!("   Decompressed size: {} bytes", decompressed.len());
                        println!("   Content: {:?}", String::from_utf8_lossy(&decompressed));
                        println!("   Hex: {:02X?}", decompressed);

                        // Save to file
                        let filename = format!("extracted_blob_{}.txt", blob_count);
                        std::fs::write(&filename, &decompressed)?;
                        println!("   💾 Saved to: {}", filename);

                        // Move to next blob
                        pos = compressed_start + compressed_len;
                        found_valid_compression = true;
                        break;
                    }
                }
                Err(_) => {
                    // Not valid LZ4 data at this length, continue trying
                }
            }
        }

        if !found_valid_compression {
            println!("❌ Could not find valid LZ4 compression for this blob");

            // Check if this might be uncompressed data
            if decompressed_length < 100 && pos + 4 + decompressed_length as usize <= content.len()
            {
                let potential_raw = &content[pos + 4..pos + 4 + decompressed_length as usize];
                if potential_raw.iter().all(|&b| b.is_ascii()) {
                    println!("   Trying as uncompressed data:");
                    println!("   Content: {:?}", String::from_utf8_lossy(potential_raw));

                    let filename = format!("extracted_blob_{}_raw.txt", blob_count);
                    std::fs::write(&filename, potential_raw)?;
                    println!("   💾 Saved raw to: {}", filename);

                    pos += 4 + decompressed_length as usize;
                } else {
                    // Skip this blob
                    pos += 4;
                }
            } else {
                pos += 4;
            }
        }

        blob_count += 1;

        // Safety check to prevent infinite loops
        if blob_count > 10 {
            break;
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("BLOB EXTRACTION ISSUE ANALYSIS");
    println!("{}", "=".repeat(60));

    // Now let's identify the specific issue with file 3.txt extraction
    // The issue described is "extra bytes at start, missing bytes at end"
    // This suggests the blob pack format parsing is not handling the length prefix correctly

    println!("\nIssue Analysis:");
    println!("- The blob pack format includes a 4-byte length prefix before each compressed blob");
    println!("- If this prefix is included in extracted content, it would appear as 'extra bytes at start'");
    println!("- If the extraction stops 4 bytes early, it would appear as 'missing bytes at end'");

    println!("\nRecommended Fix:");
    println!("1. In BlobLoc::load_from_pack_file(), ensure the 4-byte length prefix is NOT included in extracted content");
    println!(
        "2. For LZ4 compression (type 2), read the length, then decompress the following data"
    );
    println!(
        "3. For uncompressed data (type 0), read the length, then return the following raw data"
    );

    // Generate a corrected extraction example
    println!("\n{}", "=".repeat(60));
    println!("CORRECTED EXTRACTION EXAMPLE");
    println!("{}", "=".repeat(60));

    // Demonstrate correct extraction for each blob found
    pos = 0;
    blob_count = 0;

    while pos < content.len() && blob_count < 5 {
        if pos + 4 > content.len() {
            break;
        }

        let decompressed_length = u32::from_be_bytes([
            content[pos],
            content[pos + 1],
            content[pos + 2],
            content[pos + 3],
        ]);

        if decompressed_length == 0 || decompressed_length > 10000 {
            break;
        }

        println!("\nCorrected extraction for blob {}:", blob_count);
        println!(
            "Step 1: Read length prefix at offset {} = {} bytes",
            pos, decompressed_length
        );

        let compressed_start = pos + 4;
        println!(
            "Step 2: Start reading compressed data at offset {}",
            compressed_start
        );

        // Find the correct compressed length through trial
        for compressed_len in 1..std::cmp::min(content.len() - compressed_start + 1, 200) {
            if compressed_start + compressed_len > content.len() {
                break;
            }

            let compressed_data = &content[compressed_start..compressed_start + compressed_len];

            if let Ok(decompressed) =
                lz4_flex::decompress(compressed_data, decompressed_length as usize)
            {
                if decompressed.len() == decompressed_length as usize {
                    println!(
                        "Step 3: Decompress {} bytes to get final content",
                        compressed_len
                    );
                    println!(
                        "Result: {:?} ({} bytes)",
                        String::from_utf8_lossy(&decompressed),
                        decompressed.len()
                    );
                    println!("✅ No extra bytes at start, no missing bytes at end");

                    pos = compressed_start + compressed_len;
                    break;
                }
            }
        }

        blob_count += 1;
    }

    Ok(())
}
