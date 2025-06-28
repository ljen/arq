//! Pack File Analysis Tool
//!
//! This tool analyzes Arq 7 pack files to understand their internal structure,
//! identify patterns, and develop proper parsing strategies.

use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug)]
struct PackFileAnalysis {
    file_size: u64,
    header_analysis: HeaderAnalysis,
    entries: Vec<PackEntry>,
    potential_strings: Vec<String>,
    compression_signatures: Vec<CompressionSignature>,
}

#[derive(Debug)]
struct HeaderAnalysis {
    first_32_bytes: Vec<u8>,
    potential_length: u32,
    potential_count: u32,
    magic_signatures: Vec<String>,
}

#[derive(Debug)]
struct PackEntry {
    offset: u64,
    potential_length: u32,
    data_preview: Vec<u8>,
    analysis: String,
}

#[derive(Debug)]
struct CompressionSignature {
    offset: u64,
    signature_type: String,
    confidence: f32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let pack_file_path = if args.len() > 1 {
        &args[1]
    } else {
        // Default to our test pack file
        "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/89/88F120-159A-4AFF-A047-1C59ED169CE8.pack"
    };

    if !Path::new(pack_file_path).exists() {
        eprintln!("Pack file not found: {}", pack_file_path);
        eprintln!("Usage: {} [pack_file_path]", args[0]);
        return Ok(());
    }

    println!("🔍 Analyzing Pack File: {}", pack_file_path);
    println!("{}", "=".repeat(80));

    let analysis = analyze_pack_file(pack_file_path)?;
    print_analysis(&analysis);

    // Try different parsing strategies
    println!("\n🧪 Testing Parsing Strategies");
    println!("{}", "=".repeat(80));

    test_parsing_strategies(pack_file_path)?;

    Ok(())
}

fn analyze_pack_file(path: &str) -> Result<PackFileAnalysis, Box<dyn std::error::Error>> {
    let mut file = BufReader::new(File::open(path)?);
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    // Read and analyze header
    let header_analysis = analyze_header(&mut file)?;

    // Find potential entries
    let entries = find_pack_entries(&mut file)?;

    // Extract potential strings
    let potential_strings = extract_strings(&mut file)?;

    // Identify compression signatures
    let compression_signatures = identify_compression_signatures(&mut file)?;

    Ok(PackFileAnalysis {
        file_size,
        header_analysis,
        entries,
        potential_strings,
        compression_signatures,
    })
}

fn analyze_header(
    file: &mut BufReader<File>,
) -> Result<HeaderAnalysis, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;

    let mut first_32_bytes = vec![0u8; 32];
    file.read_exact(&mut first_32_bytes)?;

    // Try interpreting first 4 bytes as different formats
    let potential_length = u32::from_be_bytes([
        first_32_bytes[0],
        first_32_bytes[1],
        first_32_bytes[2],
        first_32_bytes[3],
    ]);
    let potential_count = u32::from_be_bytes([
        first_32_bytes[4],
        first_32_bytes[5],
        first_32_bytes[6],
        first_32_bytes[7],
    ]);

    // Look for magic signatures
    let mut magic_signatures = Vec::new();
    if let Ok(header_str) = String::from_utf8(first_32_bytes[0..8].to_vec()) {
        if header_str
            .chars()
            .all(|c| c.is_ascii() && (c.is_alphanumeric() || c.is_ascii_punctuation()))
        {
            magic_signatures.push(format!("ASCII: '{}'", header_str));
        }
    }

    // Check for common binary signatures
    if &first_32_bytes[0..4] == b"ARQO" {
        magic_signatures.push("Arq Encrypted Object".to_string());
    }
    if &first_32_bytes[0..4] == b"ARQ_" {
        magic_signatures.push("Arq Format".to_string());
    }

    Ok(HeaderAnalysis {
        first_32_bytes,
        potential_length,
        potential_count,
        magic_signatures,
    })
}

fn find_pack_entries(
    file: &mut BufReader<File>,
) -> Result<Vec<PackEntry>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let file_size = file.seek(SeekFrom::End(0))?;

    let mut entries = Vec::new();

    // Scan for potential length prefixes
    for offset in (0..file_size).step_by(4) {
        if offset + 8 > file_size {
            break;
        }

        file.seek(SeekFrom::Start(offset))?;

        if let Ok(potential_length) = file.read_u32::<BigEndian>() {
            // Check if this could be a valid length
            if potential_length > 0
                && potential_length < file_size as u32
                && offset + potential_length as u64 <= file_size
            {
                // Read some data to analyze
                let mut preview = vec![0u8; std::cmp::min(64, potential_length as usize)];
                file.read_exact(&mut preview)?;

                let analysis = analyze_data_chunk(&preview);

                entries.push(PackEntry {
                    offset,
                    potential_length,
                    data_preview: preview,
                    analysis,
                });

                // Don't analyze every 4 bytes if we found something promising
                if entries.len() > 20 {
                    break;
                }
            }
        }
    }

    Ok(entries)
}

fn analyze_data_chunk(data: &[u8]) -> String {
    let mut analysis = Vec::new();

    // Check for text content
    let text_ratio = data
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count() as f32
        / data.len() as f32;
    if text_ratio > 0.8 {
        analysis.push("Likely text/ASCII".to_string());
    }

    // Check for binary patterns
    if data.len() >= 4 {
        let first_bytes = &data[0..4];
        match first_bytes {
            [0x00, 0x00, _, _] => analysis.push("Starts with length prefix".to_string()),
            [0x78, 0x9C, _, _] => analysis.push("Zlib/Deflate compressed".to_string()),
            [0x1F, 0x8B, _, _] => analysis.push("Gzip compressed".to_string()),
            [0x04, 0x22, 0x4D, 0x18] => analysis.push("LZ4 compressed".to_string()),
            [b'A', b'R', b'Q', _] => analysis.push("Arq format".to_string()),
            _ => {}
        }
    }

    // Check entropy (randomness)
    let entropy = calculate_entropy(data);
    if entropy > 7.5 {
        analysis.push("High entropy (compressed/encrypted)".to_string());
    } else if entropy < 3.0 {
        analysis.push("Low entropy (structured/text)".to_string());
    }

    // Look for UUID patterns
    if let Ok(text) = String::from_utf8(data.to_vec()) {
        if text.contains('-') && text.len() >= 36 {
            if text.chars().filter(|&c| c == '-').count() >= 4 {
                analysis.push("Contains UUID-like strings".to_string());
            }
        }
    }

    if analysis.is_empty() {
        "Binary data".to_string()
    } else {
        analysis.join(", ")
    }
}

fn calculate_entropy(data: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

fn extract_strings(file: &mut BufReader<File>) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    let mut buffer = vec![0u8; file_size as usize];
    file.read_exact(&mut buffer)?;

    let mut strings = Vec::new();
    let mut current_string = Vec::new();

    for &byte in &buffer {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_string.push(byte);
        } else {
            if current_string.len() >= 4 {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.push(s);
                }
            }
            current_string.clear();
        }
    }

    // Filter interesting strings
    strings.retain(|s| {
        s.len() >= 4
            && (s.contains("pack")
                || s.contains("blob")
                || s.contains(".txt")
                || s.contains("FD5575D9")
                || s.contains("/")
                || s.len() > 20)
    });

    Ok(strings)
}

fn identify_compression_signatures(
    file: &mut BufReader<File>,
) -> Result<Vec<CompressionSignature>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    let mut buffer = vec![0u8; file_size as usize];
    file.read_exact(&mut buffer)?;

    let mut signatures = Vec::new();

    // Scan for compression signatures
    for (i, window) in buffer.windows(4).enumerate() {
        match window {
            [0x78, 0x9C, _, _] => signatures.push(CompressionSignature {
                offset: i as u64,
                signature_type: "Zlib/Deflate".to_string(),
                confidence: 0.9,
            }),
            [0x1F, 0x8B, _, _] => signatures.push(CompressionSignature {
                offset: i as u64,
                signature_type: "Gzip".to_string(),
                confidence: 0.95,
            }),
            [0x04, 0x22, 0x4D, 0x18] => signatures.push(CompressionSignature {
                offset: i as u64,
                signature_type: "LZ4".to_string(),
                confidence: 0.8,
            }),
            _ => {}
        }
    }

    Ok(signatures)
}

fn print_analysis(analysis: &PackFileAnalysis) {
    println!("📊 Pack File Analysis Results");
    println!("{}", "-".repeat(50));
    println!("File Size: {} bytes", analysis.file_size);

    println!("\n🔬 Header Analysis:");
    println!(
        "First 32 bytes: {:02X?}",
        &analysis.header_analysis.first_32_bytes
    );
    println!(
        "Potential length (BE): {}",
        analysis.header_analysis.potential_length
    );
    println!(
        "Potential count (BE): {}",
        analysis.header_analysis.potential_count
    );

    if !analysis.header_analysis.magic_signatures.is_empty() {
        println!(
            "Magic signatures: {:?}",
            analysis.header_analysis.magic_signatures
        );
    }

    println!("\n📦 Potential Pack Entries ({}):", analysis.entries.len());
    for (i, entry) in analysis.entries.iter().take(10).enumerate() {
        println!(
            "Entry #{}: offset={}, length={}, analysis={}",
            i + 1,
            entry.offset,
            entry.potential_length,
            entry.analysis
        );
        println!(
            "  Preview: {:02X?}",
            &entry.data_preview[0..std::cmp::min(16, entry.data_preview.len())]
        );
    }

    if analysis.entries.len() > 10 {
        println!("... and {} more entries", analysis.entries.len() - 10);
    }

    println!(
        "\n🔤 Extracted Strings ({}):",
        analysis.potential_strings.len()
    );
    for string in analysis.potential_strings.iter().take(15) {
        println!("  '{}'", string);
    }

    if analysis.potential_strings.len() > 15 {
        println!(
            "  ... and {} more strings",
            analysis.potential_strings.len() - 15
        );
    }

    println!(
        "\n🗜️ Compression Signatures ({}):",
        analysis.compression_signatures.len()
    );
    for sig in &analysis.compression_signatures {
        println!(
            "  {} at offset {} (confidence: {:.1}%)",
            sig.signature_type,
            sig.offset,
            sig.confidence * 100.0
        );
    }
}

fn test_parsing_strategies(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = BufReader::new(File::open(path)?);

    println!("Strategy 1: Header + Length + LZ4 Data");
    test_header_length_lz4(&mut file)?;

    println!("\nStrategy 2: Directory Structure Parsing");
    test_directory_structure(&mut file)?;

    println!("\nStrategy 3: Sequential Entry Reading");
    test_sequential_entries(&mut file)?;

    println!("\nStrategy 4: Binary Tree Format");
    test_binary_tree_format(&mut file)?;

    Ok(())
}

fn test_header_length_lz4(file: &mut BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;

    // Read potential header
    let total_length = file.read_u32::<BigEndian>()?;
    println!("  Total pack length: {}", total_length);

    // Try to read first entry
    let entry_length = file.read_u32::<BigEndian>()?;
    println!("  First entry length: {}", entry_length);

    if entry_length > 0 && entry_length < 65536 {
        let mut entry_data = vec![0u8; entry_length as usize];
        file.read_exact(&mut entry_data)?;

        // Try LZ4 decompression
        if entry_data.len() >= 4 {
            let decompressed_length =
                u32::from_be_bytes([entry_data[0], entry_data[1], entry_data[2], entry_data[3]]);
            println!("    Decompressed length: {}", decompressed_length);

            if decompressed_length > 0 && decompressed_length < 1048576 {
                match lz4_flex::decompress(&entry_data[4..], decompressed_length as usize) {
                    Ok(decompressed) => {
                        println!(
                            "    ✅ LZ4 decompression successful! {} bytes",
                            decompressed.len()
                        );
                        analyze_decompressed_data(&decompressed);
                    }
                    Err(e) => println!("    ❌ LZ4 decompression failed: {}", e),
                }
            }
        }
    }

    Ok(())
}

fn test_directory_structure(file: &mut BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;

    // Skip total length
    file.read_u32::<BigEndian>()?;

    // Try reading as directory entries
    for i in 0..5 {
        match file.read_u32::<BigEndian>() {
            Ok(entry_type) => {
                println!("  Entry {}: type/size = {}", i, entry_type);

                // Try reading name length
                if let Ok(name_len) = file.read_u32::<BigEndian>() {
                    if name_len > 0 && name_len < 256 {
                        let mut name_bytes = vec![0u8; name_len as usize];
                        if file.read_exact(&mut name_bytes).is_ok() {
                            if let Ok(name) = String::from_utf8(name_bytes) {
                                println!("    Name: '{}'", name);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(())
}

fn test_sequential_entries(file: &mut BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(0))?;
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    let mut offset = 0u64;
    let mut entry_count = 0;

    while offset < file_size && entry_count < 10 {
        file.seek(SeekFrom::Start(offset))?;

        if let Ok(length) = file.read_u32::<BigEndian>() {
            if length > 0 && length < file_size as u32 && offset + length as u64 <= file_size {
                println!(
                    "  Entry {}: offset={}, length={}",
                    entry_count, offset, length
                );

                // Read some data to identify type
                let mut preview = vec![0u8; std::cmp::min(32, length as usize)];
                file.read_exact(&mut preview)?;

                let analysis = analyze_data_chunk(&preview);
                println!("    Analysis: {}", analysis);

                offset += 4 + length as u64;
                entry_count += 1;
            } else {
                offset += 4;
            }
        } else {
            break;
        }
    }

    Ok(())
}

fn test_binary_tree_format(file: &mut BufReader<File>) -> Result<(), Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(311))?; // Known offset from backup record

    let mut buffer = vec![0u8; 512]; // Known length from backup record
    file.read_exact(&mut buffer)?;

    println!("  Reading from known tree offset (311, length 512)");
    println!("  First 32 bytes: {:02X?}", &buffer[0..32]);

    // Try interpreting as binary tree
    let mut cursor = std::io::Cursor::new(&buffer);

    // Tree format: version (u32) + child_count (u64) + children
    if let Ok(version) = cursor.read_u32::<BigEndian>() {
        println!("    Potential tree version: {}", version);

        if let Ok(child_count) = cursor.read_u64::<BigEndian>() {
            println!("    Potential child count: {}", child_count);

            if child_count > 0 && child_count < 100 {
                println!("    Attempting to read {} children...", child_count);

                for i in 0..std::cmp::min(child_count, 3) {
                    if let Ok(name_len) = cursor.read_u64::<BigEndian>() {
                        if name_len > 0 && name_len < 256 {
                            let mut name_bytes = vec![0u8; name_len as usize];
                            if cursor.read_exact(&mut name_bytes).is_ok() {
                                if let Ok(name) = String::from_utf8(name_bytes) {
                                    println!("      Child {}: '{}'", i, name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Try LZ4 decompression on the entire buffer
    println!("  Trying LZ4 decompression on entire buffer...");
    if buffer.len() >= 4 {
        let decompressed_length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        println!("    Indicated decompressed length: {}", decompressed_length);

        if decompressed_length > 0 && decompressed_length < 65536 {
            match lz4_flex::decompress(&buffer[4..], decompressed_length as usize) {
                Ok(decompressed) => {
                    println!(
                        "    ✅ LZ4 decompression successful! {} bytes",
                        decompressed.len()
                    );
                    analyze_decompressed_data(&decompressed);
                }
                Err(e) => println!("    ❌ LZ4 decompression failed: {}", e),
            }
        }
    }

    Ok(())
}

fn analyze_decompressed_data(data: &[u8]) {
    println!("      Decompressed data analysis:");
    println!("        Length: {} bytes", data.len());
    println!(
        "        First 32 bytes: {:02X?}",
        &data[0..std::cmp::min(32, data.len())]
    );

    // Try to interpret as text
    if let Ok(text) = String::from_utf8(data.to_vec()) {
        if text.chars().take(100).all(|c| c.is_ascii()) {
            println!(
                "        ASCII text preview: '{}'",
                &text[0..std::cmp::min(100, text.len())]
            );
        }
    }

    // Try to parse as binary tree
    let mut cursor = std::io::Cursor::new(data);
    if let Ok(version) = cursor.read_u32::<BigEndian>() {
        println!("        Potential tree version: {}", version);
        if let Ok(child_count) = cursor.read_u64::<BigEndian>() {
            println!("        Potential child count: {}", child_count);
        }
    }
}
