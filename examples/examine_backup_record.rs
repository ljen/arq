use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/backupfolders/29F6E502-2737-4417-8023-4940D61BA375/backuprecords/00173/6107191.backuprecord";

    let mut file = BufReader::new(File::open(path)?);

    // Read the 4-byte decompressed length header
    let decompressed_length = file.read_u32::<BigEndian>()?;
    println!("Decompressed length: {}", decompressed_length);

    // Read all remaining compressed data
    let mut compressed_data = Vec::new();
    file.read_to_end(&mut compressed_data)?;
    println!("Compressed data length: {}", compressed_data.len());

    // Decompress using LZ4 with known decompressed size
    let decompressed = lz4_flex::decompress(&compressed_data, decompressed_length as usize)?;
    println!("Actual decompressed length: {}", decompressed.len());

    // Convert to string and print first 1000 characters
    let content = String::from_utf8_lossy(&decompressed);
    println!("First 1000 characters of decompressed content:");
    println!("{}", &content[..std::cmp::min(1000, content.len())]);

    // Try to find where the JSON parsing might be failing at position 1180
    let error_pos = 1180;
    if content.len() > error_pos {
        let start = if error_pos > 100 { error_pos - 100 } else { 0 };
        let end = std::cmp::min(error_pos + 100, content.len());
        println!("\nContext around position {}:", error_pos);
        println!("{}", &content[start..end]);
    }

    // Also look for boolean false values
    let mut pos = 0;
    while let Some(found_pos) = content[pos..].find("false") {
        let actual_pos = pos + found_pos;
        let start = if actual_pos > 50 { actual_pos - 50 } else { 0 };
        let end = std::cmp::min(actual_pos + 100, content.len());
        println!("\nContext around 'false' at position {}:", actual_pos);
        println!("{}", &content[start..end]);
        pos = actual_pos + 5; // Move past this "false"
        if pos >= content.len() {
            break;
        }
    }

    Ok(())
}
