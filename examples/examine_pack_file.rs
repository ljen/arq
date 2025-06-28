use byteorder::{BigEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pack_file_path = "tests/arq_storage_location/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/A4/D92A6D-C4D9-4ACC-B544-1DB0660F80DF.pack";
    let offset = 311;
    let length = 512;

    let mut file = BufReader::new(File::open(pack_file_path)?);
    let file_size = file.seek(SeekFrom::End(0))?;
    println!("Pack file size: {} bytes", file_size);

    // Read the beginning of the file
    file.seek(SeekFrom::Start(0))?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)?;
    println!("File header (first 16 bytes):");
    for (i, byte) in header.iter().enumerate() {
        print!("{:02x} ", byte);
        if (i + 1) % 8 == 0 {
            println!();
        }
    }
    println!();

    // Check if the first 4 bytes are a length
    let header_length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    println!("Header length interpretation: {}", header_length);

    // Read at the specified offset
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; length as usize];
    file.read_exact(&mut buffer)?;

    println!("\nData at offset {} (length {}):", offset, length);
    println!("First 64 bytes:");
    for (i, byte) in buffer.iter().take(64).enumerate() {
        print!("{:02x} ", byte);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();

    // Check if the first 4 bytes at offset are a length
    if buffer.len() >= 4 {
        let data_length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        println!("Length at offset (first 4 bytes): {}", data_length);

        // Try to decompress the remaining data as LZ4
        if buffer.len() > 4 {
            let compressed_data = &buffer[4..];
            println!("Compressed data length: {}", compressed_data.len());

            match lz4_flex::decompress(compressed_data, data_length as usize) {
                Ok(decompressed) => {
                    println!("Successfully decompressed {} bytes", decompressed.len());
                    println!("First 100 bytes of decompressed data:");
                    let preview = std::str::from_utf8(
                        &decompressed[..std::cmp::min(100, decompressed.len())],
                    )
                    .unwrap_or("(non-UTF8 data)");
                    println!("{}", preview);

                    // Try to interpret as binary Tree format
                    println!("\nTrying to parse as binary Tree...");
                    let mut cursor = std::io::Cursor::new(&decompressed);

                    // Read tree version
                    match cursor.read_u32::<BigEndian>() {
                        Ok(version) => {
                            println!("Tree version: {}", version);

                            // Read child nodes count
                            match cursor.read_u64::<BigEndian>() {
                                Ok(count) => {
                                    println!("Child nodes count: {}", count);
                                }
                                Err(e) => println!("Failed to read child nodes count: {}", e),
                            }
                        }
                        Err(e) => println!("Failed to read tree version: {}", e),
                    }
                }
                Err(e) => {
                    println!("LZ4 decompression failed: {}", e);

                    // Maybe it's not compressed or uses a different format
                    println!("Raw data interpretation (first 100 chars):");
                    let preview = std::str::from_utf8(&buffer[..std::cmp::min(100, buffer.len())])
                        .unwrap_or("(non-UTF8 data)");
                    println!("{}", preview);
                }
            }
        }
    }

    // Also examine some data before the offset to understand the pack structure
    println!("\nExamining data before offset...");
    if offset >= 64 {
        file.seek(SeekFrom::Start(offset - 64))?;
        let mut before_buffer = [0u8; 64];
        file.read_exact(&mut before_buffer)?;

        println!("64 bytes before offset {}:", offset);
        for (i, byte) in before_buffer.iter().enumerate() {
            print!("{:02x} ", byte);
            if (i + 1) % 16 == 0 {
                println!();
            }
        }
        println!();
    }

    Ok(())
}
