use crate::error::Result;
use crate::lz4;
use crate::type_utils::ArqRead;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum CompressionType {
    None,
    Gzip,
    LZ4,
}

use std::io::Read;
// Removed unused import: use byteorder::{BigEndian, ReadBytesExt};
// The lz4_decompress_with_prefix function was removed as it's redundant.
// src/lz4.rs::decompress correctly handles the BigEndian prefix via read_arq_i32()
// and uses lz4_flex.

impl CompressionType {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<CompressionType> {
        let c = reader.read_arq_i32()?;

        Ok(match c {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            // Arq 7 BlobLoc.compressionType is u32.
            // The existing CompressionType::new takes ArqRead which reads i32.
            // This might be okay if the values are always positive and small.
            _ => return Err(crate::error::Error::InvalidData(format!("Compression type '{}' unknown", c))),
        })
    }

    pub fn decompress(compressed_data_with_optional_prefix: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        Ok(match compression_type {
            // Assuming lz4::decompress is fixed to handle BigEndian prefix.
            CompressionType::LZ4 => lz4::decompress(compressed_data_with_optional_prefix)?,
            CompressionType::Gzip => {
                // Gzip does not typically have an external length prefix in the same way.
                // The compressed stream is self-describing.
                // Need to implement gzip decompression.
                // For now, let's use a library like flate2.
                use flate2::read::GzDecoder;
                let mut decoder = GzDecoder::new(compressed_data_with_optional_prefix);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            CompressionType::None => compressed_data_with_optional_prefix.to_owned(),
        })
    }
}
