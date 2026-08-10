use flate2::read::GzDecoder;
use std::io::Read;

use crate::error::Error;
use crate::error::Result;
use crate::lz4;
use crate::type_utils::ArqRead;

#[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Gzip,
    LZ4,
    Lzfse,
}

impl TryFrom<i32> for CompressionType {
    type Error = Error;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CompressionType::None),
            1 => Ok(CompressionType::Gzip),
            2 => Ok(CompressionType::LZ4),
            3 => Ok(CompressionType::Lzfse),
            _ => Err(Error::InvalidFormat(format!(
                "Unknown compression type: {}",
                value
            ))),
        }
    }
}

impl TryFrom<u32> for CompressionType {
    type Error = Error;
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CompressionType::None),
            1 => Ok(CompressionType::Gzip),
            2 => Ok(CompressionType::LZ4),
            3 => Ok(CompressionType::Lzfse),
            _ => Err(Error::InvalidFormat(format!(
                "Unknown compression type: {}",
                value
            ))),
        }
    }
}

impl CompressionType {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<CompressionType> {
        let c = reader.read_arq_i32()?;
        CompressionType::try_from(c)
    }

    pub fn new_from_u32(index: u32) -> Result<CompressionType> {
        CompressionType::try_from(index)
    }

    pub fn decompress(compressed: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        Ok(match compression_type {
            CompressionType::LZ4 => lz4::decompress(compressed)?,
            CompressionType::Gzip => {
                let mut decoder = GzDecoder::new(compressed);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                decompressed
            }
            CompressionType::Lzfse => return Err(Error::UnsupportedFeature("LZFSE compression is not supported yet".to_string())),
            CompressionType::None => compressed.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
<<<<<<< ours — module `tests` (S+F, confidence: low)
// hint: Structural and logic conflict. Both design and behavior differ.
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_decompress_none() {
        let data = b"hello world test data";
        let decompressed = CompressionType::decompress(data, CompressionType::None).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_gzip() {
        let data = b"hello world test data";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = CompressionType::decompress(&compressed, CompressionType::Gzip).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_invalid_gzip() {
        let invalid_compressed = b"not gzip data";
        let result = CompressionType::decompress(invalid_compressed, CompressionType::Gzip);
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_lz4() {
        let data = b"hello world test data";
        let length: [u8; 4] = (data.len() as i32).to_be_bytes();
        let compressed_data = lz4_flex::compress(data);
        let compressed = [&length[..], &compressed_data].concat();

        let decompressed = CompressionType::decompress(&compressed, CompressionType::LZ4).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_invalid_lz4() {
        // First 4 bytes are original length (10 in big endian)
        // Rest is invalid LZ4 data
        let invalid_compressed = [0, 0, 0, 10, 255, 255, 255, 255];
        let result = CompressionType::decompress(&invalid_compressed, CompressionType::LZ4);
        assert!(result.is_err());
    }

    #[test]
    fn test_lzfse_unsupported() {
        let compressed_data = vec![1, 2, 3];
        let result = CompressionType::decompress(&compressed_data, CompressionType::Lzfse);
        assert!(result.is_err());
        if let Err(Error::UnsupportedFeature(msg)) = result {
            assert_eq!(msg, "LZFSE compression is not supported yet");
        } else {
            panic!("Expected UnsupportedFeature error");
        }
    }
}
