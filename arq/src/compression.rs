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
            CompressionType::Lzfse => unimplemented!(), // LZFSE is not supported yet
            CompressionType::None => compressed.to_owned(),
        })
    }
}
