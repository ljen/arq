use crate::error::Result;
use crate::lz4;
use crate::type_utils::ArqRead;
use std::convert::From;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum CompressionType {
    None,
    Gzip,
    LZ4,
}

impl From<i32> for CompressionType {
    fn from(value: i32) -> Self {
        match value {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", value),
        }
    }
}

impl From<u32> for CompressionType {
    fn from(value: u32) -> Self {
        match value {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", value),
        }
    }
}

impl CompressionType {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<CompressionType> {
        let c = reader.read_arq_i32()?;

        Ok(match c {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", c),
        })
    }

    pub fn new_from_u32(index: u32) -> Result<CompressionType> {
        Ok(match index {
            0 => CompressionType::None,
            1 => CompressionType::Gzip,
            2 => CompressionType::LZ4,
            _ => panic!("Compression type '{}' unknown", index),
        })
    }

    pub fn decompress(compressed: &[u8], compression_type: CompressionType) -> Result<Vec<u8>> {
        Ok(match compression_type {
            CompressionType::LZ4 => lz4::decompress(compressed)?,
            CompressionType::Gzip => unimplemented!(),
            CompressionType::None => compressed.to_owned(),
        })
    }
}
