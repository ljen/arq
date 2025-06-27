use std::io::Cursor;

use crate::error::Result;
use crate::type_utils::ArqRead;

// Made public for testing purposes and integration tests
pub fn compress(src: &[u8]) -> Result<Vec<u8>> {
    let length: [u8; 4] = (src.len() as i32).to_be_bytes();
    // The original_len is i32, but lz4_flex::compress doesn't take original_len.
    // The prefix is added *after* compression.
    // The length prefix should be the *original (uncompressed)* length.
    let compressed_data = lz4_flex::compress(src);
    let all = [&length[..], &compressed_data].concat();
    Ok(all)
}

pub fn decompress(src: &[u8]) -> Result<Vec<u8>> {
    // Reverting to the version that uses lz4_flex::block::decompress
    // as it aligns with "LZ4 block format" and produced sane prefix debug logs.
    let mut reader = Cursor::new(src);
    let original_len = reader.read_arq_i32()? as usize;
    if original_len == 0 {
        return Ok(Vec::new());
    }
    // Assuming Arq's "LZ4 block format" means a raw block.
    // The data after the prefix (&src[4..]) is the raw block.
    // original_len is the expected decompressed size.
    lz4_flex::block::decompress(&src[4..], original_len).map_err(crate::error::ArqError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lz4() {
        let test = String::from("Test string we want to compress").into_bytes();
        let compressed = compress(&test).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        // We only read up to test.len() because decompressed fills the rest of the buffer
        // with zeros
        assert_eq!(test[..], decompressed[..test.len()]);
    }
}
