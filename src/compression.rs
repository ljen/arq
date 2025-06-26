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
use byteorder::{BigEndian, ReadBytesExt};


// Helper function for LZ4 decompression with 4-byte big-endian length prefix
// This was implicitly used/assumed in arq7_format.rs, let's define it clearly here.
pub fn lz4_decompress_with_prefix(data_with_prefix: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(data_with_prefix);
    let _decompressed_size = cursor.read_u32::<BigEndian>()?; // Read the 4-byte prefix (decompressed length)
    // The lz4::decompress function in this crate seems to take the raw compressed block without the prefix,
    // and it figures out the decompressed size. Some LZ4 libraries require the original size.
    // The Arq format states "4-byte big-endian length followed by the compressed data".
    // Let's assume the existing lz4::decompress is fine if it doesn't need original size.
    // If lz4::decompress is a block decompressor, it doesn't use the prefix.
    // The prefix is for the *user* of LZ4 to know how much buffer to allocate if needed.
    // The `lz4_flex` crate, for example, its `decompress_into` needs output buffer size.
    // `decompress_size_prepended` handles a size prepended to the stream.

    // The existing lz4::decompress in this project might be from an older library or custom.
    // Let's re-check src/lz4.rs.
    // `src/lz4.rs` has `decompress(data: &[u8]) -> Result<Vec<u8>>`.
    // It uses `liblz4_sys::LZ4_decompress_safe` which requires knowing the output size.
    // It currently calculates this by reading a u32 from the *start* of the data.
    // THIS IS THE PREFIX. So `lz4::decompress` *already* handles the prefix.

    // Therefore, the distinction I was making might be incorrect if `lz4::decompress`
    // *already* expects the prefix.

    // Let's verify `lz4::decompress` behavior. If it reads its own prefix, then
    // `CompressionType::decompress` for LZ4 is already correct.
    // The problem arises if `data_with_prefix` has the prefix, and `lz4::decompress` also tries to read it.

    // From `src/lz4.rs`:
    // pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    //    let mut decompressed_len_arr = [0u8; 4];
    //    decompressed_len_arr.copy_from_slice(&data[0..4]);
    //    let decompressed_len = Cursor::new(&decompressed_len_arr).read_u32::<LittleEndian>()?;
    //    ...
    //    LZ4_decompress_safe(data[4..].as_ptr() as *const i8, ...
    // This confirms: `lz4::decompress` *does* expect the 4-byte prefix (LittleEndian though, Arq7 doc says BigEndian for prefix).
    // This is a bug if Arq7 uses BigEndian prefix and lz4.rs uses LittleEndian.

    // Arq 7 Documentation: "Data described ... as 'LZ4-compressed' is stored as a
    // 4-byte big-endian length followed by the compressed data".
    // Current `lz4::decompress` in `src/lz4.rs` reads a LittleEndian u32. This needs fixing.

    // Step 1: Fix lz4::decompress to read BigEndian prefix.
    // Step 2: Ensure CompressionType::decompress calls this fixed lz4::decompress.
    // Then, PackObject::get_content_arq7 can use CompressionType::decompress directly.
    // This change will be in src/lz4.rs.

    // For now, let's assume lz4::decompress will be fixed.
    // The current CompressionType::decompress is then conceptually correct.
    // The direct call to `lz4_decompress_with_prefix` in `PackObject::get_content_arq7`
    // was a workaround for the *assumption* that `lz4::decompress` was raw.
    // If `lz4::decompress` becomes prefix-aware (correctly BigEndian), that's the one to use.

    // Given this, the refactor for `CompressionType::decompress` itself is minimal,
    // it already calls `lz4::decompress`. The main fix is in `lz4.rs`.
    // No change here then, but `PackObject::get_content_arq7` should be changed back
    // to use `CompressionType::decompress` after `lz4.rs` is fixed.
    // This specific refactoring step for compression.rs is thus blocked by fixing lz4.rs.

    // Let's proceed with the plan to fix lz4.rs first.
    // After that, I will simplify PackObject::get_content_arq7.
    Ok(()) // Placeholder for actual implementation if needed
}


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
