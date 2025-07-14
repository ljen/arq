//! Enhanced BlobLoc format detection and parsing with robust error recovery
//!
//! This module provides utilities to detect different BlobLoc binary formats
//! and implement recovery mechanisms for misaligned or corrupted data.

use crate::arq7::binary::ArqBinaryReader;
use crate::error::{Error, Result};
use byteorder::ReadBytesExt;
use std::io::{Seek, SeekFrom};

/// Format variants detected in BlobLoc parsing
#[derive(Debug, Clone, PartialEq)]
pub enum BlobLocFormat {
    /// Standard Arq7 format with all expected fields
    Standard,
    /// Misaligned format where relativePath data is shifted
    MisalignedPath,
    /// Pack format with additional metadata fields
    PackFormat,
    /// Legacy format with different field ordering
    Legacy,
    /// Unknown/corrupted format
    Unknown,
}

/// Enhanced BlobLoc parser with format detection and recovery
pub struct BlobLocParser<R: ArqBinaryReader + Seek> {
    reader: R,
    format: Option<BlobLocFormat>,
}

impl<R: ArqBinaryReader + Seek> BlobLocParser<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            format: None,
        }
    }

    /// Detect the BlobLoc format by analyzing the binary structure
    pub fn detect_format(&mut self) -> Result<BlobLocFormat> {
        let start_pos = self.reader.stream_position().map_err(Error::IoError)?;

        // Try to parse with standard format first
        match self.try_parse_standard() {
            Ok(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
                self.format = Some(BlobLocFormat::Standard);
                return Ok(BlobLocFormat::Standard);
            }
            Err(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
            }
        }

        // Try misaligned path format
        match self.try_parse_misaligned() {
            Ok(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
                self.format = Some(BlobLocFormat::MisalignedPath);
                return Ok(BlobLocFormat::MisalignedPath);
            }
            Err(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
            }
        }

        // Try pack format
        match self.try_parse_pack_format() {
            Ok(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
                self.format = Some(BlobLocFormat::PackFormat);
                return Ok(BlobLocFormat::PackFormat);
            }
            Err(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
            }
        }

        // Try legacy format
        match self.try_parse_legacy() {
            Ok(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
                self.format = Some(BlobLocFormat::Legacy);
                return Ok(BlobLocFormat::Legacy);
            }
            Err(_) => {
                self.reader
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::IoError)?;
            }
        }

        self.format = Some(BlobLocFormat::Unknown);
        Ok(BlobLocFormat::Unknown)
    }

    /// Parse BlobLoc with the detected or specified format
    pub fn parse_with_format(&mut self, format: BlobLocFormat) -> Result<EnhancedBlobLoc> {
        match format {
            BlobLocFormat::Standard => self.parse_standard(),
            BlobLocFormat::MisalignedPath => self.parse_misaligned(),
            BlobLocFormat::PackFormat => self.parse_pack_format(),
            BlobLocFormat::Legacy => self.parse_legacy(),
            BlobLocFormat::Unknown => self.parse_with_recovery(),
        }
    }

    /// Parse with automatic format detection
    pub fn parse(&mut self) -> Result<EnhancedBlobLoc> {
        let format = self.detect_format()?;
        self.parse_with_format(format)
    }

    /// Try parsing with standard Arq7 format
    fn try_parse_standard(&mut self) -> Result<()> {
        // Validate standard format structure without consuming data
        let _blob_identifier = self.reader.read_arq_string_required()?;
        let _is_packed = self.reader.read_arq_bool()?;
        let _is_large_pack = self.reader.read_arq_bool()?;
        let _relative_path = self.reader.read_arq_string()?;
        let _offset = self.reader.read_arq_u64()?;
        let _length = self.reader.read_arq_u64()?;
        let _stretch_key = self.reader.read_arq_bool()?;
        let _compression = self.reader.read_arq_u32()?;
        Ok(())
    }

    /// Try parsing with misaligned path format
    fn try_parse_misaligned(&mut self) -> Result<()> {
        let _blob_identifier = self.reader.read_arq_string_required()?;
        let _is_packed = self.reader.read_arq_bool()?;
        let _is_large_pack = self.reader.read_arq_bool()?;

        // In misaligned format, relativePath.isNotNull might be false
        // but path data follows anyway
        let path_null_flag =
            ReadBytesExt::read_u8(&mut self.reader).map_err(|_| Error::ParseError)?;
        if path_null_flag == 0x00 {
            // This might be misaligned - check if the next bytes look like path data
            if self.detect_hidden_path_data()? {
                return Ok(());
            }
        }

        Err(Error::ParseError)
    }

    /// Try parsing with pack format (may have additional fields)
    fn try_parse_pack_format(&mut self) -> Result<()> {
        let _blob_identifier = self.reader.read_arq_string_required()?;
        let _is_packed = self.reader.read_arq_bool()?;
        let _is_large_pack = self.reader.read_arq_bool()?;

        // Pack format might have additional metadata
        let _maybe_pack_metadata = self.reader.read_arq_u32().ok();

        let _relative_path = self.reader.read_arq_string()?;
        let _offset = self.reader.read_arq_u64()?;
        let _length = self.reader.read_arq_u64()?;
        let _stretch_key = self.reader.read_arq_bool()?;
        let _compression = self.reader.read_arq_u32()?;
        Ok(())
    }

    /// Try parsing with legacy format (different field order)
    fn try_parse_legacy(&mut self) -> Result<()> {
        let _blob_identifier = self.reader.read_arq_string_required()?;
        let _is_packed = self.reader.read_arq_bool()?;
        // Legacy might not have isLargePack field
        let _relative_path = self.reader.read_arq_string()?;
        let _offset = self.reader.read_arq_u64()?;
        let _length = self.reader.read_arq_u64()?;
        let _stretch_key = self.reader.read_arq_bool()?;
        let _compression = self.reader.read_arq_u32()?;
        Ok(())
    }

    /// Parse with standard format
    fn parse_standard(&mut self) -> Result<EnhancedBlobLoc> {
        let blob_identifier = self.reader.read_arq_string_required()?;
        let is_packed = self.reader.read_arq_bool()?;
        let is_large_pack = self.reader.read_arq_bool()?;
        let relative_path = self.reader.read_arq_string()?.unwrap_or_default();
        let offset = self.reader.read_arq_u64()?;
        let length = self.reader.read_arq_u64()?;
        let stretch_encryption_key = self.reader.read_arq_bool()?;
        let compression_type = self.reader.read_arq_u32()?;

        Ok(EnhancedBlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack),
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            format: BlobLocFormat::Standard,
            recovery_applied: false,
        })
    }

    /// Parse with misaligned path recovery
    fn parse_misaligned(&mut self) -> Result<EnhancedBlobLoc> {
        let blob_identifier = self.reader.read_arq_string_required()?;
        let is_packed = self.reader.read_arq_bool()?;
        let is_large_pack = self.reader.read_arq_bool()?;

        // Handle misaligned path
        let relative_path = self.recover_misaligned_path()?;

        let offset = self.reader.read_arq_u64()?;
        let length = self.reader.read_arq_u64()?;
        let stretch_encryption_key = self.reader.read_arq_bool()?;
        let compression_type = self.reader.read_arq_u32()?;

        Ok(EnhancedBlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack),
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            format: BlobLocFormat::MisalignedPath,
            recovery_applied: true,
        })
    }

    /// Parse with pack format
    fn parse_pack_format(&mut self) -> Result<EnhancedBlobLoc> {
        let blob_identifier = self.reader.read_arq_string_required()?;
        let is_packed = self.reader.read_arq_bool()?;
        let is_large_pack = self.reader.read_arq_bool()?;

        // Skip potential pack metadata
        let _pack_metadata = self.reader.read_arq_u32().ok();

        let relative_path = self.reader.read_arq_string()?.unwrap_or_default();
        let offset = self.reader.read_arq_u64()?;
        let length = self.reader.read_arq_u64()?;
        let stretch_encryption_key = self.reader.read_arq_bool()?;
        let compression_type = self.reader.read_arq_u32()?;

        Ok(EnhancedBlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack),
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            format: BlobLocFormat::PackFormat,
            recovery_applied: true,
        })
    }

    /// Parse with legacy format
    fn parse_legacy(&mut self) -> Result<EnhancedBlobLoc> {
        let blob_identifier = self.reader.read_arq_string_required()?;
        let is_packed = self.reader.read_arq_bool()?;
        let relative_path = self.reader.read_arq_string()?.unwrap_or_default();
        let offset = self.reader.read_arq_u64()?;
        let length = self.reader.read_arq_u64()?;
        let stretch_encryption_key = self.reader.read_arq_bool()?;
        let compression_type = self.reader.read_arq_u32()?;

        Ok(EnhancedBlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: None, // Legacy format doesn't have this field
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            format: BlobLocFormat::Legacy,
            recovery_applied: true,
        })
    }

    /// Parse with aggressive recovery for unknown formats
    fn parse_with_recovery(&mut self) -> Result<EnhancedBlobLoc> {
        // Try byte-by-byte recovery
        for skip_bytes in 0..16 {
            let start_pos = self.reader.stream_position().map_err(Error::IoError)?;

            // Skip some bytes and try parsing
            for _ in 0..skip_bytes {
                if ReadBytesExt::read_u8(&mut self.reader).is_err() {
                    break;
                }
            }

            if let Ok(blob_loc) = self.try_parse_any_format() {
                return Ok(EnhancedBlobLoc {
                    blob_identifier: blob_loc.blob_identifier,
                    is_packed: blob_loc.is_packed,
                    is_large_pack: blob_loc.is_large_pack,
                    relative_path: blob_loc.relative_path,
                    offset: blob_loc.offset,
                    length: blob_loc.length,
                    stretch_encryption_key: blob_loc.stretch_encryption_key,
                    compression_type: blob_loc.compression_type,
                    format: BlobLocFormat::Unknown,
                    recovery_applied: true,
                });
            }

            self.reader
                .seek(SeekFrom::Start(start_pos))
                .map_err(Error::IoError)?;
        }

        Err(Error::ParseError)
    }

    /// Try parsing with any format as a fallback
    fn try_parse_any_format(&mut self) -> Result<EnhancedBlobLoc> {
        // Most permissive parsing - try to extract any valid-looking data
        let blob_identifier = self
            .reader
            .read_arq_string()
            .unwrap_or(None)
            .unwrap_or_else(|| "unknown".to_string());

        let is_packed = self.reader.read_arq_bool().unwrap_or(false);
        let is_large_pack = self.reader.read_arq_bool().ok();

        let relative_path = self
            .reader
            .read_arq_string()
            .unwrap_or(None)
            .unwrap_or_default();

        let offset = self.reader.read_arq_u64().unwrap_or(0);
        let length = self.reader.read_arq_u64().unwrap_or(0);
        let stretch_encryption_key = self.reader.read_arq_bool().unwrap_or(true);
        let compression_type = self.reader.read_arq_u32().unwrap_or(2); // Default to LZ4

        Ok(EnhancedBlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack,
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
            format: BlobLocFormat::Unknown,
            recovery_applied: true,
        })
    }

    /// Detect if there's hidden path data after a null flag
    fn detect_hidden_path_data(&mut self) -> Result<bool> {
        let pos = self.reader.stream_position().map_err(Error::IoError)?;

        // Try to read what might be path data
        let mut potential_path = Vec::new();
        for _ in 0..256 {
            // Reasonable path length limit
            match ReadBytesExt::read_u8(&mut self.reader) {
                Ok(0) => break, // Null terminator
                Ok(b)
                    if b.is_ascii()
                        && (b.is_ascii_alphanumeric()
                            || b == b'/'
                            || b == b'.'
                            || b == b'-'
                            || b == b'_') =>
                {
                    potential_path.push(b);
                }
                _ => break,
            }
        }

        self.reader
            .seek(SeekFrom::Start(pos))
            .map_err(Error::IoError)?;

        // Check if this looks like a path
        if potential_path.len() > 3 {
            let path_str = String::from_utf8_lossy(&potential_path);
            Ok(path_str.starts_with('/') || path_str.contains("pack") || path_str.contains("blob"))
        } else {
            Ok(false)
        }
    }

    /// Recover misaligned path data
    fn recover_misaligned_path(&mut self) -> Result<String> {
        let path_null_flag =
            ReadBytesExt::read_u8(&mut self.reader).map_err(|_| Error::ParseError)?;

        if path_null_flag != 0x00 {
            // Not misaligned, read normally
            self.reader
                .seek(SeekFrom::Current(-1))
                .map_err(Error::IoError)?;
            return Ok(self.reader.read_arq_string()?.unwrap_or_default());
        }

        // Try to recover hidden path data
        let mut path_bytes = Vec::new();
        let mut found_valid_path = false;

        // Read until we find a reasonable path or hit a limit
        for _ in 0..512 {
            match ReadBytesExt::read_u8(&mut self.reader) {
                Ok(0) => break, // Null terminator
                Ok(b'/') if path_bytes.is_empty() => {
                    path_bytes.push(b'/');
                    found_valid_path = true;
                }
                Ok(byte)
                    if found_valid_path
                        && (byte.is_ascii_alphanumeric()
                            || byte == b'/'
                            || byte == b'.'
                            || byte == b'-'
                            || byte == b'_'
                            || byte == b' ') =>
                {
                    path_bytes.push(byte);
                }
                Ok(byte) if !found_valid_path && byte.is_ascii_alphabetic() => {
                    // Might be part of a path without leading slash
                    path_bytes.push(byte);
                    if path_bytes.len() > 3 {
                        let partial = String::from_utf8_lossy(&path_bytes);
                        if partial.contains("pack") || partial.contains("blob") {
                            found_valid_path = true;
                        }
                    }
                }
                _ => break,
            }
        }

        if found_valid_path && !path_bytes.is_empty() {
            Ok(String::from_utf8_lossy(&path_bytes).into_owned())
        } else {
            Ok(String::new())
        }
    }
}

/// Enhanced BlobLoc with format information and recovery status
#[derive(Debug, Clone)]
pub struct EnhancedBlobLoc {
    pub blob_identifier: String,
    pub is_packed: bool,
    pub is_large_pack: Option<bool>,
    pub relative_path: String,
    pub offset: u64,
    pub length: u64,
    pub stretch_encryption_key: bool,
    pub compression_type: u32,
    pub format: BlobLocFormat,
    pub recovery_applied: bool,
}

impl EnhancedBlobLoc {
    /// Convert to standard arq7::BlobLoc
    pub fn to_arq7_blob_loc(self) -> crate::arq7::BlobLoc {
        crate::arq7::BlobLoc {
            blob_identifier: self.blob_identifier,
            compression_type: self.compression_type,
            is_packed: self.is_packed,
            length: self.length,
            offset: self.offset,
            relative_path: self.relative_path,
            stretch_encryption_key: self.stretch_encryption_key,
            is_large_pack: self.is_large_pack,
        }
    }

    /// Convert to blob_location::BlobLoc
    pub fn to_blob_location(self) -> crate::blob_location::BlobLoc {
        crate::blob_location::BlobLoc {
            blob_identifier: self.blob_identifier,
            compression_type: self.compression_type,
            is_packed: self.is_packed,
            length: self.length,
            offset: self.offset,
            relative_path: self.relative_path,
            stretch_encryption_key: self.stretch_encryption_key,
            is_large_pack: self.is_large_pack,
        }
    }

    /// Check if the parsed data looks reasonable
    pub fn validate(&self) -> bool {
        // Basic validation checks
        if self.blob_identifier.is_empty() {
            return false;
        }

        // Check for abnormal values that indicate parsing errors
        if self.offset > 1_000_000_000_000 || self.length > 1_000_000_000_000 {
            return false;
        }

        // Path validation if present
        if !self.relative_path.is_empty() {
            if self.relative_path.len() > 4096 {
                return false;
            }

            // Should contain backup-related patterns or start with /
            let has_backup_patterns = self.relative_path.contains("pack")
                || self.relative_path.contains("blob")
                || self.relative_path.contains("objects");

            if !self.relative_path.starts_with('/') && !has_backup_patterns {
                return false;
            }
        }

        true
    }
}

/// Utility function to parse BlobLoc with enhanced error recovery
pub fn parse_blob_loc_enhanced<R: ArqBinaryReader + Seek>(reader: R) -> Result<EnhancedBlobLoc> {
    let mut parser = BlobLocParser::new(reader);
    let blob_loc = parser.parse()?;

    if !blob_loc.validate() {
        return Err(Error::InvalidFormat(
            "BlobLoc validation failed".to_string(),
        ));
    }

    Ok(blob_loc)
}

/// Utility function to safely parse BlobLoc counts to prevent memory issues
pub fn validate_blob_count(count: u64) -> Result<usize> {
    const MAX_REASONABLE_BLOB_COUNT: u64 = 1_000_000; // 1 million blobs max

    if count > MAX_REASONABLE_BLOB_COUNT {
        return Err(Error::InvalidFormat(format!(
            "BlobLoc count {} exceeds reasonable limit of {}",
            count, MAX_REASONABLE_BLOB_COUNT
        )));
    }

    Ok(count as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_format_detection() {
        // Test standard format detection
        let standard_data = create_standard_test_data();
        let cursor = Cursor::new(&standard_data);
        let mut parser = BlobLocParser::new(cursor);

        let format = parser.detect_format().unwrap();
        assert_eq!(format, BlobLocFormat::Standard);
    }

    #[test]
    fn test_blob_count_validation() {
        assert!(validate_blob_count(100).is_ok());
        assert!(validate_blob_count(1_000_000).is_ok());
        assert!(validate_blob_count(1_000_001).is_err());
        assert!(validate_blob_count(7885894706840955694).is_err());
    }

    fn create_standard_test_data() -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x01); // identifier isNotNull
        let id = b"test123";
        data.extend_from_slice(&(id.len() as u64).to_be_bytes());
        data.extend_from_slice(id);
        data.push(0x01); // isPacked
        data.push(0x00); // isLargePack
        data.push(0x01); // path isNotNull
        let path = b"/test/path.pack";
        data.extend_from_slice(&(path.len() as u64).to_be_bytes());
        data.extend_from_slice(path);
        data.extend_from_slice(&1024u64.to_be_bytes()); // offset
        data.extend_from_slice(&2048u64.to_be_bytes()); // length
        data.push(0x01); // stretch key
        data.extend_from_slice(&2u32.to_be_bytes()); // compression
        data
    }
}

/// Unified BlobLoc parsing utilities for both arq7::BlobLoc and blob_location::BlobLoc
pub mod unified_parsing {
    use super::*;

    /// Parse BlobLoc with automatic format detection and recovery
    pub fn parse_blob_loc_unified<R: ArqBinaryReader>(
        reader: &mut R,
    ) -> Result<crate::arq7::BlobLoc> {
        // Try standard parsing first
        match parse_blob_loc_standard(reader) {
            Ok(blob_loc) => {
                if validate_blob_loc_data(&blob_loc) {
                    Ok(blob_loc)
                } else {
                    Err(Error::InvalidFormat(
                        "BlobLoc validation failed".to_string(),
                    ))
                }
            }
            Err(_) => {
                // Try recovery parsing
                parse_blob_loc_with_recovery(reader)
            }
        }
    }

    /// Standard BlobLoc parsing
    fn parse_blob_loc_standard<R: ArqBinaryReader>(reader: &mut R) -> Result<crate::arq7::BlobLoc> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack = reader.read_arq_bool()?;
        let relative_path = reader.read_arq_string()?.unwrap_or_default();
        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;
        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;

        Ok(crate::arq7::BlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack),
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
        })
    }

    /// BlobLoc parsing with recovery mechanisms
    fn parse_blob_loc_with_recovery<R: ArqBinaryReader>(
        reader: &mut R,
    ) -> Result<crate::arq7::BlobLoc> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack = reader.read_arq_bool()?;

        // Enhanced path recovery
        let relative_path = recover_relative_path(reader)?;

        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;

        // Validate and sanitize offset/length
        let safe_offset = if offset > 1_000_000_000_000 {
            0
        } else {
            offset
        };
        let safe_length = if length > 1_000_000_000_000 {
            0
        } else {
            length
        };

        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;

        Ok(crate::arq7::BlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack),
            relative_path,
            offset: safe_offset,
            length: safe_length,
            stretch_encryption_key,
            compression_type,
        })
    }

    /// Recover relative path from potentially misaligned data
    fn recover_relative_path<R: ArqBinaryReader>(reader: &mut R) -> Result<String> {
        // Try reading as normal string first
        match reader.read_arq_string() {
            Ok(Some(path)) if is_valid_blob_path(&path) => Ok(path),
            Ok(Some(_)) | Ok(None) => {
                // Path is invalid or null, try recovery
                recover_misaligned_path_data(reader)
            }
            Err(_) => Ok(String::new()),
        }
    }

    /// Attempt to recover misaligned path data
    fn recover_misaligned_path_data<R: ArqBinaryReader>(reader: &mut R) -> Result<String> {
        // Read potential path bytes directly
        let mut path_bytes = Vec::new();
        let mut found_slash = false;

        for _ in 0..256 {
            // Reasonable path length limit
            match ReadBytesExt::read_u8(reader) {
                Ok(0) => break, // Null terminator
                Ok(b'/') if !found_slash => {
                    path_bytes.push(b'/');
                    found_slash = true;
                }
                Ok(byte) if found_slash && is_valid_path_byte(byte) => {
                    path_bytes.push(byte);
                }
                Ok(byte) if !found_slash && byte.is_ascii_alphabetic() => {
                    path_bytes.push(byte);
                    // Check if this looks like a backup path component
                    if path_bytes.len() >= 4 {
                        let partial = String::from_utf8_lossy(&path_bytes);
                        if partial.contains("pack") || partial.contains("blob") {
                            found_slash = true;
                        }
                    }
                }
                _ => break,
            }
        }

        if found_slash && !path_bytes.is_empty() {
            let recovered_path = String::from_utf8_lossy(&path_bytes).into_owned();
            if is_valid_blob_path(&recovered_path) {
                Ok(recovered_path)
            } else {
                Ok(String::new())
            }
        } else {
            Ok(String::new())
        }
    }

    /// Check if a byte is valid for path content
    fn is_valid_path_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric()
            || byte == b'/'
            || byte == b'.'
            || byte == b'-'
            || byte == b'_'
            || byte == b' '
    }

    /// Validate BlobLoc data for reasonableness
    fn validate_blob_loc_data(blob_loc: &crate::arq7::BlobLoc) -> bool {
        // Basic validation
        if blob_loc.blob_identifier.is_empty() {
            return false;
        }

        // Check for abnormal offset/length values
        if blob_loc.offset > 1_000_000_000_000 || blob_loc.length > 1_000_000_000_000 {
            return false;
        }

        // Validate path if present
        if !blob_loc.relative_path.is_empty() {
            is_valid_blob_path(&blob_loc.relative_path)
        } else {
            true
        }
    }

    /// Validate blob path
    fn is_valid_blob_path(path: &str) -> bool {
        if path.is_empty() || path.len() > 4096 {
            return false;
        }

        // Check for backup-related patterns
        let has_backup_patterns = path.contains("treepacks")
            || path.contains("blobpacks")
            || path.contains("largeblobpacks")
            || path.contains(".pack")
            || path.contains("standardobjects")
            || path.contains("blob");

        // Must start with / or contain backup patterns
        let has_valid_prefix = path.starts_with('/') || has_backup_patterns;

        // Check for valid characters only
        let has_valid_chars = path.chars().all(|c| {
            !c.is_control()
                && (c.is_ascii_alphanumeric()
                    || c == '/'
                    || c == '-'
                    || c == '_'
                    || c == '.'
                    || c == ' '
                    || c == '('
                    || c == ')'
                    || c == ':')
        });

        has_valid_prefix && has_valid_chars
    }
}
