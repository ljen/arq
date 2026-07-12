//! Defines the BlobLoc structure and its methods for representing blob locations.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom}; // Removed unused BufRead
use std::path::Path;

use crate::arq7::binary::ArqBinaryReader; // For from_binary_reader
use crate::arq7::EncryptedKeySet; // For encryption/decryption
use crate::error::{Error, Result};
use crate::object_encryption::EncryptedObject; // For decryption logic

const MAX_BLOB_SIZE: u64 = 4 * 1024 * 1024 * 1024; // 4 GB

/// BlobLoc describes the location of a blob
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct BlobLoc {
    #[serde(rename = "blobIdentifier")]
    pub blob_identifier: String,
    #[serde(rename = "compressionType")]
    pub compression_type: u32, // 0 = None, 1 = Gzip (legacy), 2 = LZ4
    #[serde(rename = "isPacked")]
    pub is_packed: bool,
    pub length: u64, // Length of the (potentially compressed and/or encrypted) blob data
    pub offset: u64, // Offset within the pack file if is_packed is true
    #[serde(rename = "relativePath")]
    pub relative_path: String, // Path to the pack file or standalone blob, relative to backup set root + UUID
    #[serde(rename = "stretchEncryptionKey")]
    pub stretch_encryption_key: bool, // Usually true for Arq7 encrypted blobs
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(rename = "isLargePack")]
    pub is_large_pack: Option<bool>, // Specific to Arq7 large pack handling
}

impl BlobLoc {
    /// Parse a BlobLoc from binary data according to the documented Arq 7 format.
    pub fn from_binary_reader<R: ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let loc = Self::read_binary_fields(reader, None)?;

        Ok(BlobLoc {
            blob_identifier,
            is_packed,
            ..loc
        })
    }

    /// Parse a BlobLoc with fallback for observed Arq 7 data that includes an extra isLargePack flag.
    pub(crate) fn from_binary_reader_with_recovery<R: ArqBinaryReader + Seek>(
        reader: &mut R,
    ) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let layout_start = reader.stream_position()?;

        let official = match Self::read_binary_fields(reader, None) {
            Ok(loc) => Some((loc, reader.stream_position()?)),
            Err(_) => None,
        };

        if let Some((loc, _)) = &official {
            if loc.has_valid_binary_fields() {
                return Ok(BlobLoc {
                    blob_identifier,
                    is_packed,
                    ..loc.clone()
                });
            }
        }

        reader.seek(SeekFrom::Start(layout_start))?;
        let fallback_error = match reader.read_arq_bool() {
            Ok(is_large_pack) => match Self::read_binary_fields(reader, Some(is_large_pack)) {
                Ok(loc) if loc.has_valid_binary_fields() => {
                    return Ok(BlobLoc {
                        blob_identifier,
                        is_packed,
                        ..loc
                    });
                }
                Ok(loc) if official.is_none() => {
                    return Ok(BlobLoc {
                        blob_identifier,
                        is_packed,
                        ..loc
                    });
                }
                Ok(_) => None,
                Err(e) => Some(e),
            },
            Err(e) => Some(e),
        };

        if let Some((loc, end)) = official {
            reader.seek(SeekFrom::Start(end))?;
            return Ok(BlobLoc {
                blob_identifier,
                is_packed,
                ..loc
            });
        }

        Err(fallback_error.unwrap_or(Error::ParseError))
    }

    fn read_binary_fields<R: ArqBinaryReader>(
        reader: &mut R,
        is_large_pack: Option<bool>,
    ) -> Result<Self> {
        let relative_path = reader.read_arq_string()?.unwrap_or_default();
        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;
        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;

        Ok(BlobLoc {
            blob_identifier: String::new(),
            is_packed: false,
            is_large_pack,
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
        })
    }

    fn has_valid_binary_fields(&self) -> bool {
        self.compression_type <= 2
            && self.length <= MAX_BLOB_SIZE
            && (self.relative_path.is_empty() || Self::is_valid_path(&self.relative_path))
    }

    /// Validate if a string looks like a reasonable file path
    pub fn is_valid_path(path: &str) -> bool {
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

        // Should start with / for absolute paths or contain backup patterns
        if !path.starts_with('/') && !has_backup_patterns {
            return false;
        }

        // Should contain valid characters and no control characters
        path.chars().all(|c| {
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
        })
    }

    /// Normalize relative path to handle absolute paths that should be treated as relative
    /// to the backup set directory.
    fn normalize_relative_path(&self, backup_set_dir: &Path) -> std::path::PathBuf {
        let path_str = &self.relative_path;
        // If path starts with backup_set_dir's UUID, remove it
        if let Some(first_component) = backup_set_dir.file_name().and_then(|n| n.to_str()) {
            if path_str.starts_with(&format!("/{}", first_component)) {
                // println!("starting with backup id");
                let stripped_path = path_str.trim_start_matches('/');
                let components: Vec<&str> = stripped_path.splitn(2, '/').collect();
                if components.len() > 1 {
                    return backup_set_dir.join(components[1]);
                }
            }
        }
        // Fallback: assume path is relative after the initial UUID component if present
        let parts: Vec<&str> = path_str.splitn(3, '/').collect();
        if parts.len() == 3 && parts[0].is_empty() && !parts[1].is_empty() {
            // e.g. "/<UUID>/actual/path"
            backup_set_dir.join(parts[2])
        } else if parts.len() == 2 && parts[0].is_empty() {
            // e.g. "/actual/path" (no UUID prefix)
            backup_set_dir.join(parts[1])
        } else {
            // Default to joining directly if no clear UUID prefix pattern
            backup_set_dir.join(path_str.trim_start_matches('/'))
        }
    }

    /// Load data from this blob location, with optional encryption support
    pub fn load_data<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let backup_set_dir_ref = backup_set_dir.as_ref();
        let file_path = self.normalize_relative_path(backup_set_dir_ref);

        if self.is_packed {
            self.load_from_pack_file_with_encryption(&file_path, keyset)
        } else {
            self.load_standalone_file_with_encryption(&file_path, keyset)
        }
    }

    /// Load data from standalone file with encryption support
    fn load_standalone_file_with_encryption(
        &self,
        file_path: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let file = File::open(file_path).map_err(Error::IoError)?;
        let mut reader = BufReader::new(file);

        let mut raw_data = Vec::new();
        reader.read_to_end(&mut raw_data).map_err(Error::IoError)?;

        let decrypted_data = if let Some(ks) = keyset {
            if raw_data.len() >= 4 && &raw_data[0..4] == b"ARQO" {
                let mut cursor = std::io::Cursor::new(&raw_data);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&ks.hmac_key)?;
                encrypted_obj.decrypt(&ks.encryption_key)? // Assuming full key if stretch not specified
            } else {
                raw_data
            }
        } else {
            raw_data
        };

        self.decompress_data(decrypted_data)
    }

    /// Load data from pack file with encryption support
    pub fn load_from_pack_file_with_encryption(
        &self,
        pack_file_path: &Path, // This path should already be correctly joined by normalize_relative_path
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let mut file = File::open(pack_file_path).map_err(Error::IoError)?;
        file.seek(SeekFrom::Start(self.offset))
            .map_err(Error::IoError)?;

        if self.length > MAX_BLOB_SIZE {
            return Err(Error::InvalidFormat(format!(
                "Blob length {} exceeds maximum allowed size",
                self.length
            )));
        }
        let mut blob_data_in_pack = vec![0u8; self.length as usize];
        file.read_exact(&mut blob_data_in_pack)
            .map_err(Error::IoError)?;

        let decrypted_data = if let Some(ks) = keyset {
            // Arq7 encrypted blobs within packs also start with ARQO header
            if blob_data_in_pack.len() >= 4 && &blob_data_in_pack[0..4] == b"ARQO" {
                let mut cursor = std::io::Cursor::new(&blob_data_in_pack);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&ks.hmac_key)?;
                encrypted_obj.decrypt(&ks.encryption_key)?
            } else {
                blob_data_in_pack
            }
        } else {
            blob_data_in_pack
        };

        self.decompress_data(decrypted_data)
    }

    fn decompress_data(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        match self.compression_type {
            0 => Ok(data), // No compression
            1 => {
                // Gzip compression (legacy)
                use flate2::read::GzDecoder;
                let mut decoder = GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder
                    .read_to_end(&mut decompressed)
                    .map_err(Error::IoError)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 compression
                if data.len() < 4 && !data.is_empty() {
                    // Allow empty data to pass through if original was empty
                    return Err(Error::InvalidFormat(
                        "LZ4 data too short for length prefix".to_string(),
                    ));
                }
                if data.is_empty() {
                    return Ok(data);
                } // Empty data is valid

                let length_prefix = &data[0..4];
                let actual_decompressed_length =
                    u32::from_be_bytes(length_prefix.try_into().unwrap()) as usize;
                let compressed_data_body = &data[4..];

                Ok(lz4_flex::block::decompress(
                    compressed_data_body,
                    actual_decompressed_length,
                )?)
            }
            _ => Err(Error::InvalidFormat(format!(
                "Unsupported compression type: {}",
                self.compression_type
            ))),
        }
    }

    /// Load and parse as binary tree with encryption support
    pub fn load_tree_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::tree::Tree>> {
        let data = self.load_data(backup_set_dir, keyset)?;
        if data.is_empty() {
            return Ok(None);
        }
        crate::tree::Tree::from_arq7_binary_data(&data).map(Some)
    }

    /// Load and parse as binary node with encryption support
    pub fn load_node_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::node::Node>> {
        let data = self.load_data(backup_set_dir, keyset)?;
        if data.is_empty() {
            return Ok(None);
        }
        let mut cursor = std::io::Cursor::new(&data);
        crate::node::Node::from_binary_reader_arq7(&mut cursor, None).map(Some)
    }

    /// Extract the actual file content from this blob location
    pub fn extract_content(
        &self,
        backup_set_path: &Path, // Should be backup_set_dir
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        self.load_data(backup_set_path, keyset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    struct NonSeekReader {
        inner: Cursor<Vec<u8>>,
    }

    impl Read for NonSeekReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }

    fn arq_string(value: &str) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
        bytes
    }

    #[test]
    fn parses_official_arq7_binary_blobloc_without_large_pack_flag() {
        let mut data = Vec::new();
        data.extend(arq_string("abc123"));
        data.push(1);
        data.extend(arq_string("/PLAN/blobpacks/AA/example.pack"));
        data.extend_from_slice(&12u64.to_be_bytes());
        data.extend_from_slice(&34u64.to_be_bytes());
        data.push(1);
        data.extend_from_slice(&2u32.to_be_bytes());

        let mut cursor = Cursor::new(data);
        let loc = BlobLoc::from_binary_reader(&mut cursor).unwrap();

        assert_eq!(loc.blob_identifier, "abc123");
        assert!(loc.is_packed);
        assert_eq!(loc.is_large_pack, None);
        assert_eq!(loc.relative_path, "/PLAN/blobpacks/AA/example.pack");
        assert_eq!(loc.offset, 12);
        assert_eq!(loc.length, 34);
        assert!(loc.stretch_encryption_key);
        assert_eq!(loc.compression_type, 2);
    }

    #[test]
    fn test_is_valid_path() {
        // Valid paths
        assert!(BlobLoc::is_valid_path("/path/to/backup"));
        assert!(BlobLoc::is_valid_path("/path/to/backup.pack"));
        assert!(BlobLoc::is_valid_path("/backup-123_456.pack"));
        assert!(BlobLoc::is_valid_path("/a:b(c) d")); // valid chars: ':', '(', ')', ' '
        assert!(BlobLoc::is_valid_path("treepacks/something"));
        assert!(BlobLoc::is_valid_path("blobpacks/something"));
        assert!(BlobLoc::is_valid_path("largeblobpacks/something"));
        assert!(BlobLoc::is_valid_path("standardobjects/something"));
        assert!(BlobLoc::is_valid_path("blob/something"));
        assert!(BlobLoc::is_valid_path("something.pack"));

        // Invalid paths
        assert!(!BlobLoc::is_valid_path(""));

        let long_path = "a".repeat(4097);
        assert!(!BlobLoc::is_valid_path(&long_path));

        // Missing leading slash and no backup pattern
        assert!(!BlobLoc::is_valid_path("just/a/normal/path"));

        // Invalid characters
        assert!(!BlobLoc::is_valid_path("/invalid/path\n")); // control char
        assert!(!BlobLoc::is_valid_path("/invalid/path*")); // forbidden char '*'
        assert!(!BlobLoc::is_valid_path("/invalid/path?")); // forbidden char '?'
        assert!(!BlobLoc::is_valid_path("/invalid/path<")); // forbidden char '<'
        assert!(!BlobLoc::is_valid_path("/invalid/path>")); // forbidden char '>'
        assert!(!BlobLoc::is_valid_path("/invalid/path|")); // forbidden char '|'
    }

    #[test]
    fn parses_official_arq7_binary_blobloc_from_non_seek_reader() {
        let mut data = Vec::new();
        data.extend(arq_string("abc123"));
        data.push(1);
        data.extend(arq_string("/PLAN/blobpacks/AA/example.pack"));
        data.extend_from_slice(&12u64.to_be_bytes());
        data.extend_from_slice(&34u64.to_be_bytes());
        data.push(1);
        data.extend_from_slice(&2u32.to_be_bytes());

        let mut reader = NonSeekReader {
            inner: Cursor::new(data),
        };
        let loc = BlobLoc::from_binary_reader(&mut reader).unwrap();

        assert_eq!(loc.blob_identifier, "abc123");
        assert_eq!(loc.relative_path, "/PLAN/blobpacks/AA/example.pack");
    }

    fn create_test_blobloc(compression_type: u32) -> BlobLoc {
        BlobLoc {
            blob_identifier: "test".to_string(),
            compression_type,
            is_packed: false,
            length: 0,
            offset: 0,
            relative_path: "".to_string(),
            stretch_encryption_key: false,
            is_large_pack: None,
        }
    }

    #[test]
    fn decompress_data_no_compression() {
        let loc = create_test_blobloc(0);
        let data = b"hello world".to_vec();
        let result = loc.decompress_data(data.clone()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn decompress_data_gzip() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let loc = create_test_blobloc(1);
        let original_data = b"hello world".to_vec();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&original_data).unwrap();
        let compressed_data = encoder.finish().unwrap();

        let result = loc.decompress_data(compressed_data).unwrap();
        assert_eq!(result, original_data);
    }

    #[test]
    fn decompress_data_lz4() {
        let loc = create_test_blobloc(2);
        let original_data = b"hello world".to_vec();

        let compressed_body = lz4_flex::block::compress(&original_data);
        let mut compressed_data = Vec::new();
        let uncompressed_len = original_data.len() as u32;
        compressed_data.extend_from_slice(&uncompressed_len.to_be_bytes());
        compressed_data.extend_from_slice(&compressed_body);

        let result = loc.decompress_data(compressed_data).unwrap();
        assert_eq!(result, original_data);
    }

    #[test]
    fn decompress_data_lz4_empty() {
        let loc = create_test_blobloc(2);
        let empty_data = Vec::new();
        let result = loc.decompress_data(empty_data.clone()).unwrap();
        assert_eq!(result, empty_data);
    }

    #[test]
    fn decompress_data_lz4_too_short() {
        let loc = create_test_blobloc(2);
        let short_data = b"123".to_vec();
        let result = loc.decompress_data(short_data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn decompress_data_unsupported_type() {
        let loc = create_test_blobloc(3);
        let data = b"hello world".to_vec();
        let result = loc.decompress_data(data);
        assert!(matches!(result, Err(Error::InvalidFormat(_))));
    }
}
