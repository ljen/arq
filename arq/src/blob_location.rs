//! Defines the BlobLoc structure and its methods for representing blob locations.

use std::f64::consts::E;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom}; // Removed unused BufRead
use std::path::Path;

use crate::arq7::binary::ArqBinaryReader; // For from_binary_reader
use crate::arq7::EncryptedKeySet; // For encryption/decryption
use crate::error::{Error, Result};
use crate::object_encryption::EncryptedObject; // For decryption logic

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
    /// Parse a BlobLoc from binary data according to Arq 7 format with enhanced error recovery.
    pub fn from_binary_reader<R: ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        // Use unified parsing with automatic format detection and recovery
        match crate::blob_format_detector::unified_parsing::parse_blob_loc_unified(reader) {
            Ok(arq7_blob_loc) => {
                // Convert from arq7::BlobLoc to blob_location::BlobLoc
                Ok(BlobLoc {
                    blob_identifier: arq7_blob_loc.blob_identifier,
                    compression_type: arq7_blob_loc.compression_type,
                    is_packed: arq7_blob_loc.is_packed,
                    length: arq7_blob_loc.length,
                    offset: arq7_blob_loc.offset,
                    relative_path: arq7_blob_loc.relative_path,
                    stretch_encryption_key: arq7_blob_loc.stretch_encryption_key,
                    is_large_pack: arq7_blob_loc.is_large_pack,
                })
            }
            Err(_e) => {
                // Fallback to original parsing if unified parsing fails
                Self::from_binary_reader_fallback(reader)
            }
        }
    }

    /// Fallback parsing method for compatibility
    fn from_binary_reader_fallback<R: ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack_binary = reader.read_arq_bool()?;

        // Simplified path recovery
        let relative_path = match reader.read_arq_string() {
            Ok(Some(path)) if Self::is_valid_path(&path) => path,
            Ok(Some(_)) | Ok(None) => {
                // Try simple recovery
                Self::try_recover_misaligned_path(reader)
                    .unwrap_or(None)
                    .unwrap_or_default()
            }
            Err(_) => String::new(),
        };

        let offset = reader.read_arq_u64().unwrap_or(0);
        let length = reader.read_arq_u64().unwrap_or(0);

        // Validate offset and length
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

        let stretch_encryption_key = reader.read_arq_bool().unwrap_or(true);
        let compression_type = reader.read_arq_u32().unwrap_or(2); // Default to LZ4

        Ok(BlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack_binary),
            relative_path,
            offset: safe_offset,
            length: safe_length,
            stretch_encryption_key,
            compression_type,
        })
    }

    /// Simplified recovery for misaligned relativePath data
    fn try_recover_misaligned_path<R: ArqBinaryReader>(reader: &mut R) -> Result<Option<String>> {
        // Try one recovery attempt
        match reader.read_arq_string() {
            Ok(Some(potential_path)) if Self::is_valid_path(&potential_path) => {
                Ok(Some(potential_path))
            }
            _ => Ok(None),
        }
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
        println!("Reading file \tBlobLoc\t{:?}", file_path);

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
