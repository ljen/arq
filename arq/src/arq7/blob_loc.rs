use super::binary;
use super::encrypted_keyset::EncryptedKeySet;
use crate::error::{Error, Result};
use crate::object_encryption::EncryptedObject;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// BlobLoc describes the location of a blob
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobLoc {
    #[serde(rename = "blobIdentifier")]
    pub blob_identifier: String,
    #[serde(rename = "compressionType")]
    pub compression_type: u32,
    #[serde(rename = "isPacked")]
    pub is_packed: bool,
    pub length: u64,
    pub offset: u64,
    #[serde(rename = "relativePath")]
    pub relative_path: String,
    #[serde(rename = "stretchEncryptionKey")]
    pub stretch_encryption_key: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)] // `default` makes it optional for deserialization
    #[serde(rename = "isLargePack")]
    pub is_large_pack: Option<bool>,
}

impl BlobLoc {
    /// Parse a BlobLoc from binary data according to Arq 7 format with enhanced error recovery.
    pub fn from_binary_reader<R: binary::ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack_binary = reader.read_arq_bool()?; // Read as bool from binary

        // Adapt relative_path reading from BlobLoc's special handling
        let relative_path = match reader.read_arq_string() {
            Ok(Some(path)) => path,
            Ok(None) => {
                // TODO
                // This part is a bit heuristic, trying to recover if path was marked null
                // but data looks like a path. For simplicity in unified struct,
                // we might simplify this or ensure reader is correctly positioned.
                // For now, let's assume if it's None, it's genuinely None or an empty string.
                // The original BinaryBlobLoc had more complex recovery.
                // Let's stick to what `read_arq_string` provides directly for now.
                // If it returns None, we'll use an empty string.
                String::new()
            }
            Err(_) => {
                // If parsing fails completely (e.g. IO error or bad format after flag)
                // return an empty string or propagate error. For now, empty string.
                String::new()
            }
        };

        let offset = reader.read_arq_u64()?;
        let length = reader.read_arq_u64()?;
        let stretch_encryption_key = reader.read_arq_bool()?;
        let compression_type = reader.read_arq_u32()?;

        Ok(BlobLoc {
            blob_identifier,
            is_packed,
            is_large_pack: Some(is_large_pack_binary), // Map the binary bool to Some(bool)
            relative_path,
            offset,
            length,
            stretch_encryption_key,
            compression_type,
        })
    }

    /// Fallback parsing method for compatibility
    #[allow(dead_code)]
    fn from_binary_reader_fallback<R: binary::ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        let blob_identifier = reader.read_arq_string_required()?;
        let is_packed = reader.read_arq_bool()?;
        let is_large_pack_binary = reader.read_arq_bool()?;

        // Simplified path recovery
        let relative_path = match reader.read_arq_string() {
            Ok(Some(path)) if Self::is_valid_path(&path) => path,
            Ok(Some(_)) | Ok(None) => {
                // Try simple recovery
                Self::try_simple_path_recovery(reader)
                    .unwrap_or(None)
                    .unwrap_or_default()
            }
            Err(_) => String::new(),
        };

        let offset = reader.read_arq_u64().unwrap_or(0);
        let length = reader.read_arq_u64().unwrap_or(0);

        // Validate offset and length to prevent abnormal values
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

    /// Simple path recovery without consuming too much data
    fn try_simple_path_recovery<R: binary::ArqBinaryReader>(
        reader: &mut R,
    ) -> Result<Option<String>> {
        // Try one recovery attempt - read a string and validate it
        match reader.read_arq_string() {
            Ok(Some(potential_path)) if Self::is_valid_path(&potential_path) => {
                Ok(Some(potential_path))
            }
            _ => Ok(None),
        }
    }

    /// Validate if a string looks like a reasonable file path
    fn is_valid_path(path: &str) -> bool {
        // Basic validation for path-like strings
        if path.is_empty() || path.len() > 4096 {
            return false;
        }

        // Check for typical backup path patterns
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

        // Should contain mostly printable ASCII characters
        // Allow common path characters and avoid control characters
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
                    || c == ':'
                    || c == '\\')
        });

        has_valid_chars
    }

    // from_binary_reader was already added in the previous step.
    // Methods from the old BlobLoc have been moved here.
    // The `from_binary_blob_loc` method, previously on BlobLoc, is now obsolete
    // and has been removed as its logic is incorporated into Node::from_binary_node.

    /// Normalize relative path to handle absolute paths that should be treated as relative
    fn normalize_relative_path(&self, backup_set_dir: &Path) -> std::path::PathBuf {
        // Handle different relative path formats:
        // 1. JSON format: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/treepacks/..."
        // 2. Binary format paths: "/FD5575D9-B7E1-43D9-B29C-B54ACC9BC2A9/blobpacks/..."
        let path_parts: Vec<&str> = self.relative_path.split('/').collect();
        let path_without_uuid = if path_parts.len() > 2 && !path_parts[1].is_empty() {
            // Skip the UUID part (first non-empty component)
            path_parts[2..].join("/")
        } else {
            // Fallback to removing just the leading slash
            self.relative_path.trim_start_matches('/').to_string()
        };
        backup_set_dir.join(&path_without_uuid)
    }

    /// Load data from this blob location, with optional encryption support
    pub fn load_data<P: AsRef<Path>>(
        &self,
        backup_set_dir: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let backup_set_dir = backup_set_dir.as_ref();

        if self.is_packed {
            self.load_from_pack_file_with_encryption(backup_set_dir, keyset)
        } else {
            // Load from standalone file
            let file_path = self.normalize_relative_path(backup_set_dir);
            self.load_standalone_file_with_encryption(&file_path, keyset)
        }
    }

    /// Load the actual blob data from a pack file or standalone object (legacy method)
    pub fn load_data_legacy(&self, backup_set_path: &std::path::Path) -> Result<Vec<u8>> {
        self.load_data(backup_set_path, None)
    }

    /// Load data from standalone file with encryption support
    fn load_standalone_file_with_encryption(
        &self,
        file_path: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let file = File::open(file_path)?;
        let mut reader = BufReader::new(file);

        let data = if let Some(keyset) = keyset {
            // Check if this is an encrypted file
            let mut header = [0u8; 4];
            reader.read_exact(&mut header)?;

            // "ARQO" - encrypted
            if header == [65, 82, 81, 79] {
                // Seek back and decrypt
                reader.seek(SeekFrom::Start(0))?;
                let encrypted_obj = EncryptedObject::new(&mut reader)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                encrypted_obj.decrypt(&keyset.encryption_key[..32])?
            } else {
                // Not encrypted, read normally
                reader.seek(SeekFrom::Start(0))?;
                let mut data = Vec::new();
                reader.read_to_end(&mut data)?;
                data
            }
        } else {
            // No encryption support
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            data
        };

        // Decompress if needed
        match self.compression_type {
            0 => Ok(data), // No compression
            1 => {
                // Gzip compression (legacy)
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 compression
                if data.len() < 4 {
                    return Err(Error::InvalidFormat("LZ4 data too short".to_string()));
                }
                let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let compressed_data = &data[4..];
                Ok(lz4_flex::block::decompress(compressed_data, length)?)
            }
            _ => Err(Error::InvalidFormat(format!(
                "Unsupported compression type: {}",
                self.compression_type
            ))),
        }
    }

    /// Load data from pack file with encryption support
    fn load_from_pack_file_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        let pack_file_path = self.normalize_relative_path(backup_set_dir);

        let mut file = File::open(&pack_file_path)?;

        // Seek to the blob's offset
        file.seek(SeekFrom::Start(self.offset))?;

        // Read the blob data
        let mut blob_data = vec![0u8; self.length as usize];
        file.read_exact(&mut blob_data)?;

        // Handle encryption if present
        let data = if let Some(keyset) = keyset {
            // Check if this blob is encrypted  "ARQO"
            if blob_data.len() >= 4 && &blob_data[0..4] == [65, 82, 81, 79] {
                // This blob is encrypted
                let mut cursor = std::io::Cursor::new(&blob_data);
                let encrypted_obj = EncryptedObject::new(&mut cursor)?;
                encrypted_obj.validate(&keyset.hmac_key)?;
                encrypted_obj.decrypt(&keyset.encryption_key[..32])?
            } else {
                // Not encrypted
                blob_data
            }
        } else {
            blob_data
        };

        // Decompress if needed
        match self.compression_type {
            0 => Ok(data), // No compression
            1 => {
                // Gzip compression (legacy)
                use std::io::Read;
                let mut decoder = flate2::read::GzDecoder::new(&data[..]);
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed)?;
                Ok(decompressed)
            }
            2 => {
                // LZ4 compression
                if data.len() < 4 {
                    return Err(Error::InvalidFormat("LZ4 data too short".to_string()));
                }
                let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                let compressed_data = &data[4..];
                Ok(lz4_flex::block::decompress(compressed_data, length)?)
            }
            _ => Err(Error::InvalidFormat(format!(
                "Unsupported compression type: {}",
                self.compression_type
            ))),
        }
    }

    /// Load and parse a tree from this blob location
    pub fn load_tree(&self, backup_set_path: &std::path::Path) -> Result<crate::tree::Tree> {
        // Changed to crate::tree::Tree
        match self.load_tree_with_encryption(backup_set_path, None)? {
            Some(tree) => Ok(tree),
            None => Err(Error::InvalidFormat("No tree data found".to_string())),
        }
    }

    /// Load and parse as binary tree with encryption support
    pub fn load_tree_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::tree::Tree>> {
        let tree_data = self.load_data(backup_set_dir, keyset)?;
        if tree_data.is_empty() {
            return Ok(None);
        }

        // Use the unified Tree's method for parsing Arq7 binary data
        let tree = crate::tree::Tree::from_arq7_binary_data(&tree_data)?;
        Ok(Some(tree))
    }

    /// Load and parse a node from this blob location
    pub fn load_node(
        &self,
        backup_set_path: &std::path::Path,
    ) -> Result<Option<crate::node::Node>> {
        // Changed to crate::node::Node
        // Changed return type to unified Node
        self.load_node_with_encryption(backup_set_path, None)
    }

    /// Load and parse as binary node with encryption support
    pub fn load_node_with_encryption(
        &self,
        backup_set_dir: &Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Option<crate::node::Node>> {
        // Changed to crate::node::Node
        // Changed return type to unified Node
        let data = self.load_data(backup_set_dir, keyset)?;

        if data.is_empty() {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&data);
        // Call the new from_binary_reader on the unified Node struct
        // Pass None for tree_version as BlobLoc itself doesn't know the tree version.
        // The from_binary_reader_arq7 method in crate::node::Node handles Option<u32> for tree_version.
        let node = crate::node::Node::from_binary_reader_arq7(&mut cursor, None)?;
        Ok(Some(node))
    }

    /// Extract the actual file content from this blob location
    pub fn extract_content(
        &self,
        backup_set_path: &std::path::Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<Vec<u8>> {
        self.load_data(backup_set_path, keyset)
    }

    /// Extract file content as a UTF-8 string (for text files)
    pub fn extract_text_content(
        &self,
        backup_set_path: &std::path::Path,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<String> {
        let content = self.extract_content(backup_set_path, keyset)?;
        Ok(String::from_utf8_lossy(&content).to_string())
    }

    /// Save extracted content to a file
    pub fn extract_to_file<P: AsRef<std::path::Path>>(
        &self,
        backup_set_path: &std::path::Path,
        output_path: P,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<()> {
        let content = self.extract_content(backup_set_path, keyset)?;
        std::fs::write(output_path, content)?;
        Ok(())
    }

    /// Extract content to file with encryption support
    pub fn extract_to_file_with_encryption<P1: AsRef<Path>, P2: AsRef<Path>>(
        &self,
        backup_set_dir: P1,
        output_path: P2,
        keyset: Option<&EncryptedKeySet>,
    ) -> Result<()> {
        let data = self.load_data(backup_set_dir.as_ref(), keyset)?;
        std::fs::write(output_path, data)?;
        Ok(())
    }
}
