use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::type_utils::ArqRead;

/// BlobKey
///
/// Unified BlobKey structure.
/// Used as an auxiliary data structure for various metadata components.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobKey {
    #[serde(rename = "sha1")]
    pub sha1: String,

    #[serde(rename = "stretchEncryptionKey")]
    pub stretch_encryption_key: bool,

    #[serde(rename = "storageType")]
    pub storage_type: u32,

    #[serde(rename = "archiveSize")]
    pub archive_size: u64,

    #[serde(rename = "compressionType")]
    pub compression_type: u32, // From Arq5TreeBlobKey, will be defaulted in binary reads

    // Fields previously unique to the old BlobKey (binary parsed)
    // No direct JSON rename for archive_id as it wasn't in Arq5TreeBlobKey's JSON context
    #[serde(default)] // If missing in JSON, it will default to String::default() (empty string)
                      // Alternatively, could be Option<String>
    pub archive_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_upload_date: Option<DateTime<Utc>>, // Changed to Option<DateTime<Utc>>
}

impl BlobKey {
    /// Creates a new BlobKey by reading from an ArqRead stream (binary format).
    pub fn new<R: ArqRead>(mut reader: R) -> Result<Option<BlobKey>> {
        // Read fields common to the old BlobKey binary format
        let sha1_val = reader.read_arq_string()?;

        // According to original BlobKey::new, if sha1 is empty, it's considered None.
        // This typically happens when an optional BlobKey is not present in the stream.
        if sha1_val.is_empty() {
            // Before returning Ok(None), we need to consume the rest of the fields
            // that would have been read by the old BlobKey::new if sha1 was not empty,
            // to ensure the reader is in the correct state for subsequent reads.
            // Old BlobKey::new read: is_encryption_key_stretched (bool), storage_type (u32),
            // archive_id (string), archive_size (u64), archive_upload_date (Date).
            // We must consume these even if we return None.

            let _ = reader.read_arq_bool()?; // is_encryption_key_stretched
            let _ = reader.read_arq_u32()?;  // storage_type
            let _ = reader.read_arq_string()?; // archive_id
            let _ = reader.read_arq_u64()?;  // archive_size

            // Consume date presence byte and potentially the date value
            let present_byte = reader.read_bytes(1)?;
            if present_byte[0] == 0x01 {
                let _ = reader.read_arq_u64()?; // milliseconds_since_epoch
            }
            return Ok(None);
        }

        let stretch_encryption_key_val = reader.read_arq_bool()?;
        let storage_type_val = reader.read_arq_u32()?;
        let archive_id_val = reader.read_arq_string()?;
        let archive_size_val = reader.read_arq_u64()?;

        // Read and convert archive_upload_date
        let parsed_archive_upload_date: Option<DateTime<Utc>>;
        let present_byte = reader.read_bytes(1)?;
        if present_byte[0] == 0x01 {
            let milliseconds_since_epoch = reader.read_arq_u64()?;
            // DateTime::from_timestamp_millis expects i64. u64 might be too large.
            // However, typical timestamps should fit. Consider error handling or capping if necessary.
            // For now, direct conversion, assuming valid range.
            if milliseconds_since_epoch == 0 { // Treat 0 milliseconds as None as well
                parsed_archive_upload_date = None;
            } else {
                parsed_archive_upload_date = DateTime::from_timestamp_millis(milliseconds_since_epoch as i64);
                if parsed_archive_upload_date.is_none() {
                    // This case means the timestamp was out of range for DateTime<Utc>
                    // Log or handle as an error. For now, map to None or return error.
                    // Let's return an error for invalid timestamp values.
                    return Err(crate::error::Error::InvalidFormat(format!(
                        "Invalid timestamp for archive_upload_date: {}ms", milliseconds_since_epoch
                    )));
                }
            }
        } else {
            parsed_archive_upload_date = None;
        }

        Ok(Some(BlobKey {
            sha1: sha1_val,
            stretch_encryption_key: stretch_encryption_key_val,
            storage_type: storage_type_val,
            archive_id: archive_id_val,
            archive_size: archive_size_val,
            archive_upload_date: parsed_archive_upload_date,
            compression_type: 0, // Default value for compression_type as it's not in the binary stream here
        }))
    }
}
