use chrono::{DateTime, Utc};

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
    pub fn new<R: ArqRead>(reader: &mut R) -> Result<Option<BlobKey>> {
        // Changed to &mut R
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
            let _ = reader.read_arq_u32()?; // storage_type
            let _ = reader.read_arq_string()?; // archive_id
            let _ = reader.read_arq_u64()?; // archive_size

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
            if milliseconds_since_epoch == 0 {
                // Treat 0 milliseconds as None as well
                parsed_archive_upload_date = None;
            } else {
                parsed_archive_upload_date =
                    DateTime::from_timestamp_millis(milliseconds_since_epoch as i64);
                if parsed_archive_upload_date.is_none() {
                    // This case means the timestamp was out of range for DateTime<Utc>
                    // Log or handle as an error. For now, map to None or return error.
                    // Let's return an error for invalid timestamp values.
                    return Err(crate::error::Error::InvalidFormat(format!(
                        "Invalid timestamp for archive_upload_date: {}ms",
                        milliseconds_since_epoch
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use byteorder::{NetworkEndian, WriteBytesExt};

    fn write_arq_string(buf: &mut Vec<u8>, s: &str) {
        if s.is_empty() {
            buf.push(0x00);
        } else {
            buf.push(0x01);
            buf.write_u64::<NetworkEndian>(s.len() as u64).unwrap();
            buf.extend_from_slice(s.as_bytes());
        }
    }

    fn create_dummy_blobkey_bytes(sha1: &str, time_ms: u64, include_date: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        // sha1 string
        write_arq_string(&mut buf, sha1);

        if !sha1.is_empty() {
            // stretch_encryption_key
            buf.push(0x00); // false

            // storage_type
            buf.write_u32::<NetworkEndian>(0).unwrap();

            // archive_id (empty string)
            write_arq_string(&mut buf, "");

            // archive_size
            buf.write_u64::<NetworkEndian>(0).unwrap();

            // archive_upload_date
            if include_date {
                buf.push(0x01);
                buf.write_u64::<NetworkEndian>(time_ms).unwrap();
            } else {
                buf.push(0x00);
            }
        } else {
            // If sha1 is empty, the original logic reads the rest of fields to consume
            // We need to write them so the reader doesn't hit EOF prematurely
            buf.push(0x00); // stretch_encryption_key
            buf.write_u32::<NetworkEndian>(0).unwrap(); // storage_type
            write_arq_string(&mut buf, ""); // archive_id
            buf.write_u64::<NetworkEndian>(0).unwrap(); // archive_size
            if include_date {
                buf.push(0x01);
                buf.write_u64::<NetworkEndian>(time_ms).unwrap();
            } else {
                buf.push(0x00);
            }
        }

        buf
    }

    #[test]
    fn test_blob_key_new_invalid_date() {
        // use a timestamp that evaluates to far in the future
        let invalid_timestamp = i64::MAX as u64; // > year 9999
        let bytes = create_dummy_blobkey_bytes("some-sha1", invalid_timestamp, true);
        let mut cursor = Cursor::new(bytes);

        let result = BlobKey::new(&mut cursor);

        assert!(result.is_err());
        match result {
            Err(crate::error::Error::InvalidFormat(msg)) => {
                assert!(msg.contains("Invalid timestamp for archive_upload_date"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_blob_key_new_valid() {
        let valid_timestamp = 1672531200000_u64; // 2023-01-01 00:00:00 UTC
        let bytes = create_dummy_blobkey_bytes("valid-sha1", valid_timestamp, true);
        let mut cursor = Cursor::new(bytes);

        let result = BlobKey::new(&mut cursor).unwrap();
        assert!(result.is_some());

        let key = result.unwrap();
        assert_eq!(key.sha1, "valid-sha1");
        assert!(key.archive_upload_date.is_some());
        assert_eq!(key.archive_upload_date.unwrap().timestamp_millis(), valid_timestamp as i64);
    }

    #[test]
    fn test_blob_key_new_empty_sha1() {
        let bytes = create_dummy_blobkey_bytes("", 0, false);
        let mut cursor = Cursor::new(bytes);

        let result = BlobKey::new(&mut cursor).unwrap();
        assert!(result.is_none());

        // Ensure reader consumed all expected bytes
        assert_eq!(cursor.position(), cursor.into_inner().len() as u64);
    }
}
