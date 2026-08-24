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
            buf.push(0);
        } else {
            buf.push(1);
            buf.write_u64::<NetworkEndian>(s.len() as u64).unwrap();
            buf.extend_from_slice(s.as_bytes());
        }
    }

    fn write_arq_bool(buf: &mut Vec<u8>, b: bool) {
        buf.push(if b { 1 } else { 0 });
    }

    fn write_arq_u32(buf: &mut Vec<u8>, v: u32) {
        buf.write_u32::<NetworkEndian>(v).unwrap();
    }

    fn write_arq_u64(buf: &mut Vec<u8>, v: u64) {
        buf.write_u64::<NetworkEndian>(v).unwrap();
    }

    #[test]
    fn test_blob_key_new_empty_sha1() {
        let mut buf = Vec::new();
        write_arq_string(&mut buf, ""); // sha1
        write_arq_bool(&mut buf, true); // stretch_encryption_key
        write_arq_u32(&mut buf, 1); // storage_type
        write_arq_string(&mut buf, "archive_123"); // archive_id
        write_arq_u64(&mut buf, 1024); // archive_size
        buf.push(1); // date present
        write_arq_u64(&mut buf, 1234567890); // date ms

        let mut reader = Cursor::new(buf);
        let result = BlobKey::new(&mut reader).unwrap();
        assert!(result.is_none());

        // Ensure all bytes were read
        assert_eq!(reader.position(), reader.into_inner().len() as u64);
    }

    #[test]
    fn test_blob_key_new_invalid_date() {
        let mut buf = Vec::new();
        write_arq_string(&mut buf, "some_sha1");
        write_arq_bool(&mut buf, false);
        write_arq_u32(&mut buf, 2);
        write_arq_string(&mut buf, "archive_456");
        write_arq_u64(&mut buf, 2048);
        buf.push(1); // date present
        // Value that overflows DateTime::from_timestamp_millis when cast to i64
        write_arq_u64(&mut buf, i64::MAX as u64 + 1000000000000000);

        let mut reader = Cursor::new(buf);
        let result = BlobKey::new(&mut reader);

        assert!(matches!(result, Err(crate::error::Error::InvalidFormat(_))));
    }

    #[test]
    fn test_blob_key_new_valid() {
        let mut buf = Vec::new();
        write_arq_string(&mut buf, "some_sha1");
        write_arq_bool(&mut buf, true);
        write_arq_u32(&mut buf, 3);
        write_arq_string(&mut buf, "archive_789");
        write_arq_u64(&mut buf, 4096);
        buf.push(1); // date present
        write_arq_u64(&mut buf, 1000); // 1 second past epoch

        let mut reader = Cursor::new(buf);
        let result = BlobKey::new(&mut reader).unwrap();
        assert!(result.is_some());

        let key = result.unwrap();
        assert_eq!(key.sha1, "some_sha1");
        assert_eq!(key.stretch_encryption_key, true);
        assert_eq!(key.storage_type, 3);
        assert_eq!(key.archive_id, "archive_789");
        assert_eq!(key.archive_size, 4096);
        assert_eq!(key.archive_upload_date.unwrap().timestamp_millis(), 1000);
        assert_eq!(key.compression_type, 0);
    }

    #[test]
    fn test_blob_key_new_zero_date() {
        let mut buf = Vec::new();
        write_arq_string(&mut buf, "some_sha1");
        write_arq_bool(&mut buf, false);
        write_arq_u32(&mut buf, 4);
        write_arq_string(&mut buf, "archive_000");
        write_arq_u64(&mut buf, 8192);
        buf.push(1); // date present
        write_arq_u64(&mut buf, 0); // 0 ms

        let mut reader = Cursor::new(buf);
        let result = BlobKey::new(&mut reader).unwrap();
        assert!(result.is_some());

        let key = result.unwrap();
        assert!(key.archive_upload_date.is_none());
    }
}
