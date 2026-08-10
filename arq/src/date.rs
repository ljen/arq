use chrono::prelude::DateTime;

use crate::error::Result;
use crate::type_utils::ArqRead;

pub struct Date {
    pub milliseconds_since_epoch: u64,
}

impl Date {
    pub fn new<R: ArqRead>(mut reader: R) -> Result<Date> {
        let present = reader.read_bytes(1)?;
        let milliseconds_since_epoch = if present[0] == 0x01 {
            reader.read_arq_u64()?
        } else {
            0
        };

        Ok(Date {
            milliseconds_since_epoch,
        })
    }
}

impl std::fmt::Display for Date {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match DateTime::from_timestamp_millis(self.milliseconds_since_epoch as i64) {
            Some(datetime) => write!(f, "{}", datetime),
            None => write!(
                f,
                "<invalid timestamp: {}ms>",
                self.milliseconds_since_epoch
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_date_present() {
        // 0x01 indicates present, followed by 8 bytes of big-endian u64
        let mut data = vec![0x01];
        data.extend_from_slice(&1609459200000u64.to_be_bytes()); // 2021-01-01T00:00:00Z in ms
        let cursor = Cursor::new(data);
        let date = Date::new(cursor).unwrap();
        assert_eq!(date.milliseconds_since_epoch, 1609459200000);
    }

    #[test]
    fn test_date_absent() {
        // 0x00 indicates absent
        let data = vec![0x00];
        let cursor = Cursor::new(data);
        let date = Date::new(cursor).unwrap();
        assert_eq!(date.milliseconds_since_epoch, 0);
    }

    #[test]
    fn test_date_error_eof_first_byte() {
        // empty input
        let data: Vec<u8> = vec![];
        let cursor = Cursor::new(data);
        assert!(Date::new(cursor).is_err());
    }

    #[test]
    fn test_date_error_eof_u64() {
        // 0x01 indicates present, but missing the subsequent 8 bytes
        let data = vec![0x01, 0x00, 0x00];
        let cursor = Cursor::new(data);
        assert!(Date::new(cursor).is_err());
    }

    #[test]
    fn test_display_valid_date() {
        let date = Date {
            milliseconds_since_epoch: 1609459200000,
        };
        assert_eq!(date.to_string(), "2021-01-01 00:00:00 UTC");
    }

    #[test]
    fn test_display_invalid_date() {
        // Use a value that would cause from_timestamp_millis to return None.
        // from_timestamp_millis takes i64, so passing something that doesn't fit or is way out of bounds.
        // To trigger None, we need something that exceeds chrono limits, typically beyond year 262143.
        // 10_000_000_000_000_000 (10 quadrillion milliseconds) corresponds to year ~319000.
        let invalid_date = Date {
            milliseconds_since_epoch: 10_000_000_000_000_000,
        };

        let output = invalid_date.to_string();
        assert_eq!(output, "<invalid timestamp: 10000000000000000ms>");
    }
}
