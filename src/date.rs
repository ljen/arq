use chrono::prelude::DateTime; // Keep DateTime, remove NaiveDateTime and Utc

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
        let seconds = (self.milliseconds_since_epoch / 1000) as i64;
        let nanoseconds = ((self.milliseconds_since_epoch % 1000) as u32) * 1_000_000;

        // DateTime::from_timestamp directly creates a DateTime<Utc>
        // It returns an Option, so unwrap() is consistent with previous from_timestamp_opt().unwrap()
        // To make this compile without importing Utc, we rely on from_timestamp creating DateTime<Utc> by default.
        // If it doesn't, this might need adjustment or Utc import.
        // Chrono 0.4.x: `DateTime::from_timestamp` returns `Option<DateTime<Utc>>`. This is fine.
        let datetime_utc = DateTime::from_timestamp(seconds, nanoseconds)
            .expect("Failed to create DateTime from timestamp, should be valid from u64 milliseconds");
        write!(f, "{}", datetime_utc)
    }
}
