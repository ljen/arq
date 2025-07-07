//! Binary format parsing utilities for Arq 7
//!
//! This module implements the binary data format parsers as specified in the
//! Arq 7 documentation for Nodes, Trees, and other binary structures.

use crate::error::Result;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;

/// ArqBinaryReader provides methods for reading Arq's binary format primitives
pub trait ArqBinaryReader: Read {
    /// Read a boolean value (1 byte: 00 or 01)
    fn read_arq_bool(&mut self) -> Result<bool> {
        let byte = self.read_u8()?;
        match byte {
            0x00 => Ok(false),
            0x01 => Ok(true),
            _ => Err(crate::error::Error::ParseError),
        }
    }

    /// Read a 32-bit unsigned integer (network byte order)
    fn read_arq_u32(&mut self) -> Result<u32> {
        Ok(self.read_u32::<BigEndian>()?)
    }

    /// Read a 64-bit unsigned integer (network byte order)
    fn read_arq_u64(&mut self) -> Result<u64> {
        Ok(self.read_u64::<BigEndian>()?)
    }

    /// Read a 32-bit signed integer (network byte order)
    fn read_arq_i32(&mut self) -> Result<i32> {
        Ok(self.read_i32::<BigEndian>()?)
    }

    /// Read a 64-bit signed integer (network byte order)
    fn read_arq_i64(&mut self) -> Result<i64> {
        Ok(self.read_i64::<BigEndian>()?)
    }

    /// Read an Arq string with bounds checking
    /// Format: 1 byte (isNotNull flag) + if not null: 8-byte length + UTF-8 data
    fn read_arq_string(&mut self) -> Result<Option<String>> {
        let is_not_null = self.read_u8()? != 0;
        if !is_not_null {
            return Ok(None);
        }

        let length = self.read_arq_u64()?;

        // Prevent excessive memory allocation - limit string length to 1MB
        if length > 1048576 {
            return Err(crate::error::Error::ParseError);
        }

        if length == 0 {
            return Ok(Some(String::new()));
        }

        let mut buffer = vec![0u8; length as usize];
        self.read_exact(&mut buffer)?;

        // Handle null termination in binary strings
        let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        let string = String::from_utf8(buffer[..end].to_vec())?;
        Ok(Some(string))
    }

    /// Read a required Arq string (returns error if null)
    fn read_arq_string_required(&mut self) -> Result<String> {
        self.read_arq_string()?
            .ok_or(crate::error::Error::ParseError)
    }

    /// Read an Arq Date
    /// Format: 1 byte (isNotNull flag) + if not null: 8-byte milliseconds since epoch
    fn read_arq_date(&mut self) -> Result<Option<i64>> {
        let is_not_null = self.read_u8()? != 0;
        if !is_not_null {
            return Ok(None);
        }
        let millis = self.read_arq_i64()?;
        Ok(Some(millis))
    }

    /// Read Arq Data with bounds checking
    /// Format: 8-byte length + that number of bytes
    fn read_arq_data(&mut self) -> Result<Vec<u8>> {
        let length = self.read_arq_u64()?;

        // Prevent excessive memory allocation - limit data length to 10MB
        if length > 10_485_760 {
            return Err(crate::error::Error::ParseError);
        }

        if length == 0 {
            return Ok(Vec::new());
        }

        let mut buffer = vec![0u8; length as usize];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

// Implement ArqBinaryReader for any type that implements Read
impl<R: Read> ArqBinaryReader for R {}

// The BinaryTree struct and its impl block have been removed.
// Its functionality is now part of crate::tree::Tree::from_arq7_binary_data.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_arq_bool() {
        let data = [0x00, 0x01];
        let mut cursor = Cursor::new(&data);

        assert_eq!(cursor.read_arq_bool().unwrap(), false);
        assert_eq!(cursor.read_arq_bool().unwrap(), true);
    }

    #[test]
    fn test_read_arq_bool_invalid() {
        let data = [0x02];
        let mut cursor = Cursor::new(&data);

        assert!(cursor.read_arq_bool().is_err());
    }

    #[test]
    fn test_read_arq_string() {
        // Create test data: isNotNull=true, length=5, "hello"
        let data = [
            0x01, // isNotNull = true
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // length = 5
            b'h', b'e', b'l', b'l', b'o', // "hello"
        ];
        let mut cursor = Cursor::new(&data);

        let result = cursor.read_arq_string().unwrap();
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn test_read_arq_string_null() {
        let data = [0x00]; // isNotNull = false
        let mut cursor = Cursor::new(&data);

        let result = cursor.read_arq_string().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_read_arq_integers() {
        let data = [
            0x00, 0x00, 0x00, 0x01, // u32 = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // u64 = 2
            0xFF, 0xFF, 0xFF, 0xFF, // i32 = -1
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // i64 = -1
        ];
        let mut cursor = Cursor::new(&data);

        assert_eq!(cursor.read_arq_u32().unwrap(), 1);
        assert_eq!(cursor.read_arq_u64().unwrap(), 2);
        assert_eq!(cursor.read_arq_i32().unwrap(), -1);
        assert_eq!(cursor.read_arq_i64().unwrap(), -1);
    }

    #[test]
    fn test_read_arq_data() {
        let data = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // length = 3
            b'f', b'o', b'o', // "foo"
        ];
        let mut cursor = Cursor::new(&data);

        let result = cursor.read_arq_data().unwrap();
        assert_eq!(result, b"foo");
    }

    #[test]
    fn test_read_arq_date() {
        let data = [
            0x01, // isNotNull = true
            0x00, 0x00, 0x01, 0x7F, 0x4F, 0x8B, 0x5A, 0x00, // milliseconds
        ];
        let mut cursor = Cursor::new(&data);

        let result = cursor.read_arq_date().unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_read_arq_date_null() {
        let data = [0x00]; // isNotNull = false
        let mut cursor = Cursor::new(&data);

        let result = cursor.read_arq_date().unwrap();
        assert_eq!(result, None);
    }
}
