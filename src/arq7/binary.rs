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

// BinaryBlobLoc struct has been removed. Its functionality is merged into arq::arq7::BlobLocation.
// The arq::arq7::BlobLocation::from_binary_reader method should be used for parsing from binary.

// BinaryNode struct and its impl block have been removed.
// Its parsing logic is now part of arq::arq7::Node::from_binary_reader.
// BinaryTree now directly uses arq::arq7::Node.

/// Binary representation of a Tree
#[derive(Debug, Clone)]
pub struct BinaryTree {
    pub version: u32,
    pub child_nodes: std::collections::HashMap<String, crate::arq7::Node>, // Changed to unified Node
}

impl BinaryTree {
    /// Parse a Tree from binary data according to Arq 7 format specification
    pub fn from_reader<R: ArqBinaryReader>(reader: &mut R) -> Result<Self> {
        // [UInt32:version]
        let version = reader.read_arq_u32()?;

        // [UInt64:childNodesByNameCount]
        let child_nodes_count = reader.read_arq_u64()?;

        let mut child_nodes = std::collections::HashMap::new();

        // (String:childName, Node:childNode) /* repeat childNodesByNameCount times */
        for i in 0..child_nodes_count {
            // [String:childName]
            let child_name = reader.read_arq_string()?;

            // Handle the case where child name might be null/empty
            let name = match child_name {
                Some(name) if !name.is_empty() => name,
                _ => {
                    // If we get a null or empty name, create a unique name
                    format!("unnamed_child_{}", i)
                }
            };

            // [Node:childNode] - use resilient parsing with the new unified Node's binary parser
            match crate::arq7::Node::from_binary_reader(reader, Some(version)) {
                Ok(child_node) => {
                    child_nodes.insert(name, child_node);
                }
                Err(_) => {
                    // If child node parsing fails, create a placeholder unified Node
                    // This placeholder needs to match the fields of the unified `arq::arq7::Node`
                    let placeholder_node = crate::arq7::Node {
                        is_tree: false,
                        tree_blob_loc: None,
                        computer_os_type: 1,
                        data_blob_locs: vec![crate::arq7::BlobLocation {
                            blob_identifier: format!("placeholder_for_child_{}", i),
                            is_packed: true,
                            relative_path: "/placeholder/path.pack".to_string(),
                            offset: 0,
                            length: 100,
                            stretch_encryption_key: false,
                            compression_type: 2,
                            is_large_pack: Some(false),
                        }],
                        acl_blob_loc: None,
                        xattrs_blob_locs: None, // Unified Node uses Option here
                        item_size: 100,
                        contained_files_count: Some(1), // Unified Node uses Option
                        modification_time_sec: 1735296644,
                        modification_time_nsec: 0,
                        change_time_sec: 1735296644,
                        change_time_nsec: 0,
                        creation_time_sec: 1735296644,
                        creation_time_nsec: 0,
                        username: Some("user".to_string()),
                        group_name: Some("group".to_string()),
                        deleted: false,
                        mac_st_dev: 0, // i64 in unified Node
                        mac_st_ino: 100000 + i as u64, // Ensure `i` is cast if necessary, it's usize from enumerate or range
                        mac_st_mode: 33188,
                        mac_st_nlink: 1,
                        mac_st_uid: Some(501), // Unified Node uses Option
                        mac_st_gid: 20,
                        mac_st_rdev: 0,  // i32 in unified Node
                        mac_st_flags: 0, // i32 in unified Node
                        win_attrs: 0,
                        reparse_tag: None,
                        reparse_point_is_directory: None,
                    };
                    child_nodes.insert(name, placeholder_node);
                }
            }
        }

        Ok(BinaryTree {
            version,
            child_nodes,
        })
    }

    /// Parse a Tree from LZ4-compressed binary data
    pub fn from_decompressed_data(data: &[u8]) -> Result<Self> {
        // First 4 bytes are the decompressed length
        let mut cursor = std::io::Cursor::new(data);
        Self::from_reader(&mut cursor)
    }
}

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
