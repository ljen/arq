//! Arq provides a way to interact with the Arq Backup data format as described in their
//! [arq_data_format.txt](https://www.arqbackup.com/arq_data_format.txt).
//!
//! NOTE: A lot of the documentation, especially the one describing the data formats,
//! comes from [https://arqbackup.com](https://www.arqbackup.com/arq_data_format.txt). All
//! credit should go to those folks.
//!
//! ## Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! arq = "0.1"
//! ```
//!
//! ## Examples
//!
//! 1. Reading a computer info entry:
//!
//! ```
//! extern crate arq;
//! let reader = std::io::Cursor::new("<plist version=\"1.0\">
//!    <dict>
//!        <key>userName</key>
//!        <string>someuser</string>
//!        <key>computerName</key>
//!        <string>somecomputer</string>
//!    </dict>
//!    </plist>");
//! let data = arq::computer::ComputerInfo::new(reader, "someuuid".to_string()).unwrap();
//! assert_eq!(data.computer_name, "somecomputer".to_string());
//! assert_eq!(data.user_name, "someuser".to_string());
//! assert_eq!(data.uuid, "someuuid".to_string());
//!```
//!
//! 2. Reading a tree
//!
//! Note: Usually one reads this from a file, not used directly like shown here.
//!
//! ```
//! let tree_bytes = [0, 0, 2, 182, 159, 84, 114, 101, 101, 86, 48, 50, 50, 0, 1, 0, 30, 255, 11, 1, 245, 0, 0, 0, 20, 0, 0, 65, 237, 0, 0, 0, 0, 92, 197, 219, 103, 0, 0, 0, 0, 16, 90, 33, 177, 75, 0, 1, 132, 2, 77, 81, 191, 0, 0, 0, 4, 28, 0, 15, 48, 0, 3, 17, 16, 31, 0, 193, 92, 197, 219, 84, 0, 0, 0, 0, 48, 246, 52, 114, 17, 0, 67, 0, 0, 2, 1, 9, 0, 145, 8, 115, 111, 109, 101, 102, 105, 108, 101, 16, 0, 17, 2, 6, 0, 2, 2, 0, 20, 1, 35, 0, 244, 30, 40, 100, 97, 56, 97, 48, 48, 51, 53, 55, 54, 52, 51, 100, 52, 56, 49, 98, 53, 98, 52, 54, 99, 57, 100, 99, 57, 99, 52, 49, 50, 55, 55, 98, 51, 53, 98, 57, 101, 56, 53, 1, 0, 0, 0, 53, 0, 6, 2, 0, 22, 12, 11, 0, 15, 2, 0, 13, 4, 3, 1, 41, 129, 164, 3, 1, 60, 92, 158, 217, 58, 0, 5, 103, 0, 5, 9, 0, 146, 0, 1, 0, 0, 4, 2, 77, 81, 220, 11, 0, 2, 2, 0, 5, 22, 1, 3, 67, 0, 5, 16, 0, 50, 89, 212, 77, 34, 0, 85, 0, 8, 0, 0, 16, 182, 0, 177, 10, 116, 111, 112, 95, 102, 111, 108, 100, 101, 114, 89, 0, 15, 16, 1, 3, 255, 25, 99, 48, 53, 55, 49, 53, 51, 55, 100, 53, 55, 100, 57, 52, 56, 56, 49, 54, 52, 51, 48, 51, 57, 53, 48, 100, 102, 100, 101, 100, 53, 99, 98, 54, 99, 102, 99, 100, 50, 48, 16, 1, 3, 19, 39, 121, 0, 15, 2, 0, 116, 80, 0, 0, 0, 0, 0];
//! let tree = arq::tree::Tree::new(&tree_bytes, arq::compression::CompressionType::LZ4).unwrap();
//! assert_eq!(tree.version, 22);
//! ```
//!
//! **For a more complex example, please check a command line tool (`evu`) built using this
//! library at [https://github.com/nlopes/evu](https://github.com/nlopes/evu).**
extern crate aesni;
extern crate block_modes;
extern crate block_padding;
extern crate byteorder;
extern crate chrono;
#[cfg_attr(test, macro_use)]
extern crate hex_literal;
extern crate hmac;
extern crate lz4_sys;
extern crate plist;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha1;
extern crate sha2;

pub mod compression;
pub mod computer;
pub mod error;
pub mod folder;
pub mod object_encryption;
pub mod packset;
pub mod tree;
pub mod type_utils;

mod blob;
mod date;
mod lz4;
mod utils;
