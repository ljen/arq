use std::num::TryFromIntError;
use serde_json; // Added for serde_json::Error

pub type Result<T> = std::result::Result<T, ArqError>; // Renamed Error to ArqError

#[derive(Debug)]
pub enum ArqError { // Renamed Error to ArqError
    WrongPassword,
    CryptoError,
    CipherError,
    BlockModeError,
    ParseError, // Generic parse error, might be refined or removed if specific ones cover all cases
    ConversionError(std::str::Utf8Error),
    Io(std::io::Error), // Renamed from IoError to avoid stutter (ArqError::Io) and match new Generic variant pattern
    Decompression(String), // Changed to String to be more generic for lz4_flex or other errors
    DecompressionDataLengthOutOfBounds,

    // Variants from previous version, potentially merged or adjusted
    InvalidData(String),
    // JsonDecode(String), // Replaced by Json(serde_json::Error)
    Encryption(String),
    PlistDecode(String), // Consider From<plist::Error>
    Input(String),
    NotFound(String),
    NotSupported(String),
    // Io(String), // This was a duplicate of sorts, std::io::Error is better. Generic can cover other IO strings.

    // New variants for arq7 parsers
    Json(serde_json::Error),
    Generic(String), // For general error messages
    NotImplemented(String),
}

impl std::fmt::Display for ArqError { // Renamed Error to ArqError
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            ArqError::ConversionError(ref err) => write!(f, "ConversionError: {err}"),
            ArqError::Decompression(ref msg) => write!(f, "DecompressionError: {msg}"),
            ArqError::Io(ref err) => write!(f, "IoError: {err}"),
            ArqError::InvalidData(ref msg) => write!(f, "InvalidData: {msg}"),
            ArqError::Encryption(ref msg) => write!(f, "Encryption: {msg}"),
            ArqError::PlistDecode(ref msg) => write!(f, "PlistDecodeError: {msg}"),
            ArqError::Input(ref msg) => write!(f, "InputError: {msg}"),
            ArqError::NotFound(ref msg) => write!(f, "NotFound: {msg}"),
            ArqError::NotSupported(ref msg) => write!(f, "NotSupported: {msg}"),
            ArqError::WrongPassword => write!(f, "WrongPassword"),
            ArqError::CryptoError => write!(f, "CryptoError"),
            ArqError::CipherError => write!(f, "CipherError"),
            ArqError::BlockModeError => write!(f, "BlockModeError"),
            ArqError::ParseError => write!(f, "ParseError"),
            ArqError::DecompressionDataLengthOutOfBounds => write!(f, "DecompressionDataLengthOutOfBounds"),
            ArqError::Json(ref err) => write!(f, "JsonError: {err}"),
            ArqError::Generic(ref msg) => write!(f, "GenericError: {msg}"),
            ArqError::NotImplemented(ref msg) => write!(f, "NotImplementedError: {msg}"),
        }
    }
}

impl From<TryFromIntError> for ArqError { // Renamed Error to ArqError
    fn from(_error: TryFromIntError) -> Self {
        ArqError::DecompressionDataLengthOutOfBounds
    }
}

impl std::error::Error for ArqError { // Renamed Error to ArqError
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            ArqError::ConversionError(ref err) => Some(err),
            ArqError::Io(ref err) => Some(err),
            ArqError::Json(ref err) => Some(err),
            // Add other sources if ArqError variants wrap other error types
            _ => None,
        }
    }
}

impl std::convert::From<digest::InvalidLength> for ArqError { // Renamed Error to ArqError
    fn from(_error: digest::InvalidLength) -> ArqError {
        ArqError::CryptoError
    }
}

impl std::convert::From<aes::cipher::block_padding::UnpadError> for ArqError { // Renamed Error to ArqError
    fn from(_: aes::cipher::block_padding::UnpadError) -> Self {
        ArqError::CipherError
    }
}

impl std::convert::From<plist::Error> for ArqError { // Renamed Error to ArqError
    fn from(error: plist::Error) -> ArqError {
        ArqError::PlistDecode(error.to_string()) // Store plist error as string
    }
}

impl std::convert::From<std::str::Utf8Error> for ArqError { // Renamed Error to ArqError
    fn from(error: std::str::Utf8Error) -> ArqError {
        ArqError::ConversionError(error)
    }
}

impl std::convert::From<std::io::Error> for ArqError { // Renamed Error to ArqError
    fn from(error: std::io::Error) -> ArqError {
        ArqError::Io(error)
    }
}

impl std::convert::From<std::num::ParseIntError> for ArqError { // Renamed Error to ArqError
    fn from(_error: std::num::ParseIntError) -> ArqError {
        ArqError::ParseError // Or a more specific variant if appropriate
    }
}

impl std::convert::From<lz4_flex::block::DecompressError> for ArqError { // Renamed Error to ArqError
    fn from(error: lz4_flex::block::DecompressError) -> ArqError {
        ArqError::Decompression(error.to_string())
    }
}

// New From implementation for serde_json::Error
impl std::convert::From<serde_json::Error> for ArqError {
    fn from(error: serde_json::Error) -> ArqError {
        ArqError::Json(error)
    }
}
