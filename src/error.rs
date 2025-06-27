use std::num::TryFromIntError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    CryptoError,
    CipherError,
    BlockModeError,
    ParseError,
    ConversionError(std::str::Utf8Error),
    IoError(std::io::Error), // For standard I/O errors
    DecompressionError(lz4_flex::block::DecompressError),
    DecompressionDataLengthOutOfBounds,

    // Added variants
    InvalidData(String),
    JsonDecode(String),
    Encryption(String),
    PlistDecode(String),
    Input(String),
    NotFound(String),
    NotSupported(String),
    Io(String), // For custom I/O related error messages
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::ConversionError(ref err) => write!(f, "ConversionError: {err}"),
            Error::DecompressionError(ref err) => write!(f, "DecompressionError: {err}"),
            Error::IoError(ref err) => write!(f, "IoError: {err}"),
            Error::InvalidData(ref msg) => write!(f, "InvalidData: {msg}"),
            Error::JsonDecode(ref msg) => write!(f, "JsonDecode: {msg}"),
            Error::Encryption(ref msg) => write!(f, "Encryption: {msg}"),
            Error::PlistDecode(ref msg) => write!(f, "PlistDecode: {msg}"),
            Error::Input(ref msg) => write!(f, "Input: {msg}"),
            Error::NotFound(ref msg) => write!(f, "NotFound: {msg}"),
            Error::NotSupported(ref msg) => write!(f, "NotSupported: {msg}"),
            Error::Io(ref msg) => write!(f, "Io: {msg}"),
            // Other specific errors from libraries might be better handled by their own Display impl
            // or wrapped in a general error string if not covered above.
            // For example, CryptoError, CipherError, BlockModeError, ParseError could have custom strings.
            Error::WrongPassword => write!(f, "WrongPassword"),
            Error::CryptoError => write!(f, "CryptoError"),
            Error::CipherError => write!(f, "CipherError"),
            Error::BlockModeError => write!(f, "BlockModeError"),
            Error::ParseError => write!(f, "ParseError"), // Generic parse error
            Error::DecompressionDataLengthOutOfBounds => write!(f, "DecompressionDataLengthOutOfBounds"),
        }
    }
}

impl From<TryFromIntError> for Error {
    fn from(_error: TryFromIntError) -> Self {
        Error::DecompressionDataLengthOutOfBounds
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::ConversionError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl std::convert::From<digest::InvalidLength> for Error {
    fn from(_error: digest::InvalidLength) -> Error {
        Error::CryptoError
    }
}

impl std::convert::From<aes::cipher::block_padding::UnpadError> for Error {
    fn from(_: aes::cipher::block_padding::UnpadError) -> Self {
        Error::CipherError
    }
}

impl std::convert::From<plist::Error> for Error {
    fn from(_error: plist::Error) -> Error {
        Error::ParseError
    }
}

impl std::convert::From<std::str::Utf8Error> for Error {
    fn from(error: std::str::Utf8Error) -> Error {
        Error::ConversionError(error)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl std::convert::From<std::num::ParseIntError> for Error {
    fn from(_error: std::num::ParseIntError) -> Error {
        Error::ParseError
    }
}

impl std::convert::From<lz4_flex::block::DecompressError> for Error {
    fn from(error: lz4_flex::block::DecompressError) -> Error {
        Error::DecompressionError(error)
    }
}
