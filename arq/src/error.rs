use std::num::TryFromIntError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    WrongPassword,
    CryptoError,
    CipherError,
    BlockModeError,
    ParseError,
    InvalidFormat(String),
    ConversionError(std::str::Utf8Error),
    IoError(std::io::Error),
    DecompressionError(lz4_flex::block::DecompressError),
    DecompressionDataLengthOutOfBounds,
    JsonError(serde_json::Error),
    Lz4Error(lz4_flex::frame::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::ConversionError(ref err) => write!(f, "{err}"),
            Error::DecompressionError(ref err) => write!(f, "{err}"),
            Error::JsonError(ref err) => write!(f, "{err}"),
            Error::Lz4Error(ref err) => write!(f, "{err}"),
            Error::InvalidFormat(ref msg) => write!(f, "Invalid format: {msg}"),
            _ => write!(f, "{:#?}", self),
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
            Error::JsonError(ref err) => Some(err),
            Error::Lz4Error(ref err) => Some(err),
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

impl std::convert::From<std::string::FromUtf8Error> for Error {
    fn from(_error: std::string::FromUtf8Error) -> Error {
        Error::ParseError
    }
}

impl std::convert::From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Error {
        Error::JsonError(error)
    }
}

impl std::convert::From<lz4_flex::frame::Error> for Error {
    fn from(error: lz4_flex::frame::Error) -> Error {
        Error::Lz4Error(error)
    }
}
