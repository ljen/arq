use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    ArqError(arq::error::Error),
    OsError(std::ffi::OsString),
    IoError(std::io::Error),
    OptionError, // Consider removing if not used, or make more specific
    NotFound(String),
    Generic(String), // Added for general errors
    CliInputError(String), // Added for CLI argument errors
    UnknownArqVersion(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ArqError(err) => write!(f, "Arq library error: {}", err),
            Error::OsError(os_str) => write!(f, "OS error: {:?}", os_str),
            Error::IoError(err) => write!(f, "IO error: {}", err),
            Error::OptionError => write!(f, "Option error: value was None"), // Or more specific message
            Error::NotFound(msg) => write!(f, "Not found: {}", msg),
            Error::Generic(msg) => write!(f, "Error: {}", msg),
            Error::CliInputError(msg) => write!(f, "CLI input error: {}", msg),
            Error::UnknownArqVersion(path) => write!(f, "Could not determine Arq version at path: {}", path),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::ArqError(err) => Some(err),
            Error::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error {
        Error::IoError(error)
    }
}

impl std::convert::From<std::ffi::OsString> for Error {
    fn from(error: std::ffi::OsString) -> Error {
        Error::OsError(error)
    }
}

impl std::convert::From<arq::error::Error> for Error {
    fn from(error: arq::error::Error) -> Error {
        Error::ArqError(error)
    }
}

// impl std::convert::From<std::option::NoneError> for Error {
//     fn from(_error: std::option::NoneError) -> Error {
//         Error::OptionError
//     }
// }
