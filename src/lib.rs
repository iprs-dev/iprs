//! Package implement [multiformat] specification.
//!
//! [multiformat]: http://multiformats.io
use std::{error, fmt, result};

#[macro_use]
mod util;
pub mod multicodec;
pub mod multihash;

pub use multibase;
pub use multicodec::Multicodec;

/// Type alias for Result return type, used by this package.
pub type Result<T> = result::Result<T, Error>;

/// Error variants that can be returned by this package's API.
///
/// Each variant carries a prefix, typically identifying the
/// error location.
pub enum Error {
    IOError(String, String),
    Invalid(String, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Error::{IOError, Invalid};

        match self {
            IOError(p, msg) => write!(f, "{} IOError: {}", p, msg),
            Invalid(p, msg) => write!(f, "{} Invalid: {}", p, msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl error::Error for Error {}
