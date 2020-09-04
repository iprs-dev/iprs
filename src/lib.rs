//! Package implement [multiformat] specification.
//!
//! [multiformat]: http://multiformats.io
use std::{fmt, result};

#[macro_use]
mod util;

/// Re-export multibase. Checkout [multibase][multibase-link] for
/// further details.
///
/// [multibase-link]: https://github.com/multiformats/multibase
pub use multibase;

/// Type alias for Result return type, used by this package.
pub type Result<T> = result::Result<T, Error>;

/// Error variants that can be returned by this package's API.
///
/// Each variant carries a prefix, typically identifying the
/// error location.
pub enum Error {
    Invalid(String, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Error::Invalid;

        match self {
            Invalid(p, msg) => write!(f, "{} Invalid: {}", p, msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}
