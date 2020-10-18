//! Library implement _inter planetary specifications_ in rust-lang.
//!
//! **Stated Goals**
//!
//! * [multiformats](http://multiformats.io)
//! * [inter-planetary-linked-data](http://ipld.io)
//! * [peer-to-peer library](http://libp2p.io)
//! * [inter-planetray-file-system](http://ipfs.io)
//! * Between production ready and research friendly, choose research.
//! * Between performance and composability, choose composable.
//! * Between rustdoc and unit-test, choose rustdoc first.

#![feature(box_syntax, box_patterns)]

use std::{error, fmt, result};

#[macro_use]
extern crate data_encoding_macro;

#[macro_use]
pub mod util;
pub mod cid;
pub mod multibase;
pub mod multicodec;
// mod multiformat;
pub mod addr_info;
pub mod cbor;
pub mod multistream;
pub mod net_addr;
pub mod net_conn;
pub mod pb;
pub mod peer_id;
pub mod peer_record;

// modules that have its own sub-directories
pub mod identity;
pub mod ipfsd;
pub mod ipld;
pub mod multiaddr;
pub mod multihash;

/// Type alias for Result return type, used by this package.
pub type Result<T> = result::Result<T, Error>;

/// Error variants that can be returned by this package's API.
///
/// Each variant carries a prefix, typically identifying the
/// error location.
pub enum Error {
    Fatal(String, String),
    Overflow(String, String),
    IOError(String, String),
    SysFail(String, String),
    IPCFail(String, String),
    ThreadFail(String, String),
    FilePath(String, String),
    Invalid(String, String),
    ParseError(String, String),
    DecodeError(String, String),
    EncodeError(String, String),
    CborDecode(String, String),
    DnsError(String, String),
    SigningError(String, String),
    BadInput(String, String),
    BadCodec(String, String),
    BadAddr(String, String),
    HashFail(String, String),
    NotImplemented(String, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Error::*;

        match self {
            Fatal(p, msg) => write!(f, "{} Fatal: {}", p, msg),
            Overflow(p, msg) => write!(f, "{} Overflow: {}", p, msg),
            IOError(p, msg) => write!(f, "{} IOError: {}", p, msg),
            SysFail(p, msg) => write!(f, "{} SysFail: {}", p, msg),
            IPCFail(p, msg) => write!(f, "{} IPCFail: {}", p, msg),
            ThreadFail(p, msg) => write!(f, "{} ThreadFail: {}", p, msg),
            FilePath(p, msg) => write!(f, "{} FilePath: {}", p, msg),
            Invalid(p, msg) => write!(f, "{} Invalid: {}", p, msg),
            ParseError(p, msg) => write!(f, "{} ParseError: {}", p, msg),
            DecodeError(p, msg) => write!(f, "{} DecodeError: {}", p, msg),
            EncodeError(p, msg) => write!(f, "{} EncodeError: {}", p, msg),
            CborDecode(p, msg) => write!(f, "{} CborDecode: {}", p, msg),
            DnsError(p, msg) => write!(f, "{} DnsError: {}", p, msg),
            SigningError(p, msg) => write!(f, "{} SigningError: {}", p, msg),
            BadInput(p, msg) => write!(f, "{} BadInput: {}", p, msg),
            BadCodec(p, msg) => write!(f, "{} BadCodec: {}", p, msg),
            BadAddr(p, msg) => write!(f, "{} BadAddr: {}", p, msg),
            HashFail(p, msg) => write!(f, "{} HashFail: {}", p, msg),
            NotImplemented(p, msg) => write!(f, "{} NotImplemented: {}", p, msg),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", self)
    }
}

impl error::Error for Error {}
