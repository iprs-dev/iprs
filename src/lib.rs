// Copyright (c) 2020 R Pratap Chakravarthy

//! Package implement [multiformats] specification.
//!
//! [multiformats]: http://multiformats.io

#![feature(box_syntax, box_patterns)]

use std::{error, fmt, result};

#[macro_use]
extern crate data_encoding_macro;

#[macro_use]
mod util;
pub mod cid;
pub mod multibase;
pub mod multicodec;
// mod multiformat;
pub mod addr_info;
pub mod net_addr;
pub mod net_conn;
pub mod pb;
pub mod peer_id;
pub mod peer_record;

// modules that has its own sub-directories
pub mod identity;
pub mod ipfsd;
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
    IOError(String, String),
    SysFail(String, String),
    IPCFail(String, String),
    ThreadFail(String, String),
    Invalid(String, String),
    DecodeError(String, String),
    EncodeError(String, String),
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
            IOError(p, msg) => write!(f, "{} IOError: {}", p, msg),
            SysFail(p, msg) => write!(f, "{} SysFail: {}", p, msg),
            IPCFail(p, msg) => write!(f, "{} IPCFail: {}", p, msg),
            ThreadFail(p, msg) => write!(f, "{} ThreadFail: {}", p, msg),
            Invalid(p, msg) => write!(f, "{} Invalid: {}", p, msg),
            DecodeError(p, msg) => write!(f, "{} DecodeError: {}", p, msg),
            EncodeError(p, msg) => write!(f, "{} EncodeError: {}", p, msg),
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
