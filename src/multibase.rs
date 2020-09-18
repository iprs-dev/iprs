//! Module handles [multibase] specification.
//!
//! [multibase]: https://github.com/multiformats/multibase

use multibase;

use std::io;

use crate::{Error, Result};

/// Type to encode/decode bytes into/from multi-base formats.
///
/// Refer to [multibase] specification for supported base formats.
///
/// [multibase]: https://github.com/multiformats/multibase
pub struct Multibase {
    base: multibase::Base,
    data: Option<Vec<u8>>,
}

impl Multibase {
    /// Create a multibase encoder from one of the many base formats.
    pub fn from_base(base: multibase::Base) -> Result<Multibase> {
        Ok(Multibase { base, data: None })
    }

    /// Create a multibase encoder from character prefix defined in multibase
    /// [specification].
    ///
    /// [specification]: https://github.com/multiformats/multibase/blob/master/multibase.csv
    pub fn from_char(ch: char) -> Result<Multibase> {
        let base = match multibase::Base::from_code(ch) {
            Ok(base) => Ok(base),
            Err(e) => err_at!(BadInput, Err(e), format!("bad char `{}`", ch)),
        }?;

        Ok(Multibase { base, data: None })
    }

    /// Encode input binary-data using this base format, encoded stream of
    /// bytes shall have the <base-prefix> followed by the actual
    /// base-representation of the `input`.
    pub fn encode<I: AsRef<[u8]>>(&self, input: I) -> Result<Vec<u8>> {
        let mut buf = Vec::default();
        self.encode_with(input, &mut buf)?;
        Ok(buf)
    }

    /// Decode <base-prefix> followed by the base-representation, into
    /// raw-data. Caller can use the returned value to get the base
    /// format and the original raw-data.
    pub fn decode(buf: &[u8]) -> Result<Multibase> {
        use std::str::from_utf8;

        let text = err_at!(BadInput, from_utf8(buf))?;
        let (base, data) = err_at!(BadInput, multibase::decode(text))?;

        let val = Multibase {
            base,
            data: Some(data),
        };

        Ok(val)
    }

    // Same as encode but avoids memory allocation by using the supplied
    // buffer `buf`.
    fn encode_with<I, W>(&self, input: I, buf: &mut W) -> Result<usize>
    where
        I: AsRef<[u8]>,
        W: io::Write,
    {
        let text = multibase::encode(self.base.clone(), input);
        err_at!(IOError, buf.write(text.as_bytes()))?;
        Ok(text.len())
    }

    /// Return the `Base` format type.
    pub fn to_base(&self) -> multibase::Base {
        self.base.clone()
    }

    /// Return the decoded original binary-data from base-format.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.data.clone()
    }
}

pub const TABLE: [(&'static str, char, &'static str); 23] = [
    (
        "identity",
        '\0',
        "8-bit binary (encoder and decoder keeps data unmodified)",
    ),
    ("base2", '0', "binary (01010101)"),
    ("base8", '7', "octal"),
    ("base10", '9', "decimal"),
    ("base16", 'f', "hexadecimal"),
    ("base16upper", 'F', "hexadecimal"),
    (
        "base32hex",
        'v',
        "rfc4648 case-insensitive - no padding - highest char",
    ),
    (
        "base32hexupper",
        'V',
        "rfc4648 case-insensitive - no padding - highest char",
    ),
    (
        "base32hexpad",
        't',
        "rfc4648 case-insensitive - with padding",
    ),
    (
        "base32hexpadupper",
        'T',
        "rfc4648 case-insensitive - with padding",
    ),
    ("base32", 'b', "rfc4648 case-insensitive - no padding"),
    ("base32upper", 'B', "rfc4648 case-insensitive - no padding"),
    ("base32pad", 'c', "rfc4648 case-insensitive - with padding"),
    (
        "base32padupper",
        'C',
        "rfc4648 case-insensitive - with padding",
    ),
    ("base32z", 'h', "z-base-32 (used by Tahoe-LAFS)"),
    (
        "base36",
        'k',
        "base36 [0-9a-z] case-insensitive - no padding",
    ),
    (
        "base36upper",
        'K',
        "base36 [0-9a-z] case-insensitive - no padding",
    ),
    ("base58btc", 'z', "base58 bitcoin"),
    ("base58flickr", 'Z', "base58 flicker"),
    ("base64", 'm', "rfc4648 no padding"),
    ("base64pad", 'M', "rfc4648 with padding - MIME encoding"),
    ("base64url", 'u', "rfc4648 no padding"),
    ("base64urlpad", 'U', "rfc4648 with padding"),
];

#[cfg(test)]
#[path = "multibase_test.rs"]
mod multibase_test;
