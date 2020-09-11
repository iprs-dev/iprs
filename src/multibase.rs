//! Module handles [multibase] specification.
//!
//! [multibase]: https://github.com/multiformats/multibase

use std::io;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

/// Type to encode/decode bytes into/from multi-base formats.
///
/// Refer to [multibase] specification for supported base formats.
///
/// [multibase]: https://github.com/multiformats/multibase
pub struct Multibase {
    codec: Multicodec,
    base: multibase::Base,
    data: Option<Vec<u8>>,
}

impl Multibase {
    /// Create a multibase encoder from one of the many base formats.
    pub fn from_base(base: multibase::Base) -> Result<Multibase> {
        let val = Multibase {
            codec: multicodec::MULTIBASE.into(),
            base,
            data: None,
        };
        Ok(val)
    }

    /// Create a multibase encoder from character prefix defined in multibase
    /// [specification].
    ///
    /// [specification]: https://github.com/multiformats/multibase/blob/master/multibase.csv
    pub fn from_char(ch: char) -> Result<Multibase> {
        let val = Multibase {
            codec: multicodec::MULTIBASE.into(),
            base: err_at!(Invalid, multibase::Base::from_code(ch))?,
            data: None,
        };
        Ok(val)
    }

    /// Decode base-format into binary-data.
    ///
    /// Use the returned `Multibase` type to get the binary-data.
    ///
    /// ```ignore
    ///     Multibase::from_slice(input)?.to_bytes()
    /// ```
    pub fn from_slice(buf: &[u8]) -> Result<Multibase> {
        use std::str::from_utf8;

        let (codec, rem) = Multicodec::from_slice(buf)?;

        let s = err_at!(BadInput, from_utf8(rem))?;
        let (base, data) = err_at!(Invalid, multibase::decode(s))?;

        let val = Multibase {
            codec,
            base,
            data: Some(data),
        };

        Ok(val)
    }

    /// Encode input binary-data using this base format.
    pub fn encode<I: AsRef<[u8]>>(&self, input: I) -> Result<Vec<u8>> {
        let mut buf = Vec::default();
        self.encode_with(input, &mut buf)?;
        Ok(buf)
    }

    /// Same as encode but avoids memory allocation by using the supplied
    /// buffer `buf`.
    pub fn encode_with<I, W>(&self, input: I, buf: &mut W) -> Result<usize>
    where
        I: AsRef<[u8]>,
        W: io::Write,
    {
        let n = self.codec.encode_with(buf)?;

        let text = multibase::encode(self.base.clone(), input);
        err_at!(IOError, buf.write(text.as_bytes()))?;
        let m = text.len();

        Ok(n + m)
    }

    /// Return the codec value.
    pub fn to_codec(&self) -> Multicodec {
        self.codec.clone()
    }

    /// Return the `Base` format type.
    pub fn to_base(&self) -> multibase::Base {
        self.base.clone()
    }

    /// Return the decoded binary-data from base-format.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.data.clone()
    }

    /// Same as to_bytes() but return a reference, might be cheaper
    /// than calling `to_bytes()`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|x| x.as_slice())
    }
}
