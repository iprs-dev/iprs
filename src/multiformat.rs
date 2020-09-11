//! Module implement Multiformat type for reading byte-stream.

#[allow(unused_imports)]
use crate::multicodec::TABLE;
use crate::{
    multibase::Multibase,
    multicodec::{self, Codepoint, Multicodec},
    multihash::Multihash,
    Error, Result,
};

/// Enumeration of different multiformats.
///
/// Typically used for parsing input byte-stream.
pub enum Multiformat {
    Multibase(Multibase),
    Multihash(Multihash),
}

impl Multiformat {
    /// Convert input byte-stream into one of multi-format types. If
    /// `code_points` is None, then default [TABLE] from [multicodec]
    /// is used.
    pub fn from_slice<'a, 'b>(
        buf: &'a [u8],
        code_points: Option<&'b [Codepoint]>,
    ) -> Result<(Multiformat, &'a [u8])> {
        let codes = code_points.unwrap_or(multicodec::TABLE.as_ref());

        let (codec, _) = Multicodec::from_slice(buf)?;

        let mut iter = codes.iter();
        let (val, rem) = loop {
            match iter.next() {
                Some(code_point) => match code_point.tag.as_str() {
                    "multibase" => {
                        let val = Multibase::from_slice(buf)?;
                        break (Multiformat::Multibase(val), &buf[buf.len()..]);
                    }
                    "multihash" => {
                        let (val, rem) = Multihash::from_slice(buf)?;
                        break (Multiformat::Multihash(val), rem);
                    }
                    _ => (),
                },
                None => err_at!(BadInput, msg: format!("{}", codec))?,
            }
        };
        Ok((val, rem))
    }
}
