//! Module implement Multiformat type for reading byte-stream.

use crate::{
    multibase::Multibase,
    multicodec::{self, Multicodec},
    multihash::Multihash,
    Error, Result,
};

/// Enumeration of different multiformats.
///
/// Typically used for parsing input byte-stream.
pub enum Multiformat {
    Multibase(Multicodec, Multibase),
    Multihash(Multicodec, Multihash),
}

impl Multiformat {
    /// Create a new Multiformat from multi-base.
    pub fn from_multibase(value: Multibase) -> Result<Multiformat> {
        let codec: Multicodec = multicodec::MULTIBASE.into();
        Ok(Multiformat::Multibase(codec, value))
    }

    /// Create a new Multiformat from multi-hash.
    pub fn from_multihash(value: Multihash) -> Result<Multiformat> {
        let codec = value.to_codec();
        Ok(Multiformat::Multihash(codec, value))
    }

    /// Encode multi-format value and its under-lying type.
    pub fn encode(&self) -> Result<Vec<u8>> {
        use Multiformat::*;

        let data = match self {
            Multibase(codec, mb) => {
                let mut out = codec.encode()?;
                out.extend(mb.encode()?.as_bytes());
                out
            }
            Multihash(_codec, mh) => {
                // as per specification, multi-codec is encoded by multihash.
                mh.encode()?
            }
        };
        Ok(data)
    }

    /// Decode input byte-stream into one of multi-format types.
    pub fn decode(buf: &[u8]) -> Result<(Multiformat, &[u8])> {
        use std::str::from_utf8;

        let (codec, rem) = Multicodec::decode(buf)?;
        let (val, rem) = match codec.to_code() {
            multicodec::MULTIBASE => {
                let val = {
                    let text = err_at!(BadInput, from_utf8(rem))?;
                    Multibase::decode(text)?
                };
                (Multiformat::Multibase(codec, val), &buf[buf.len()..])
            }
            _ => {
                // as per specification, multi-codec is decoded by multihash.
                if let Ok((val, rem)) = Multihash::decode(buf) {
                    (Multiformat::Multihash(codec, val), rem)
                } else {
                    err_at!(BadInput, msg: format!("{}", codec))?
                }
            }
        };

        Ok((val, rem))
    }
}
