use bs58;
use multibase::Base;

use std::{fmt, result};

use crate::{
    multibase::Multibase,
    multicodec::{self, Multicodec},
    multihash::Multihash,
    Error, Result,
};

pub enum Version {
    Zero,
    One,
    Two,
    Three,
}

pub enum Cid {
    Zero(Multihash),
    One(Base, Multicodec, Multihash),
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self {
            Cid::Zero(mh) => {
                let base = Base::Base58Btc;
                write!(f, "{:?}-cidv0-dag-pb-{}", base, mh)
            }
            Cid::One(base, codec, mh) => {
                let cid_v1: Multicodec = multicodec::CID_V1.into();
                write!(f, "{:?}-{}-{}-{}", base, cid_v1, codec, mh)
            }
        }
    }
}

impl Cid {
    /// Create a new Cid in Version-0 format for data. Here data shall be
    /// encoded in Multihash specification using SHA2-256 cryptographic
    /// hash algorithm.
    ///
    /// * 32 byte length SHA2-256 digest is created for data.
    /// * Resulting digest is encoded in [multihash] format.
    ///
    /// _Refer to [CIDv0] spec for details_
    ///
    /// [CIDv0]: https://github.com/multiformats/cid#cidv0
    /// [multihash]: https://multiformats.io/multihash/
    ///
    pub fn new_v0(data: &[u8]) -> Result<Cid> {
        let mut mh = Multihash::from_codec(multicodec::SHA2_256.into())?;
        mh.write(data)?.finish()?;
        Ok(Cid::Zero(mh))
    }

    /// <cidv1> ::= <multibase-prefix><multicodec-cidv1><codec><multihash>
    ///
    /// * _<codec>_, describes multicodec-content-type or format of the
    ///   data being addressed.
    /// * _<multihash>_, is SHA2-256 of data in Multihash format.
    ///
    /// _Refer to [CIDv1] spec for details_
    ///
    /// [CIDv1]: https://github.com/multiformats/cid#how-does-it-work
    ///
    pub fn new_v1(base: Base, codec: Multicodec, data: &[u8]) -> Result<Cid> {
        let mut mh = Multihash::from_codec(multicodec::SHA2_256.into())?;
        mh.write(data)?.finish()?;
        Ok(Cid::One(base, codec, mh))
    }

    /// Encode in base format.
    ///
    /// * If value is a CIDv0 variant, encoded into legacy base48btc format.
    /// * If value is a CIDv1 variant, encoded using specified base format.
    /// * If `base` is supplied as None, base58btc is used for CIDv0 and
    ///   base-32-lower is used for CIDv1,
    pub fn to_base_text(&self) -> Result<String> {
        let text = match self {
            Cid::Zero(mh) => bs58::encode(mh.encode()?).into_string(),
            Cid::One(base, codec, mh) => {
                let mut data = {
                    let codec = Multicodec::from_code(multicodec::CID_V1)?;
                    codec.encode()?
                };
                data.extend(codec.encode()?);
                data.extend(mh.encode()?);
                Multibase::from_base(base.clone(), &data)?.encode()?
            }
        };
        Ok(text)
    }

    /// Decode a base encoded CID. CID format can either be in
    /// legacy (v0) format or CIDv1 format.
    pub fn from_text(text: &str) -> Result<Cid> {
        let mut chars = text.chars();
        let cid = match (chars.next(), chars.next()) {
            (Some('Q'), Some('m')) | (Some('1'), Some(_)) => {
                // legacy format v0.
                let bytes = {
                    let res = bs58::decode(text.as_bytes()).into_vec();
                    err_at!(BadInput, res)?
                };
                let (mh, _) = Multihash::decode(&bytes)?;
                Cid::Zero(mh)
            }
            _ => {
                let (base, bytes) = {
                    let mb = Multibase::decode(text)?;
                    match mb.to_bytes() {
                        Some(bytes) => (mb.to_base(), bytes),
                        None => err_at!(BadInput, msg: format!("{}", text))?,
                    }
                };
                // <multicodec-cidv1><codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(BadInput, msg: format!("CID {}", codec))?,
                }

                let (codec, bytes) = Multicodec::decode(bytes)?;
                let (mh, _) = Multihash::decode(bytes)?;
                Cid::One(base, codec, mh)
            }
        };

        Ok(cid)
    }

    /// Return CID version.
    pub fn to_version(&self) -> Version {
        match self {
            Cid::Zero(_) => Version::Zero,
            Cid::One(_, _, _) => Version::One,
        }
    }

    /// Return the base encoding used for this CID.
    pub fn to_base(&self) -> Base {
        match self {
            Cid::Zero(_) => Base::Base58Btc,
            Cid::One(base, _, _) => base.clone(),
        }
    }

    /// Return the content type or format of the data being addressed.
    pub fn to_content_type(&self) -> Option<Multicodec> {
        match self {
            Cid::Zero(_) => None,
            Cid::One(_, codec, _) => Some(codec.clone()),
        }
    }

    /// Return hash digest, typically encoded with SHA2-256, in which case
    /// it must be a 32-byte vector.
    pub fn to_digest(&self) -> Vec<u8> {
        match self {
            Cid::Zero(mh) => mh.to_digest(),
            Cid::One(_, _, mh) => mh.to_digest(),
        }
    }
}