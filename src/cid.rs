//! Module implement content Identifier. _Refer [cid] spec for details_.
//!
//! [cid]: https://github.com/multiformats/cid

use bs58;
use multibase::Base;

use std::{fmt, result, str::FromStr};

use crate::{
    multibase::Multibase,
    multicodec::{self, Multicodec},
    multihash::Multihash,
    peer_id::PeerId,
    Error, Result,
};

/// Content Identifier is represeted in different formats, there is
/// legacy, then came CIDv1, to keep it future-proof there are two
/// more reserved versions allocated in [multicodec-spec].
///
/// [multicodec-spec]: https://github.com/multiformats/multicodec/blob/master/table.csv
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Version {
    Zero,
    One,
    Two,
    Three,
}

/// Content Identifier.
#[derive(Clone, Eq, PartialEq)]
pub enum Cid {
    Zero(Multihash),
    One(Option<Base>, Multicodec, Multihash),
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self {
            Cid::Zero(mh) => {
                let base = Base::Base58Btc;
                write!(f, "{:?}-cidv0-dag-pb-{}", base, mh)
            }
            Cid::One(Some(base), codec, mh) => {
                let cid_v1: Multicodec = multicodec::CID_V1.into();
                write!(f, "{:?}-{}-{}-{}", base, cid_v1, codec, mh)
            }
            Cid::One(None, codec, mh) => {
                let cid_v1: Multicodec = multicodec::CID_V1.into();
                write!(f, "binary-{}-{}-{}", cid_v1, codec, mh)
            }
        }
    }
}

impl fmt::Debug for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        <Cid as fmt::Display>::fmt(self, f)
    }
}

impl FromStr for Cid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Cid> {
        Cid::from_text(s)
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

    /// _cidv1 ::= multibase-prefix + multicodec-cidv1 + codec + multihash_
    ///
    /// * _codec_, describes multicodec-content-type or format of the
    ///   data being addressed.
    /// * _multihash_, is SHA2-256 of data in Multihash format.
    ///
    /// _Refer to [CIDv1] spec for details_
    ///
    /// [CIDv1]: https://github.com/multiformats/cid#how-does-it-work
    ///
    pub fn new_v1(base: Base, codec: Multicodec, data: &[u8]) -> Result<Cid> {
        let mut mh = Multihash::from_codec(multicodec::SHA2_256.into())?;
        mh.write(data)?.finish()?;
        Ok(Cid::One(Some(base), codec, mh))
    }

    /// Set the `new_base` for base-encoding, if _CID_ is constructed using V1.
    pub fn set_base_encoding(&mut self, new_base: Base) -> &mut Self {
        match self {
            Cid::Zero(_) => (),
            Cid::One(base, _, _) => *base = Some(new_base),
        }
        self
    }

    /// Create a Cid-v0 from peer-id.
    pub fn from_peer_id_v0(&self, peer_id: PeerId) -> Self {
        Cid::Zero(peer_id.into())
    }

    /// Create a Cid-v1 from peer-id.
    pub fn from_peer_id_v1(&self, peer_id: PeerId) -> Self {
        let code = multicodec::LIBP2P_KEY;
        Cid::One(None, code.into(), peer_id.into())
    }

    /// Decode a base encoded CID, human readable text. CID format can
    /// either be in legacy (v0) format or CIDv1 format.
    pub fn from_text(text: &str) -> Result<Cid> {
        let mut chars = text.chars();
        let cid = match (chars.next(), chars.next()) {
            (Some('Q'), Some('m')) | (Some('1'), Some(_)) => {
                // legacy format v0.
                let bytes = {
                    let res = bs58::decode(text.as_bytes()).into_vec();
                    err_at!(DecodeError, res)?
                };
                let (mh, _) = Multihash::decode(&bytes)?;
                Cid::Zero(mh)
            }
            _ => {
                let (base, bytes) = {
                    let mb = Multibase::decode(text)?;
                    match mb.to_bytes() {
                        Some(bytes) => (mb.to_base(), bytes),
                        None => err_at!(DecodeError, msg: format!("{}", text))?,
                    }
                };
                // <multicodec-cidv1><codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(DecodeError, msg: format!("CID {}", codec))?,
                }

                let (codec, bytes) = Multicodec::decode(bytes)?;
                let (mh, _) = Multihash::decode(bytes)?;
                Cid::One(Some(base), codec, mh)
            }
        };

        Ok(cid)
    }

    /// Encode in base format.
    ///
    /// * If value is a CIDv0 variant, encoded into legacy base58btc format.
    /// * If value is a CIDv1 variant, encoded using specified base format.
    pub fn to_base_text(&self) -> Result<String> {
        let text = match self {
            Cid::Zero(mh) => bs58::encode(mh.encode()?).into_string(),
            Cid::One(Some(base), codec, mh) => {
                let mut data = {
                    let codec = Multicodec::from_code(multicodec::CID_V1)?;
                    codec.encode()?
                };
                data.extend(codec.encode()?);
                data.extend(mh.encode()?);
                Multibase::from_base(base.clone(), &data)?.encode()?
            }
            Cid::One(None, _, _) => {
                let msg = format!("no base supplied, try binary encoding");
                err_at!(Invalid, msg: msg)?
            }
        };
        Ok(text)
    }

    /// Decode a binary encoded CID. Refer to [encode] method for details.
    /// Supports both legacy-format and CIDv1-format.
    pub fn decode(bytes: &[u8]) -> Result<Cid> {
        let cid = match bytes {
            [0x12, 0x20, ..] => {
                // legacy format v0.
                let (mh, _) = Multihash::decode(&bytes)?;
                Cid::Zero(mh)
            }
            _ => {
                // <multicodec-cidv1><codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(DecodeError, msg: format!("CID {}", codec))?,
                }
                let (codec, bytes) = Multicodec::decode(bytes)?;
                let (mh, _) = Multihash::decode(bytes)?;
                Cid::One(None, codec, mh)
            }
        };

        Ok(cid)
    }

    /// Encode to binary format.
    ///
    /// If value is a CIDv0 variant:
    ///
    /// * Encoded as binary multi-hash format. The resulting bytes start with
    ///   _[0x12, 0x20, ...]_
    ///
    /// If value is a CIDv1 variant:
    ///
    /// * _CID-version_ byte followed by,
    /// * _codec_, unsigned_varint multicodec value, describing
    ///   multicodec-content-type or format of the data being addressed,
    ///   followed by,
    /// * _multihash_, is SHA2-256 of data in Multihash format.
    ///
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Cid::Zero(mh) => mh.encode()?,
            Cid::One(_, codec, mh) => {
                let mut bytes = {
                    let codec = Multicodec::from_code(multicodec::CID_V1)?;
                    codec.encode()?
                };
                bytes.extend(codec.encode()?);
                bytes.extend(mh.encode()?);
                bytes
            }
        };
        Ok(bytes)
    }

    /// Return CID version.
    pub fn to_version(&self) -> Version {
        match self {
            Cid::Zero(_) => Version::Zero,
            Cid::One(_, _, _) => Version::One,
        }
    }

    /// Return the base encoding used for this CID.
    pub fn to_base(&self) -> Option<Base> {
        match self {
            Cid::Zero(_) => Some(Base::Base58Btc),
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
    pub fn to_multihash(&self) -> Multihash {
        match self {
            Cid::Zero(mh) => mh.clone(),
            Cid::One(_, _, mh) => mh.clone(),
        }
    }

    /// If CID is pointing to a peer-id, that is if the codec is
    /// _LIBP2P_KEY_, return the PeerId value.
    pub fn to_peer_id(&self) -> Option<PeerId> {
        let code = multicodec::LIBP2P_KEY;
        match self {
            Cid::One(_, codec, mh) if codec.to_code() == code => {
                //
                Some(mh.clone().into())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "cid_test.rs"]
mod cid_test;
