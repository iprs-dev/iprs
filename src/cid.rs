//! Module implement content Identifier. _Refer [cid] spec for detail_.
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

/// Content Identifier is represeted in different formats.
///
/// There is legacy, then came CIDv1, to keep it future-proof there are two
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
    /// Cid version ZERO. Actually this is legacy.
    /// In the distant future, we may remove this support after sha2 breaks.
    Zero(Multihash),
    /// Cid version ONE.
    One(Base, Multicodec, Multihash),
    ///// Use this to lazy-parse CID or to pass-around CID in text-format.
    //Text(String),
    ///// Use this to lazy-parse CID or to pass-around CID in binary-format.
    //Binary(Vec<u8>),
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self {
            Cid::Zero(mh) => {
                let base = Base::Base58Btc;
                write!(f, "{:?}-cidv0-dag-pb-{}", base, mh)
            }
            Cid::One(base, content_type, mh) => {
                let cid_v1: Multicodec = multicodec::CID_V1.into();
                write!(f, "{:?}-{}-{}-{}", base, cid_v1, content_type, mh)
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
    /// Create a new Cid in Version-0 format from `data`. Here data
    /// shall be encoded in Multihash specification using SHA2-256
    /// cryptographic hash algorithm.
    ///
    /// * _multibase_, base58btc is implied.
    /// * _multicodec_, dag-pb is implied.
    /// * _cid-version_, cidv0 is implied.
    /// * _multihash_ is SHA2_256 computed from `data`.
    ///
    /// _Refer to [CIDv0] spec for details_
    ///
    /// [CIDv0]: https://github.com/multiformats/cid#cidv0
    /// [multihash]: https://multiformats.io/multihash/
    ///
    pub fn new_v0(data: &[u8]) -> Result<Cid> {
        let mh = Multihash::new(multicodec::SHA2_256.into(), data)?;
        Ok(Cid::Zero(mh))
    }

    /// Create a new Cid in Version-1 format from `data`.
    ///
    /// _cidv1 ::= multibase-prefix + multicodec-cidv1 + codec + multihash_
    ///
    /// * _base_, describes base-encoding to be used for this Cid.
    /// * _codec_, describes multicodec-content-type of the data.
    /// * _multihash_, is SHA2_256 computed from `data`.
    ///
    /// _Refer to [CIDv1] spec for details_
    ///
    /// [CIDv1]: https://github.com/multiformats/cid#how-does-it-work
    ///
    pub fn new_v1(base: Base, content_type: Multicodec, data: &[u8]) -> Result<Cid> {
        let mh = Multihash::new(multicodec::SHA2_256.into(), data)?;
        Ok(Cid::One(base, content_type, mh))
    }

    /// Transform into v1 addressing.
    pub fn into_v1(self) -> Self {
        use multibase::Base::Base58Btc;

        match self {
            Cid::Zero(peer_id) => {
                let content_type: Multicodec = multicodec::DAG_PB.into();
                Cid::One(Base58Btc, content_type, peer_id)
            }
            val @ Cid::One(_, _, _) => val,
        }
    }

    /// Compase CID-v1 from raw-hash-links. Convert the digest into multi-hash
    /// gather the base-encoding and content-type from the context and use this
    /// API to create a CID.
    pub fn from_raw(base: Base, content_type: Multicodec, mh: Multihash) -> Self {
        Cid::One(base, content_type, mh)
    }

    /// Create a Cid-v0 from peer-id.
    pub fn from_peer_id_v0(peer_id: PeerId) -> Self {
        Cid::Zero(peer_id.into())
    }

    /// Create a Cid-v1 from peer-id. _codec_ value is implied as
    /// _LIBP2P_KEY_.
    pub fn from_peer_id_v1(base: Base, peer_id: PeerId) -> Self {
        let code = multicodec::LIBP2P_KEY;
        Cid::One(base, code.into(), peer_id.into())
    }

    /// Decode a base encoded CID, human readable text. CID format can
    /// either be in legacy (v0) format or CIDv1 format.
    pub fn from_text(text: &str) -> Result<Cid> {
        let mut chars = text.chars();
        let cid = match (chars.next(), chars.next()) {
            (Some('Q'), Some('m')) | (Some('1'), Some(_)) if text.len() == 46 => {
                // legacy format v0.
                let bytes = {
                    let res = bs58::decode(text.as_bytes()).into_vec();
                    err_at!(ParseError, res)?
                };
                let (mh, _) = Multihash::decode(&bytes)?;
                Cid::Zero(mh)
            }
            (Some('Q'), Some('m')) | (Some('1'), Some(_)) => {
                err_at!(ParseError, msg: format!("{}", text))?
            }
            _ => {
                let (base, bytes) = {
                    let mb = Multibase::from_text(text)?;
                    match mb.to_bytes() {
                        Some(bytes) => (mb.to_base(), bytes),
                        None => err_at!(ParseError, msg: format!("{}", text))?,
                    }
                };
                // <multicodec-cidv1><codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(ParseError, msg: format!("CID {}", codec))?,
                }

                let (content_type, bytes) = Multicodec::decode(bytes)?;
                let (mh, _) = Multihash::decode(bytes)?;
                Cid::One(base, content_type, mh)
            }
        };

        Ok(cid)
    }

    /// Encode in base format. Use the supplied `base`, if none, fall back
    /// to default base used while constructing the Cid.
    ///
    /// * If value is a CIDv0 variant, encoded into legacy base58btc format.
    /// * If value is a CIDv1 variant, encoded using specified base format.
    pub fn to_text(&self, base: Option<Base>) -> Result<String> {
        let text = match self {
            Cid::Zero(mh) => bs58::encode(mh.encode()?).into_string(),
            Cid::One(fallback_base, content_type, mh) => {
                let mut data = {
                    let codec = Multicodec::from_code(multicodec::CID_V1)?;
                    codec.encode()?
                };
                data.extend(content_type.encode()?);
                data.extend(mh.encode()?);
                let base = base.unwrap_or(fallback_base.clone());
                Multibase::with_base(base.clone(), &data)?.to_text()?
            }
        };
        Ok(text)
    }

    /// Decode a binary encoded CID. Refer to [Self::encode] method for details.
    /// Supports both legacy-format and CIDv1-format.
    pub fn decode(bytes: &[u8]) -> Result<(Cid, &[u8])> {
        use multibase::Base::Base32Lower;

        let (cid, bytes) = match bytes {
            [0x12, 0x20, ..] => {
                // legacy format v0.
                let (mh, bytes) = Multihash::decode(&bytes)?;
                (Cid::Zero(mh), bytes)
            }
            _ => {
                // <multicodec-cidv1><codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(DecodeError, msg: format!("CID {}", codec))?,
                }
                let (content_type, bytes) = Multicodec::decode(bytes)?;
                let (mh, bytes) = Multihash::decode(bytes)?;
                (Cid::One(Base32Lower, content_type, mh), bytes)
            }
        };

        Ok((cid, bytes))
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
    /// * _CID-version_ byte
    /// * _codec_, unsigned_varint multicodec value, describing
    ///   multicodec-content-type or format of the data being addressed
    /// * _multihash_, is SHA2-256 of data in Multihash format.
    ///
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = match self {
            Cid::Zero(mh) => mh.encode()?,
            Cid::One(_, content_type, mh) => {
                let mut bytes = {
                    let codec = Multicodec::from_code(multicodec::CID_V1)?;
                    codec.encode()?
                };
                bytes.extend(content_type.encode()?);
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
    pub fn to_base(&self) -> Base {
        match self {
            Cid::Zero(_) => Base::Base58Btc,
            Cid::One(base, _, _) => base.clone(),
        }
    }

    /// Return the content type or format of the data being addressed.
    pub fn to_content_type(&self) -> Multicodec {
        match self {
            Cid::Zero(_) => multicodec::DAG_PB.into(),
            Cid::One(_, content_type, _) => content_type.clone(),
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

    /// If CID is pointing to a peer-id, that is if the content_type is
    /// _LIBP2P_KEY_, return the PeerId value.
    pub fn to_peer_id(&self) -> Option<PeerId> {
        let code = multicodec::LIBP2P_KEY;
        match self {
            Cid::One(_, content_type, mh) if content_type.to_code() == code => {
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
