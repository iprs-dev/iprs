//! Module implement Peer ID for libp2p network. _Refer [peer-id] spec
//! for details.
//!
//! [peer-id]: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md

use bs58;
use multibase::Base;
use rand::Rng;

use std::{fmt, hash};

use crate::{
    identity::PublicKey,
    multibase::Multibase,
    multicodec::{self, Multicodec},
    multihash::Multihash,
    Error, Result,
};

/// Keys that serialize to more than 42 bytes must be hashed using
/// sha256 multihash, keys that serialize to at most 42 bytes must
/// be hashed using the "identity" multihash codec.
const MAX_INLINE_KEY_LENGTH: usize = 42;

/// Unique identifier of a peer in the network.
///
/// Peer IDs are derived by hashing the encoded public-key with multihash.
///
/// PublicKey to PeerId:
///
/// * Encode the public key as described in the [keys section].
/// * If the length of the serialized bytes is less than or equal to 42,
///   compute the "identity" multihash of the serialized bytes. In other
///   words, no hashing is performed, but the multihash format is still
///   followed. The idea here is that if the serialized byte array is
///   short enough, we can fit it in a multihash verbatim without having
///   to condense it using a hash function.
/// * If the length is greater than 42, then hash it using it using the
///   SHA256 multihash.
///
/// [keys section]: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#keys
#[derive(Clone, Eq)]
pub struct PeerId {
    mh: Multihash,
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PeerId").field(&self.to_base58btc()).finish()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_base58btc() {
            Ok(val) => val.fmt(f),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl hash::Hash for PeerId {
    fn hash<H>(&self, state: &mut H)
    where
        H: hash::Hasher,
    {
        hash::Hash::hash(&self.mh.encode().unwrap(), state)
    }
}

impl PartialEq<PeerId> for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.mh == other.mh
    }
}

impl From<Multihash> for PeerId {
    fn from(mh: Multihash) -> Self {
        PeerId { mh }
    }
}

impl From<PeerId> for Multihash {
    fn from(peer_id: PeerId) -> Self {
        peer_id.mh
    }
}

impl PeerId {
    /// Builds a `PeerId` from a public key.
    pub fn from_public_key(key: PublicKey) -> Result<PeerId> {
        let enc_buf = key.into_protobuf_encoding()?;

        let codec: Multicodec = match enc_buf.len() <= MAX_INLINE_KEY_LENGTH {
            true => multicodec::IDENTITY.into(),
            false => multicodec::SHA2_256.into(),
        };

        let mh = Multihash::new(codec, &enc_buf)?;
        Ok(PeerId { mh })
    }

    /// Generates a random peer ID from a cryptographically secure PRNG.
    ///
    /// This is useful for randomly walking on a DHT, or for testing purposes.
    pub fn generate() -> Result<PeerId> {
        let (bytes, codec) = match rand::thread_rng().gen::<bool>() {
            true => {
                let codec: Multicodec = multicodec::IDENTITY.into();
                let bytes = rand::thread_rng().gen::<[u8; 32]>().to_vec();
                (bytes, codec)
            }
            false => {
                let codec: Multicodec = multicodec::SHA2_256.into();
                let bytes = {
                    let mut data = vec![];
                    data.extend_from_slice(&rand::thread_rng().gen::<[u8; 32]>());
                    data.extend_from_slice(&rand::thread_rng().gen::<[u8; 32]>());
                    data
                };
                (bytes, codec)
            }
        };

        let mh = Multihash::new(codec, &bytes)?;
        Ok(PeerId { mh })
    }

    /// Decode a base encoded PeerId, human readable text. Peerid format
    /// can either be in legacy format (base58btc) or multi-base encoded
    /// CID format.
    pub fn from_text(text: &str) -> Result<PeerId> {
        let mut chars = text.chars();
        let peer_id = match (chars.next(), chars.next()) {
            (Some('Q'), Some('m')) | (Some('1'), Some(_)) => {
                // legacy format base58btc.
                let bytes = err_at!(BadInput, bs58::decode(text.as_bytes()).into_vec())?;
                let (mh, _) = Multihash::decode(&bytes)?;
                PeerId { mh }
            }
            _ => {
                let bytes = {
                    let mb = Multibase::from_text(text)?;
                    match mb.to_bytes() {
                        Some(bytes) => bytes,
                        None => err_at!(BadInput, msg: "{}", text)?,
                    }
                };
                // <multicodec-cidv1><libp2p-key-codec><multihash>
                let (codec, bytes) = Multicodec::decode(&bytes)?;
                match codec.to_code() {
                    multicodec::CID_V1 => (),
                    _ => err_at!(BadInput, msg: "CID {}", codec)?,
                }

                let (codec, bytes) = Multicodec::decode(bytes)?;
                match codec.to_code() {
                    multicodec::LIBP2P_KEY => (),
                    _ => err_at!(BadInput, msg: "codec {}", codec)?,
                }
                let (mh, _) = Multihash::decode(bytes)?;
                PeerId { mh }
            }
        };

        Ok(peer_id)
    }

    /// Encode peer-id to base58btc format.
    pub fn to_base58btc(&self) -> Result<String> {
        Ok(bs58::encode(self.mh.encode()?).into_string())
    }

    /// Encode peer-id to multi-base encoded CID format.
    pub fn to_base_text(&self, base: Base) -> Result<String> {
        let mut data = {
            let codec = Multicodec::from_code(multicodec::CID_V1)?;
            codec.encode()?
        };
        {
            let codec = Multicodec::from_code(multicodec::LIBP2P_KEY)?;
            data.extend_from_slice(&codec.encode()?);
        };
        data.extend_from_slice(&self.mh.encode()?);

        Ok(Multibase::with_base(base.clone(), &data)?.to_text()?)
    }

    /// Encode PeerId into multihash-binary-format.
    ///
    /// **NOTE:** This byte representation is not necessarily consistent
    /// with equality of peer IDs. That is, two peer IDs may be considered
    /// equal while having a different byte representation.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.mh.encode()
    }

    /// Decode PeerId from multihash-binary-format.
    pub fn decode(buf: &[u8]) -> Result<(PeerId, &[u8])> {
        let (mh, rem) = Multihash::decode(buf)?;
        Ok((PeerId { mh }, rem))
    }

    /// Checks whether the public key passed as parameter matches the
    /// public key of this `PeerId`.
    ///
    /// Returns `None` if this `PeerId`s hash algorithm is not supported
    /// when encoding the given public key, otherwise `Some` boolean as the
    /// result of an equality check.
    pub fn is_public_key(&self, public_key: &PublicKey) -> Option<bool> {
        let other = PeerId::from_public_key(public_key.clone()).ok()?;
        Some(self.mh == other.mh)
    }

    /// Return the peer-id as condensed version of PeerID::to_string().
    pub fn to_short_string(&self) -> String {
        use std::iter::FromIterator;

        let s = self.to_string();
        let chars: Vec<char> = s.chars().collect();

        if chars.len() <= 10 {
            String::from_iter(chars.into_iter())
        } else {
            let mut short = chars[..2].to_vec();
            short.push('*');
            short.extend_from_slice(&chars[(chars.len() - 6)..]);
            String::from_iter(short.into_iter())
        }
    }

    /// Sometimes PeerID could be encoded using IDENTITY hash. Which means,
    /// unlike when it is encoded as public-key's hash, it is possible to
    /// extract the public-key from the peer-id.
    pub fn to_public_key(&self) -> Result<Option<PublicKey>> {
        let (codec, digest) = self.mh.clone().unwrap()?;
        let public_key = match codec.to_code() {
            multicodec::IDENTITY => {
                let public_key = PublicKey::from_protobuf_encoding(&digest)?;
                Some(public_key)
            }
            _ => None,
        };

        Ok(public_key)
    }
}

#[cfg(test)]
#[path = "peer_id_test.rs"]
mod peer_id_test;
