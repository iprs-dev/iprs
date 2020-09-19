use bs58;
use rand::Rng;

use std::{fmt, hash};

use crate::{
    identity::PublicKey,
    multicodec::{self, Multicodec},
    multihash::Multihash,
    Error, Result,
};

/// Keys that serialize to more than 42 bytes must be hashed using
/// sha256 multihash, keys that serialize to at most 42 bytes must
/// be hashed using the "identity" multihash codec.
const MAX_INLINE_KEY_LENGTH: usize = 42;

/// Unique identifier of a peer of the network.
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
        f.debug_tuple("PeerId").field(&self.to_base58()).finish()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_base58() {
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

        let mut mh = Multihash::from_codec(codec)?;
        mh.write(&enc_buf)?.finish()?;

        Ok(PeerId { mh })
    }

    /// Generates a random peer ID from a cryptographically secure PRNG.
    ///
    /// This is useful for randomly walking on a DHT, or for testing purposes.
    pub fn generate() -> Result<PeerId> {
        let (bytes, codec) = match rand::thread_rng().gen::<bool>() {
            true => {
                let codec: Multicodec = multicodec::IDENTITY.into();
                (rand::thread_rng().gen::<[u8; 32]>().to_vec(), codec)
            }
            false => {
                let codec: Multicodec = multicodec::SHA2_256.into();
                let bytes = {
                    let mut data = vec![];
                    data.extend(&rand::thread_rng().gen::<[u8; 32]>());
                    data.extend(&rand::thread_rng().gen::<[u8; 32]>());
                    data
                };
                (bytes, codec)
            }
        };
        let mh = {
            let mut mh = Multihash::from_codec(codec)?;
            mh.write(&bytes)?.finish()?;
            mh
        };
        Ok(PeerId { mh })
    }

    /// Encode PeerId into raw bytes representation.
    ///
    /// **NOTE:** This byte representation is not necessarily consistent with
    /// equality of peer IDs. That is, two peer IDs may be considered equal
    /// while having a different byte representation as per `into_bytes`.
    pub fn encode(self) -> Result<Vec<u8>> {
        self.mh.encode()
    }

    /// Decode whether `data` is a valid `PeerId`. If so, returns the
    /// `PeerId`, else error.
    pub fn decode(buf: &[u8]) -> Result<(PeerId, &[u8])> {
        let (mh, rem) = Multihash::decode(buf)?;
        Ok((PeerId { mh }, rem))
    }

    /// Returns a base-58 encoded string of this `PeerId`.
    pub fn to_base58(&self) -> Result<String> {
        Ok(bs58::encode(self.mh.encode()?).into_string())
    }

    /// Convert BASE58 string to PeerId.
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = err_at!(DecodeError, bs58::decode(s).into_vec())?;
        let (peer_id, _) = PeerId::decode(&bytes)?;
        Ok(peer_id)
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
}

#[cfg(test)]
#[path = "peer_id_test.rs"]
mod peer_id_test;
