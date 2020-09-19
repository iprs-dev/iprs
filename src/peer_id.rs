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
/// a. Encode the public key as described in the keys section.
/// b. If the length of the serialized bytes is less than or equal to 42,
///    compute the "identity" multihash of the serialized bytes. In other
///    words, no hashing is performed, but the multihash format is still
///    followed. The idea here is that if the serialized byte array is
///    short enough, we can fit it in a multihash verbatim without having
///    to condense it using a hash function.
/// c. If the length is greater than 42, then hash it using it using the
///    SHA256 multihash.
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

        let code = match enc_buf.len() <= MAX_INLINE_KEY_LENGTH {
            true => multicodec::IDENTITY,
            false => multicodec::SHA2_256,
        };

        let mut mh = Multihash::from_codec(Multicodec::from_code(code)?)?;
        mh.write(&enc_buf)?.finish()?;

        Ok(PeerId { mh })
    }

    /// Checks whether `data` is a valid `PeerId`. If so, returns the
    /// `PeerId`. If not, returns back the data as an error.
    pub fn from_slice(data: &[u8]) -> Result<(PeerId, &[u8])> {
        let (mh, bytes) = Multihash::decode(data)?;
        Ok((PeerId { mh }, bytes))
    }

    /// Tries to turn a `Multihash` into a `PeerId`.
    ///
    /// If the multihash does not use a valid hashing algorithm for peer IDs,
    /// or the hash value does not satisfy the constraints for a hashed
    /// peer ID, it is returned as an `Err`.
    pub fn from_multihash(mh: Multihash) -> Result<PeerId> {
        Ok(PeerId { mh })
    }

    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = err_at!(DecodeError, bs58::decode(s).into_vec())?;
        let (peer_id, _) = PeerId::from_slice(&bytes)?;
        Ok(peer_id)
    }

    /// Generates a random peer ID from a cryptographically secure PRNG.
    ///
    /// This is useful for randomly walking on a DHT, or for testing purposes.
    pub fn generate() -> Result<PeerId> {
        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        let mh = {
            let codec = Multicodec::from_code(multicodec::IDENTITY)?;
            let mut mh = Multihash::from_codec(codec)?;
            mh.write(&bytes)?.finish()?;
            mh
        };
        Ok(PeerId { mh })
    }

    /// Returns a raw bytes representation of this `PeerId`.
    ///
    /// **NOTE:** This byte representation is not necessarily consistent with
    /// equality of peer IDs. That is, two peer IDs may be considered equal
    /// while having a different byte representation as per `into_bytes`.
    pub fn into_bytes(self) -> Result<Vec<u8>> {
        self.mh.encode()
    }

    /// Returns a base-58 encoded string of this `PeerId`.
    pub fn to_base58(&self) -> Result<String> {
        Ok(bs58::encode(self.mh.encode()?).into_string())
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
