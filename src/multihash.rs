//! Module adapts several hashing algorithms into multiformat
//! specification.

// TODO:
// 1. For Shake128 and Shake256 algorithm variable output length
//    `d` must be included as part of the spec and API.

use digest::Digest;

use std::{
    cmp,
    io::{self, Read},
};

use crate::{multicodec, Error, Multicodec, Result};

/// Type adapts several hashing algorithms that can be encoded/decoded
/// into/from multi-format/multi-hash.
#[derive(Clone, Eq, PartialEq, PartialOrd)]
pub struct Multihash {
    inner: Inner,
}

#[derive(Clone, Eq, PartialEq, PartialOrd)]
enum Inner {
    Identity(Multicodec, Identity),
    Sha1(Multicodec, Sha1),
    Sha2(Multicodec, Sha2),
    Sha3(Multicodec, Sha3),
    Blake2b(Multicodec, Blake2b),
    Blake2s(Multicodec, Blake2s),
    Blake3(Multicodec, Blake3),
    Md4(Multicodec, Md4),
    Md5(Multicodec, Md5),
    Skein(Multicodec, Skein),
    RipeMd(Multicodec, RipeMd),
}

impl From<Inner> for Multihash {
    fn from(inner: Inner) -> Multihash {
        Multihash { inner }
    }
}

impl Multihash {
    /// Create a Multihash instance to generate hash-digest and encode
    /// them in multi-format.
    pub fn from_codec(codec: Multicodec) -> Result<Multihash> {
        let code = codec.to_code();
        let inner = match code {
            multicodec::IDENTITY => {
                let hasher = Identity::from_code(code)?;
                Inner::Identity(codec, hasher)
            }
            multicodec::SHA1 => {
                let hasher = Sha1::from_code(code)?;
                Inner::Sha1(codec, hasher)
            }
            multicodec::SHA2_256 | multicodec::SHA2_512 | multicodec::DBL_SHA2_256 => {
                let hasher = Sha2::from_code(code)?;
                Inner::Sha2(codec, hasher)
            }
            multicodec::SHA3_512..=multicodec::KECCAK_512 => {
                let hasher = Sha3::from_code(code)?;
                Inner::Sha3(codec, hasher)
            }
            multicodec::BLAKE3 => {
                let hasher = Blake3::from_code(code)?;
                Inner::Blake3(codec, hasher)
            }
            multicodec::BLAKE2B_8..=multicodec::BLAKE2B_512 => {
                let hasher = Blake2b::from_code(code)?;
                Inner::Blake2b(codec, hasher)
            }
            multicodec::BLAKE2S_8..=multicodec::BLAKE2S_256 => {
                let hasher = Blake2s::from_code(code)?;
                Inner::Blake2s(codec, hasher)
            }
            multicodec::MD4 => {
                let hasher = Md4::from_code(code)?;
                Inner::Md4(codec, hasher)
            }
            multicodec::MD5 => {
                let hasher = Md5::from_code(code)?;
                Inner::Md5(codec, hasher)
            }
            multicodec::SKEIN256_8..=multicodec::SKEIN1024_1024 => {
                let hasher = Skein::from_code(code)?;
                Inner::Skein(codec, hasher)
            }
            multicodec::RIPEMD_128..=multicodec::RIPEMD_320 => {
                let hasher = RipeMd::from_code(code)?;
                Inner::RipeMd(codec, hasher)
            }
            // multicodec::SM3_256 => unimplemented!(),
            // multicodec::POSEIDON_BLS12_381_A2_FC1 => unimplemented!(),
            // multicodec::POSEIDON_BLS12_381_A2_FC1_SC => unimplemented!(),
            // multicodec::KANGAROOTWELVE => unimplemented!(),
            // multicodec::X11 => unimplemented!(),
            // multicodec::BMT => unimplemented!(),
            // multicodec::SHA2_256_TRUNC254_PADDED => unimplemented!(),
            codec => err_at!(NotImplemented, msg: format!("codec {}", codec))?,
        };
        Ok(inner.into())
    }

    /// Decode a hash-digest that was encoded using multi-format
    /// specification. Return the Multihash value and remaining byte-slice.
    /// Use the Multihash value to get the hash-digest and hash-algorithm
    /// used to generate the digest.
    pub fn from_slice(buf: &[u8]) -> Result<(Multihash, &[u8])> {
        // <hash-func-type><digest-length><digest-value>
        use unsigned_varint::decode;

        let (codec, digest, rem) = {
            let (codec, rem) = Multicodec::from_slice(buf)?;
            let (n, rem) = err_at!(BadInput, decode::usize(rem))?;
            if n <= rem.len() {
                Ok((codec, &rem[..n], &rem[n..]))
            } else {
                err_at!(BadInput, msg: format!("hash-len {}", n))
            }
        }?;

        let code = codec.to_code();
        let inner = match code {
            multicodec::IDENTITY => {
                let hasher = Identity::from_slice(code, digest)?;
                Inner::Identity(codec, hasher)
            }
            multicodec::SHA1 => {
                let hasher = Sha1::from_slice(code, digest)?;
                Inner::Sha1(codec, hasher)
            }
            multicodec::SHA2_256 | multicodec::SHA2_512 | multicodec::DBL_SHA2_256 => {
                let hasher = Sha2::from_slice(code, digest)?;
                Inner::Sha2(codec, hasher)
            }
            multicodec::SHA3_512..=multicodec::KECCAK_512 => {
                let hasher = Sha3::from_slice(code, digest)?;
                Inner::Sha3(codec, hasher)
            }
            multicodec::BLAKE3 => {
                let hasher = Blake3::from_slice(code, digest)?;
                Inner::Blake3(codec, hasher)
            }
            multicodec::BLAKE2B_8..=multicodec::BLAKE2B_512 => {
                let hasher = Blake2b::from_slice(code, digest)?;
                Inner::Blake2b(codec, hasher)
            }
            multicodec::BLAKE2S_8..=multicodec::BLAKE2S_256 => {
                let hasher = Blake2s::from_slice(code, digest)?;
                Inner::Blake2s(codec, hasher)
            }
            multicodec::MD4 => {
                let hasher = Md4::from_slice(code, digest)?;
                Inner::Md4(codec, hasher)
            }
            multicodec::MD5 => {
                let hasher = Md5::from_slice(code, digest)?;
                Inner::Md5(codec, hasher)
            }
            multicodec::SKEIN256_8..=multicodec::SKEIN1024_1024 => {
                let hasher = Skein::from_slice(code, digest)?;
                Inner::Skein(codec, hasher)
            }
            multicodec::RIPEMD_128..=multicodec::RIPEMD_320 => {
                let hasher = RipeMd::from_slice(code, digest)?;
                Inner::RipeMd(codec, hasher)
            }
            codec => err_at!(NotImplemented, msg: format!("codec {}", codec))?,
        };

        Ok((inner.into(), rem))
    }

    /// Accumulate bytes for which a hash-digest needs to be generated.
    ///
    /// Typical usage:
    ///
    /// ```ignore
    ///     let hasher = Multihash::from_code(multicodec::SHA2_256);
    ///     hasher.write("hello world".as_bytes());
    ///     (codec, digest) = hasher.finish().unwrap();
    /// ```
    ///
    /// To reuse the multihash value, call `reset()` and repeat the process.
    ///
    pub fn write(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.write(bytes)?,
            Inner::Sha1(_, hasher) => hasher.write(bytes)?,
            Inner::Sha2(_, hasher) => hasher.write(bytes)?,
            Inner::Sha3(_, hasher) => hasher.write(bytes)?,
            Inner::Blake3(_, hasher) => hasher.write(bytes)?,
            Inner::Blake2b(_, hasher) => hasher.write(bytes)?,
            Inner::Blake2s(_, hasher) => hasher.write(bytes)?,
            Inner::Md4(_, hasher) => hasher.write(bytes)?,
            Inner::Md5(_, hasher) => hasher.write(bytes)?,
            Inner::Skein(_, hasher) => hasher.write(bytes)?,
            Inner::RipeMd(_, hasher) => hasher.write(bytes)?,
        };
        Ok(self)
    }

    /// Finish accumulating data for generating digest, calling this value
    /// shall actually generate the final digest.
    pub fn finish(&mut self) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.finish()?,
            Inner::Sha1(_, hasher) => hasher.finish()?,
            Inner::Sha2(_, hasher) => hasher.finish()?,
            Inner::Sha3(_, hasher) => hasher.finish()?,
            Inner::Blake3(_, hasher) => hasher.finish()?,
            Inner::Blake2b(_, hasher) => hasher.finish()?,
            Inner::Blake2s(_, hasher) => hasher.finish()?,
            Inner::Md4(_, hasher) => hasher.finish()?,
            Inner::Md5(_, hasher) => hasher.finish()?,
            Inner::Skein(_, hasher) => hasher.finish()?,
            Inner::RipeMd(_, hasher) => hasher.finish()?,
        };
        Ok(self)
    }

    /// Reset to reuse this value for ingesting new data and generate a
    /// new hash digest.
    pub fn reset(&mut self) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.reset()?,
            Inner::Sha1(_, hasher) => hasher.reset()?,
            Inner::Sha2(_, hasher) => hasher.reset()?,
            Inner::Sha3(_, hasher) => hasher.reset()?,
            Inner::Blake3(_, hasher) => hasher.reset()?,
            Inner::Blake2b(_, hasher) => hasher.reset()?,
            Inner::Blake2s(_, hasher) => hasher.reset()?,
            Inner::Md4(_, hasher) => hasher.reset()?,
            Inner::Md5(_, hasher) => hasher.reset()?,
            Inner::Skein(_, hasher) => hasher.reset()?,
            Inner::RipeMd(_, hasher) => hasher.reset()?,
        };
        Ok(self)
    }

    /// Encode hash-digest and associated headers into
    /// multi-format/multi-hash specification.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::default();
        self.encode_with(&mut buf)?;
        Ok(buf)
    }

    /// Similar to encode() but avoid allocation by using supplied buffer
    /// `buf`.
    pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        use unsigned_varint::encode;

        let digest = match &self.inner {
            Inner::Identity(_, hasher) => hasher.as_digest()?,
            Inner::Sha1(_, hasher) => hasher.as_digest()?,
            Inner::Sha2(_, hasher) => hasher.as_digest()?,
            Inner::Sha3(_, hasher) => hasher.as_digest()?,
            Inner::Blake3(_, hasher) => hasher.as_digest()?,
            Inner::Blake2b(_, hasher) => hasher.as_digest()?,
            Inner::Blake2s(_, hasher) => hasher.as_digest()?,
            Inner::Md4(_, hasher) => hasher.as_digest()?,
            Inner::Md5(_, hasher) => hasher.as_digest()?,
            Inner::Skein(_, hasher) => hasher.as_digest()?,
            Inner::RipeMd(_, hasher) => hasher.as_digest()?,
        };
        let n = self.to_codec().encode_with(buf)?;
        let m = {
            #[cfg(not(target_arch = "wasm32"))]
            let mut scratch: [u8; 10] = Default::default();
            #[cfg(target_arch = "wasm32")]
            let mut scratch: [u8; 5] = Default::default();

            let slice = encode::usize(digest.len(), &mut scratch);
            err_at!(IOError, buf.write(slice))?;
            slice.len()
        };
        err_at!(IOError, buf.write(digest))?;
        Ok(n + m + digest.len())
    }

    /// Return the multihash codec.
    pub fn to_codec(&self) -> Multicodec {
        match &self.inner {
            Inner::Identity(codec, _) => codec.clone(),
            Inner::Sha1(codec, _) => codec.clone(),
            Inner::Sha2(codec, _) => codec.clone(),
            Inner::Sha3(codec, _) => codec.clone(),
            Inner::Blake3(codec, _) => codec.clone(),
            Inner::Blake2b(codec, _) => codec.clone(),
            Inner::Blake2s(codec, _) => codec.clone(),
            Inner::Md4(codec, _) => codec.clone(),
            Inner::Md5(codec, _) => codec.clone(),
            Inner::Skein(codec, _) => codec.clone(),
            Inner::RipeMd(codec, _) => codec.clone(),
        }
    }

    /// Unwrap the underlying codec and hash digest. Panic if digest
    /// is not generated or decoded.
    pub fn unwrap(self) -> (Multicodec, Vec<u8>) {
        let digest = match &self.inner {
            Inner::Identity(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha1(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha2(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha3(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Blake3(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Blake2b(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Blake2s(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Md4(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Md5(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Skein(_, hasher) => hasher.as_digest().unwrap(),
            Inner::RipeMd(_, hasher) => hasher.as_digest().unwrap(),
        };
        (self.to_codec(), digest.to_vec())
    }
}

impl io::Write for Multihash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct Identity {
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Identity {}

impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Identity {
    fn partial_cmp(&self, other: &Identity) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Identity {
    fn from_code(_code: u128) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.buf.extend(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.buf.drain(..).collect()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Sha1 {
    hasher: sha1::Sha1,
    digest: Option<Vec<u8>>,
}

impl Eq for Sha1 {}

impl PartialEq for Sha1 {
    fn eq(&self, other: &Sha1) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Sha1 {
    fn partial_cmp(&self, other: &Sha1) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Sha1 {
    fn from_code(_code: u128) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.hasher.finalize_reset().to_vec()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
enum Sha2 {
    Algo32 {
        hasher: sha2::Sha256,
        digest: Option<Vec<u8>>,
        double: bool,
    },
    Algo64 {
        hasher: sha2::Sha512,
        digest: Option<Vec<u8>>,
        double: bool,
    },
}

impl Eq for Sha2 {}

impl PartialEq for Sha2 {
    fn eq(&self, other: &Sha2) -> bool {
        use Sha2::*;

        match (self, other) {
            (Algo32 { digest, .. }, Algo32 { digest: other, .. }) => digest == other,
            (Algo64 { digest, .. }, Algo64 { digest: other, .. }) => digest == other,
            (_, _) => false,
        }
    }
}

impl PartialOrd for Sha2 {
    fn partial_cmp(&self, other: &Sha2) -> Option<cmp::Ordering> {
        use Sha2::*;

        match (self, other) {
            (Algo32 { digest, .. }, Algo32 { digest: other, .. }) => digest.partial_cmp(other),
            (Algo64 { digest, .. }, Algo64 { digest: other, .. }) => digest.partial_cmp(other),
            (_, _) => None,
        }
    }
}

impl Sha2 {
    fn from_code(code: u128) -> Result<Sha2> {
        let digest = None;
        let val = match code {
            multicodec::SHA2_256 => Sha2::Algo32 {
                hasher: sha2::Sha256::new(),
                digest,
                double: false,
            },
            multicodec::DBL_SHA2_256 => Sha2::Algo32 {
                hasher: sha2::Sha256::new(),
                digest,
                double: true,
            },
            multicodec::SHA2_512 => Sha2::Algo64 {
                hasher: sha2::Sha512::new(),
                digest,
                double: false,
            },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Sha2> {
        let val = match code {
            multicodec::SHA2_256 => Sha2::Algo32 {
                hasher: sha2::Sha256::new(),
                digest: Some(digest.to_vec()),
                double: false,
            },
            multicodec::DBL_SHA2_256 => Sha2::Algo32 {
                hasher: sha2::Sha256::new(),
                digest: Some(digest.to_vec()),
                double: true,
            },
            multicodec::SHA2_512 => Sha2::Algo64 {
                hasher: sha2::Sha512::new(),
                digest: Some(digest.to_vec()),
                double: false,
            },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Sha2::Algo32 {
                hasher,
                digest: None,
                ..
            } => hasher.update(bytes),
            Sha2::Algo64 {
                hasher,
                digest: None,
                ..
            } => hasher.update(bytes),
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        match self {
            Sha2::Algo32 {
                hasher,
                digest: digest @ None,
                double: false,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha2::Algo64 {
                hasher,
                digest: digest @ None,
                double: false,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha2::Algo32 {
                hasher,
                digest: digest @ None,
                double: true,
            } => {
                *digest = {
                    let hash = hasher.finalize_reset().as_slice().to_vec();
                    hasher.update(&hash);
                    Some(hasher.finalize_reset().as_slice().to_vec())
                };
            }
            Sha2::Algo64 {
                hasher,
                digest: digest @ None,
                double: true,
            } => {
                *digest = {
                    let hash = hasher.finalize_reset().as_slice().to_vec();
                    hasher.update(&hash);
                    Some(hasher.finalize_reset().as_slice().to_vec())
                };
            }
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let digest = match self {
            Sha2::Algo32 { digest, .. } => digest,
            Sha2::Algo64 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match self {
            Sha2::Algo32 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha2::Algo64 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
enum Sha3 {
    Sha3_224 {
        hasher: sha3::Sha3_224,
        digest: Option<Vec<u8>>,
    },
    Sha3_256 {
        hasher: sha3::Sha3_256,
        digest: Option<Vec<u8>>,
    },
    Sha3_384 {
        hasher: sha3::Sha3_384,
        digest: Option<Vec<u8>>,
    },
    Sha3_512 {
        hasher: sha3::Sha3_512,
        digest: Option<Vec<u8>>,
    },
    Shake128 {
        hasher: sha3::Shake128,
        digest: Option<Vec<u8>>,
    },
    Shake256 {
        hasher: sha3::Shake256,
        digest: Option<Vec<u8>>,
    },
    Keccak224 {
        hasher: sha3::Keccak224,
        digest: Option<Vec<u8>>,
    },
    Keccak256 {
        hasher: sha3::Keccak256,
        digest: Option<Vec<u8>>,
    },
    Keccak384 {
        hasher: sha3::Keccak384,
        digest: Option<Vec<u8>>,
    },
    Keccak512 {
        hasher: sha3::Keccak512,
        digest: Option<Vec<u8>>,
    },
}

impl Eq for Sha3 {}

impl PartialEq for Sha3 {
    fn eq(&self, other: &Sha3) -> bool {
        use Sha3::*;

        match (self, other) {
            (Sha3_224 { digest, .. }, Sha3_224 { digest: other, .. }) => digest == other,
            (Sha3_256 { digest, .. }, Sha3_256 { digest: other, .. }) => digest == other,
            (Sha3_384 { digest, .. }, Sha3_384 { digest: other, .. }) => digest == other,
            (Sha3_512 { digest, .. }, Sha3_512 { digest: other, .. }) => digest == other,
            (Shake128 { digest, .. }, Shake128 { digest: other, .. }) => digest == other,
            (Shake256 { digest, .. }, Shake256 { digest: other, .. }) => digest == other,
            (Keccak224 { digest, .. }, Keccak224 { digest: other, .. }) => digest == other,
            (Keccak256 { digest, .. }, Keccak256 { digest: other, .. }) => digest == other,
            (Keccak384 { digest, .. }, Keccak384 { digest: other, .. }) => digest == other,
            (Keccak512 { digest, .. }, Keccak512 { digest: other, .. }) => digest == other,
            (_, _) => false,
        }
    }
}

impl PartialOrd for Sha3 {
    fn partial_cmp(&self, other: &Sha3) -> Option<cmp::Ordering> {
        use Sha3::*;

        match (self, other) {
            (Sha3_224 { digest, .. }, Sha3_224 { digest: other, .. }) => digest.partial_cmp(other),
            (Sha3_256 { digest, .. }, Sha3_256 { digest: other, .. }) => digest.partial_cmp(other),
            (Sha3_384 { digest, .. }, Sha3_384 { digest: other, .. }) => digest.partial_cmp(other),
            (Sha3_512 { digest, .. }, Sha3_512 { digest: other, .. }) => digest.partial_cmp(other),
            (Shake128 { digest, .. }, Shake128 { digest: other, .. }) => digest.partial_cmp(other),
            (Shake256 { digest, .. }, Shake256 { digest: other, .. }) => digest.partial_cmp(other),
            (Keccak224 { digest, .. }, Keccak224 { digest: other, .. }) => {
                digest.partial_cmp(other)
            }
            (Keccak256 { digest, .. }, Keccak256 { digest: other, .. }) => {
                digest.partial_cmp(other)
            }
            (Keccak384 { digest, .. }, Keccak384 { digest: other, .. }) => {
                digest.partial_cmp(other)
            }
            (Keccak512 { digest, .. }, Keccak512 { digest: other, .. }) => {
                digest.partial_cmp(other)
            }
            (_, _) => None,
        }
    }
}

impl Sha3 {
    fn from_code(code: u128) -> Result<Sha3> {
        let digest = None;
        let val = match code {
            multicodec::SHA3_512 => {
                let hasher = sha3::Sha3_512::new();
                Sha3::Sha3_512 { hasher, digest }
            }
            multicodec::SHA3_384 => {
                let hasher = sha3::Sha3_384::new();
                Sha3::Sha3_384 { hasher, digest }
            }
            multicodec::SHA3_256 => {
                let hasher = sha3::Sha3_256::new();
                Sha3::Sha3_256 { hasher, digest }
            }
            multicodec::SHA3_224 => {
                let hasher = sha3::Sha3_224::new();
                Sha3::Sha3_224 { hasher, digest }
            }
            multicodec::SHAKE_128 => {
                let hasher = sha3::Shake128::default();
                Sha3::Shake128 { hasher, digest }
            }
            multicodec::SHAKE_256 => {
                let hasher = sha3::Shake256::default();
                Sha3::Shake256 { hasher, digest }
            }
            multicodec::KECCAK_224 => {
                let hasher = sha3::Keccak224::new();
                Sha3::Keccak224 { hasher, digest }
            }
            multicodec::KECCAK_256 => {
                let hasher = sha3::Keccak256::new();
                Sha3::Keccak256 { hasher, digest }
            }
            multicodec::KECCAK_384 => {
                let hasher = sha3::Keccak384::new();
                Sha3::Keccak384 { hasher, digest }
            }
            multicodec::KECCAK_512 => {
                let hasher = sha3::Keccak512::new();
                Sha3::Keccak512 { hasher, digest }
            }
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Sha3> {
        let val = match code {
            multicodec::SHA3_512 => Sha3::Sha3_512 {
                hasher: sha3::Sha3_512::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHA3_384 => Sha3::Sha3_384 {
                hasher: sha3::Sha3_384::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHA3_256 => Sha3::Sha3_256 {
                hasher: sha3::Sha3_256::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHA3_224 => Sha3::Sha3_224 {
                hasher: sha3::Sha3_224::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHAKE_128 => Sha3::Shake128 {
                hasher: sha3::Shake128::default(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHAKE_256 => Sha3::Shake256 {
                hasher: sha3::Shake256::default(),
                digest: Some(digest.to_vec()),
            },
            multicodec::KECCAK_224 => Sha3::Keccak224 {
                hasher: sha3::Keccak224::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::KECCAK_256 => Sha3::Keccak256 {
                hasher: sha3::Keccak256::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::KECCAK_384 => Sha3::Keccak384 {
                hasher: sha3::Keccak384::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::KECCAK_512 => Sha3::Keccak512 {
                hasher: sha3::Keccak512::new(),
                digest: Some(digest.to_vec()),
            },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Sha3::Sha3_224 {
                hasher,
                digest: None,
            } => {
                <sha3::Sha3_224 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Sha3_256 {
                hasher,
                digest: None,
            } => {
                <sha3::Sha3_256 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Sha3_384 {
                hasher,
                digest: None,
            } => {
                <sha3::Sha3_384 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Sha3_512 {
                hasher,
                digest: None,
            } => {
                <sha3::Sha3_512 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Shake128 {
                hasher,
                digest: None,
            } => {
                <sha3::Shake128 as digest::Update>::update(hasher, bytes);
            }
            Sha3::Shake256 {
                hasher,
                digest: None,
            } => {
                <sha3::Shake256 as digest::Update>::update(hasher, bytes);
            }
            Sha3::Keccak224 {
                hasher,
                digest: None,
            } => {
                <sha3::Keccak224 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Keccak256 {
                hasher,
                digest: None,
            } => {
                <sha3::Keccak256 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Keccak384 {
                hasher,
                digest: None,
            } => {
                <sha3::Keccak384 as digest::Digest>::update(hasher, bytes);
            }
            Sha3::Keccak512 {
                hasher,
                digest: None,
            } => {
                <sha3::Keccak512 as digest::Digest>::update(hasher, bytes);
            }
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        use digest::ExtendableOutput;

        match self {
            Sha3::Sha3_224 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Sha3_256 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Sha3_384 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Sha3_512 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Shake128 {
                hasher,
                digest: digest @ None,
            } => {
                let mut buf = Vec::default();
                let mut xof = hasher.finalize_xof_reset();
                err_at!(IOError, xof.read_to_end(&mut buf))?;
                *digest = Some(buf);
            }
            Sha3::Shake256 {
                hasher,
                digest: digest @ None,
            } => {
                let mut buf = Vec::default();
                let mut xof = hasher.finalize_xof_reset();
                err_at!(IOError, xof.read_to_end(&mut buf))?;
                *digest = Some(buf)
            }
            Sha3::Keccak224 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Keccak256 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Keccak384 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha3::Keccak512 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let digest = match self {
            Sha3::Sha3_224 { digest, .. } => digest,
            Sha3::Sha3_256 { digest, .. } => digest,
            Sha3::Sha3_384 { digest, .. } => digest,
            Sha3::Sha3_512 { digest, .. } => digest,
            Sha3::Shake128 { digest, .. } => digest,
            Sha3::Shake256 { digest, .. } => digest,
            Sha3::Keccak224 { digest, .. } => digest,
            Sha3::Keccak256 { digest, .. } => digest,
            Sha3::Keccak384 { digest, .. } => digest,
            Sha3::Keccak512 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match self {
            Sha3::Sha3_224 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Sha3_256 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Sha3_384 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Sha3_512 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Shake128 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Shake256 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Keccak224 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Keccak256 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Keccak384 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha3::Keccak512 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Blake3 {
    hasher: blake3::Hasher,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake3 {}

impl PartialEq for Blake3 {
    fn eq(&self, other: &Blake3) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Blake3 {
    fn partial_cmp(&self, other: &Blake3) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Blake3 {
    fn from_code(_code: u128) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => {
                let hash = blake3::Hasher::finalize(&self.hasher);
                Some(hash.as_bytes().to_vec())
            }
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Blake2b {
    code: u128,
    hasher: blake2b_simd::State,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake2b {}

impl PartialEq for Blake2b {
    fn eq(&self, other: &Blake2b) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Blake2b {
    fn partial_cmp(&self, other: &Blake2b) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Blake2b {
    fn to_digest_bits(code: u128) -> Result<usize> {
        let len = match code {
            multicodec::BLAKE2B_8 => 8,
            multicodec::BLAKE2B_16 => 16,
            multicodec::BLAKE2B_24 => 24,
            multicodec::BLAKE2B_32 => 32,
            multicodec::BLAKE2B_40 => 40,
            multicodec::BLAKE2B_48 => 48,
            multicodec::BLAKE2B_56 => 56,
            multicodec::BLAKE2B_64 => 64,
            multicodec::BLAKE2B_72 => 72,
            multicodec::BLAKE2B_80 => 80,
            multicodec::BLAKE2B_88 => 88,
            multicodec::BLAKE2B_96 => 96,
            multicodec::BLAKE2B_104 => 104,
            multicodec::BLAKE2B_112 => 112,
            multicodec::BLAKE2B_120 => 120,
            multicodec::BLAKE2B_128 => 128,
            multicodec::BLAKE2B_136 => 136,
            multicodec::BLAKE2B_144 => 144,
            multicodec::BLAKE2B_152 => 152,
            multicodec::BLAKE2B_160 => 160,
            multicodec::BLAKE2B_168 => 168,
            multicodec::BLAKE2B_176 => 176,
            multicodec::BLAKE2B_184 => 184,
            multicodec::BLAKE2B_192 => 192,
            multicodec::BLAKE2B_200 => 200,
            multicodec::BLAKE2B_208 => 208,
            multicodec::BLAKE2B_216 => 216,
            multicodec::BLAKE2B_224 => 224,
            multicodec::BLAKE2B_232 => 232,
            multicodec::BLAKE2B_240 => 240,
            multicodec::BLAKE2B_248 => 248,
            multicodec::BLAKE2B_256 => 256,
            multicodec::BLAKE2B_264 => 264,
            multicodec::BLAKE2B_272 => 272,
            multicodec::BLAKE2B_280 => 280,
            multicodec::BLAKE2B_288 => 288,
            multicodec::BLAKE2B_296 => 296,
            multicodec::BLAKE2B_304 => 304,
            multicodec::BLAKE2B_312 => 312,
            multicodec::BLAKE2B_320 => 320,
            multicodec::BLAKE2B_328 => 328,
            multicodec::BLAKE2B_336 => 336,
            multicodec::BLAKE2B_344 => 344,
            multicodec::BLAKE2B_352 => 352,
            multicodec::BLAKE2B_360 => 360,
            multicodec::BLAKE2B_368 => 368,
            multicodec::BLAKE2B_376 => 376,
            multicodec::BLAKE2B_384 => 384,
            multicodec::BLAKE2B_392 => 392,
            multicodec::BLAKE2B_400 => 400,
            multicodec::BLAKE2B_408 => 408,
            multicodec::BLAKE2B_416 => 416,
            multicodec::BLAKE2B_424 => 424,
            multicodec::BLAKE2B_432 => 432,
            multicodec::BLAKE2B_440 => 440,
            multicodec::BLAKE2B_448 => 448,
            multicodec::BLAKE2B_456 => 456,
            multicodec::BLAKE2B_464 => 464,
            multicodec::BLAKE2B_472 => 472,
            multicodec::BLAKE2B_480 => 480,
            multicodec::BLAKE2B_488 => 488,
            multicodec::BLAKE2B_496 => 496,
            multicodec::BLAKE2B_504 => 504,
            multicodec::BLAKE2B_512 => 512,
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(len)
    }

    fn from_code(code: u128) -> Result<Blake2b> {
        use blake2b_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2b {
            code,
            hasher: hasher.to_state(),
            digest: None,
        })
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Blake2b> {
        use blake2b_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2b {
            code,
            hasher: hasher.to_state(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.hasher.finalize().as_bytes().to_vec()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        use blake2b_simd::Params;

        self.hasher = {
            let mut hasher = Params::new();
            hasher.hash_length(Self::to_digest_bits(self.code)?);
            hasher.to_state()
        };
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Blake2s {
    code: u128,
    hasher: blake2s_simd::State,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake2s {}

impl PartialEq for Blake2s {
    fn eq(&self, other: &Blake2s) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Blake2s {
    fn partial_cmp(&self, other: &Blake2s) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Blake2s {
    fn to_digest_bits(code: u128) -> Result<usize> {
        let len = match code {
            multicodec::BLAKE2S_8 => 8,
            multicodec::BLAKE2S_16 => 16,
            multicodec::BLAKE2S_24 => 24,
            multicodec::BLAKE2S_32 => 32,
            multicodec::BLAKE2S_40 => 40,
            multicodec::BLAKE2S_48 => 48,
            multicodec::BLAKE2S_56 => 56,
            multicodec::BLAKE2S_64 => 64,
            multicodec::BLAKE2S_72 => 72,
            multicodec::BLAKE2S_80 => 80,
            multicodec::BLAKE2S_88 => 88,
            multicodec::BLAKE2S_96 => 96,
            multicodec::BLAKE2S_104 => 104,
            multicodec::BLAKE2S_112 => 112,
            multicodec::BLAKE2S_120 => 120,
            multicodec::BLAKE2S_128 => 128,
            multicodec::BLAKE2S_136 => 136,
            multicodec::BLAKE2S_144 => 144,
            multicodec::BLAKE2S_152 => 152,
            multicodec::BLAKE2S_160 => 160,
            multicodec::BLAKE2S_168 => 168,
            multicodec::BLAKE2S_176 => 176,
            multicodec::BLAKE2S_184 => 184,
            multicodec::BLAKE2S_192 => 192,
            multicodec::BLAKE2S_200 => 200,
            multicodec::BLAKE2S_208 => 208,
            multicodec::BLAKE2S_216 => 216,
            multicodec::BLAKE2S_224 => 224,
            multicodec::BLAKE2S_232 => 232,
            multicodec::BLAKE2S_240 => 240,
            multicodec::BLAKE2S_248 => 248,
            multicodec::BLAKE2S_256 => 256,
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(len)
    }

    fn from_code(code: u128) -> Result<Blake2s> {
        use blake2s_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2s {
            code,
            hasher: hasher.to_state(),
            digest: None,
        })
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Blake2s> {
        use blake2s_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2s {
            code,
            hasher: hasher.to_state(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.hasher.finalize().as_bytes().to_vec()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        use blake2s_simd::Params;

        self.hasher = {
            let mut hasher = Params::new();
            hasher.hash_length(Self::to_digest_bits(self.code)?);
            hasher.to_state()
        };
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Md4 {
    hasher: md4::Md4,
    digest: Option<Vec<u8>>,
}

impl Eq for Md4 {}

impl PartialEq for Md4 {
    fn eq(&self, other: &Md4) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Md4 {
    fn partial_cmp(&self, other: &Md4) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Md4 {
    fn from_code(_code: u128) -> Result<Md4> {
        Ok(Md4 {
            hasher: md4::Md4::new(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, buf: &[u8]) -> Result<Md4> {
        Ok(Md4 {
            hasher: md4::Md4::new(),
            digest: Some(buf.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.hasher.finalize_reset().to_vec()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Md5 {
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Md5 {}

impl PartialEq for Md5 {
    fn eq(&self, other: &Md5) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Md5 {
    fn partial_cmp(&self, other: &Md5) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

impl Md5 {
    fn from_code(_code: u128) -> Result<Md5> {
        Ok(Md5 {
            buf: Vec::default(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, buf: &[u8]) -> Result<Md5> {
        Ok(Md5 {
            buf: Vec::default(),
            digest: Some(buf.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.buf.extend(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => {
                let digest: [u8; 16] = md5::compute(&self.buf).into();
                Some(digest.to_vec())
            }
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
struct Skein {
    code: u128,
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Skein {}

impl PartialEq for Skein {
    fn eq(&self, other: &Skein) -> bool {
        self.digest == other.digest
    }
}

impl PartialOrd for Skein {
    fn partial_cmp(&self, other: &Skein) -> Option<cmp::Ordering> {
        self.digest.partial_cmp(&other.digest)
    }
}

macro_rules! skein_digest {
    ($type:ident, $dtype:ty, $data:expr) => {{
        use skein_hash::Digest;

        let mut hasher: skein_hash::$type<$dtype> = Default::default();
        hasher.input($data);
        hasher.result().to_vec()
    }};
}

impl Skein {
    fn from_code(code: u128) -> Result<Skein> {
        Ok(Skein {
            code,
            buf: Vec::default(),
            digest: None,
        })
    }

    fn from_slice(code: u128, buf: &[u8]) -> Result<Skein> {
        Ok(Skein {
            code,
            buf: Vec::default(),
            digest: Some(buf.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.buf.extend(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        use digest::consts;

        let digest = match &self.digest {
            None => match self.code {
                multicodec::SKEIN256_8 => skein_digest!(Skein256, consts::U8, &self.buf),
                multicodec::SKEIN256_16 => skein_digest!(Skein256, consts::U16, &self.buf),
                multicodec::SKEIN256_24 => skein_digest!(Skein256, consts::U24, &self.buf),
                multicodec::SKEIN256_32 => skein_digest!(Skein256, consts::U32, &self.buf),
                multicodec::SKEIN256_40 => skein_digest!(Skein256, consts::U40, &self.buf),
                multicodec::SKEIN256_48 => skein_digest!(Skein256, consts::U48, &self.buf),
                multicodec::SKEIN256_56 => skein_digest!(Skein256, consts::U56, &self.buf),
                multicodec::SKEIN256_64 => skein_digest!(Skein256, consts::U64, &self.buf),
                multicodec::SKEIN256_72 => skein_digest!(Skein256, consts::U72, &self.buf),
                multicodec::SKEIN256_80 => skein_digest!(Skein256, consts::U80, &self.buf),
                multicodec::SKEIN256_88 => skein_digest!(Skein256, consts::U88, &self.buf),
                multicodec::SKEIN256_96 => skein_digest!(Skein256, consts::U96, &self.buf),
                multicodec::SKEIN256_104 => skein_digest!(Skein256, consts::U104, &self.buf),
                multicodec::SKEIN256_112 => skein_digest!(Skein256, consts::U112, &self.buf),
                multicodec::SKEIN256_120 => skein_digest!(Skein256, consts::U120, &self.buf),
                multicodec::SKEIN256_128 => skein_digest!(Skein256, consts::U128, &self.buf),
                multicodec::SKEIN256_136 => skein_digest!(Skein256, consts::U136, &self.buf),
                multicodec::SKEIN256_144 => skein_digest!(Skein256, consts::U144, &self.buf),
                multicodec::SKEIN256_152 => skein_digest!(Skein256, consts::U152, &self.buf),
                multicodec::SKEIN256_160 => skein_digest!(Skein256, consts::U160, &self.buf),
                multicodec::SKEIN256_168 => skein_digest!(Skein256, consts::U168, &self.buf),
                multicodec::SKEIN256_176 => skein_digest!(Skein256, consts::U176, &self.buf),
                multicodec::SKEIN256_184 => skein_digest!(Skein256, consts::U184, &self.buf),
                multicodec::SKEIN256_192 => skein_digest!(Skein256, consts::U192, &self.buf),
                multicodec::SKEIN256_200 => skein_digest!(Skein256, consts::U200, &self.buf),
                multicodec::SKEIN256_208 => skein_digest!(Skein256, consts::U208, &self.buf),
                multicodec::SKEIN256_216 => skein_digest!(Skein256, consts::U216, &self.buf),
                multicodec::SKEIN256_224 => skein_digest!(Skein256, consts::U224, &self.buf),
                multicodec::SKEIN256_232 => skein_digest!(Skein256, consts::U232, &self.buf),
                multicodec::SKEIN256_240 => skein_digest!(Skein256, consts::U240, &self.buf),
                multicodec::SKEIN256_248 => skein_digest!(Skein256, consts::U248, &self.buf),
                multicodec::SKEIN256_256 => skein_digest!(Skein256, consts::U256, &self.buf),
                multicodec::SKEIN512_8 => skein_digest!(Skein512, consts::U8, &self.buf),
                multicodec::SKEIN512_16 => skein_digest!(Skein512, consts::U16, &self.buf),
                multicodec::SKEIN512_24 => skein_digest!(Skein512, consts::U24, &self.buf),
                multicodec::SKEIN512_32 => skein_digest!(Skein512, consts::U32, &self.buf),
                multicodec::SKEIN512_40 => skein_digest!(Skein512, consts::U40, &self.buf),
                multicodec::SKEIN512_48 => skein_digest!(Skein512, consts::U48, &self.buf),
                multicodec::SKEIN512_56 => skein_digest!(Skein512, consts::U56, &self.buf),
                multicodec::SKEIN512_64 => skein_digest!(Skein512, consts::U64, &self.buf),
                multicodec::SKEIN512_72 => skein_digest!(Skein512, consts::U72, &self.buf),
                multicodec::SKEIN512_80 => skein_digest!(Skein512, consts::U80, &self.buf),
                multicodec::SKEIN512_88 => skein_digest!(Skein512, consts::U88, &self.buf),
                multicodec::SKEIN512_96 => skein_digest!(Skein512, consts::U96, &self.buf),
                multicodec::SKEIN512_104 => skein_digest!(Skein512, consts::U104, &self.buf),
                multicodec::SKEIN512_112 => skein_digest!(Skein512, consts::U112, &self.buf),
                multicodec::SKEIN512_120 => skein_digest!(Skein512, consts::U120, &self.buf),
                multicodec::SKEIN512_128 => skein_digest!(Skein512, consts::U128, &self.buf),
                multicodec::SKEIN512_136 => skein_digest!(Skein512, consts::U136, &self.buf),
                multicodec::SKEIN512_144 => skein_digest!(Skein512, consts::U144, &self.buf),
                multicodec::SKEIN512_152 => skein_digest!(Skein512, consts::U152, &self.buf),
                multicodec::SKEIN512_160 => skein_digest!(Skein512, consts::U160, &self.buf),
                multicodec::SKEIN512_168 => skein_digest!(Skein512, consts::U168, &self.buf),
                multicodec::SKEIN512_176 => skein_digest!(Skein512, consts::U176, &self.buf),
                multicodec::SKEIN512_184 => skein_digest!(Skein512, consts::U184, &self.buf),
                multicodec::SKEIN512_192 => skein_digest!(Skein512, consts::U192, &self.buf),
                multicodec::SKEIN512_200 => skein_digest!(Skein512, consts::U200, &self.buf),
                multicodec::SKEIN512_208 => skein_digest!(Skein512, consts::U208, &self.buf),
                multicodec::SKEIN512_216 => skein_digest!(Skein512, consts::U216, &self.buf),
                multicodec::SKEIN512_224 => skein_digest!(Skein512, consts::U224, &self.buf),
                multicodec::SKEIN512_232 => skein_digest!(Skein512, consts::U232, &self.buf),
                multicodec::SKEIN512_240 => skein_digest!(Skein512, consts::U240, &self.buf),
                multicodec::SKEIN512_248 => skein_digest!(Skein512, consts::U248, &self.buf),
                multicodec::SKEIN512_256 => skein_digest!(Skein512, consts::U256, &self.buf),
                multicodec::SKEIN512_264 => skein_digest!(Skein512, consts::U264, &self.buf),
                multicodec::SKEIN512_272 => skein_digest!(Skein512, consts::U272, &self.buf),
                multicodec::SKEIN512_280 => skein_digest!(Skein512, consts::U280, &self.buf),
                multicodec::SKEIN512_288 => skein_digest!(Skein512, consts::U288, &self.buf),
                multicodec::SKEIN512_296 => skein_digest!(Skein512, consts::U296, &self.buf),
                multicodec::SKEIN512_304 => skein_digest!(Skein512, consts::U304, &self.buf),
                multicodec::SKEIN512_312 => skein_digest!(Skein512, consts::U312, &self.buf),
                multicodec::SKEIN512_320 => skein_digest!(Skein512, consts::U320, &self.buf),
                multicodec::SKEIN512_328 => skein_digest!(Skein512, consts::U328, &self.buf),
                multicodec::SKEIN512_336 => skein_digest!(Skein512, consts::U336, &self.buf),
                multicodec::SKEIN512_344 => skein_digest!(Skein512, consts::U344, &self.buf),
                multicodec::SKEIN512_352 => skein_digest!(Skein512, consts::U352, &self.buf),
                multicodec::SKEIN512_360 => skein_digest!(Skein512, consts::U360, &self.buf),
                multicodec::SKEIN512_368 => skein_digest!(Skein512, consts::U368, &self.buf),
                multicodec::SKEIN512_376 => skein_digest!(Skein512, consts::U376, &self.buf),
                multicodec::SKEIN512_384 => skein_digest!(Skein512, consts::U384, &self.buf),
                multicodec::SKEIN512_392 => skein_digest!(Skein512, consts::U392, &self.buf),
                multicodec::SKEIN512_400 => skein_digest!(Skein512, consts::U400, &self.buf),
                multicodec::SKEIN512_408 => skein_digest!(Skein512, consts::U408, &self.buf),
                multicodec::SKEIN512_416 => skein_digest!(Skein512, consts::U416, &self.buf),
                multicodec::SKEIN512_424 => skein_digest!(Skein512, consts::U424, &self.buf),
                multicodec::SKEIN512_432 => skein_digest!(Skein512, consts::U432, &self.buf),
                multicodec::SKEIN512_440 => skein_digest!(Skein512, consts::U440, &self.buf),
                multicodec::SKEIN512_448 => skein_digest!(Skein512, consts::U448, &self.buf),
                multicodec::SKEIN512_456 => skein_digest!(Skein512, consts::U456, &self.buf),
                multicodec::SKEIN512_464 => skein_digest!(Skein512, consts::U464, &self.buf),
                multicodec::SKEIN512_472 => skein_digest!(Skein512, consts::U472, &self.buf),
                multicodec::SKEIN512_480 => skein_digest!(Skein512, consts::U480, &self.buf),
                multicodec::SKEIN512_488 => skein_digest!(Skein512, consts::U488, &self.buf),
                multicodec::SKEIN512_496 => skein_digest!(Skein512, consts::U496, &self.buf),
                multicodec::SKEIN512_504 => skein_digest!(Skein512, consts::U504, &self.buf),
                multicodec::SKEIN512_512 => skein_digest!(Skein512, consts::U512, &self.buf),
                multicodec::SKEIN1024_8 => skein_digest!(Skein1024, consts::U8, &self.buf),
                multicodec::SKEIN1024_16 => skein_digest!(Skein1024, consts::U16, &self.buf),
                multicodec::SKEIN1024_24 => skein_digest!(Skein1024, consts::U24, &self.buf),
                multicodec::SKEIN1024_32 => skein_digest!(Skein1024, consts::U32, &self.buf),
                multicodec::SKEIN1024_40 => skein_digest!(Skein1024, consts::U40, &self.buf),
                multicodec::SKEIN1024_48 => skein_digest!(Skein1024, consts::U48, &self.buf),
                multicodec::SKEIN1024_56 => skein_digest!(Skein1024, consts::U56, &self.buf),
                multicodec::SKEIN1024_64 => skein_digest!(Skein1024, consts::U64, &self.buf),
                multicodec::SKEIN1024_72 => skein_digest!(Skein1024, consts::U72, &self.buf),
                multicodec::SKEIN1024_80 => skein_digest!(Skein1024, consts::U80, &self.buf),
                multicodec::SKEIN1024_88 => skein_digest!(Skein1024, consts::U88, &self.buf),
                multicodec::SKEIN1024_96 => skein_digest!(Skein1024, consts::U96, &self.buf),
                multicodec::SKEIN1024_104 => skein_digest!(Skein1024, consts::U104, &self.buf),
                multicodec::SKEIN1024_112 => skein_digest!(Skein1024, consts::U112, &self.buf),
                multicodec::SKEIN1024_120 => skein_digest!(Skein1024, consts::U120, &self.buf),
                multicodec::SKEIN1024_128 => skein_digest!(Skein1024, consts::U128, &self.buf),
                multicodec::SKEIN1024_136 => skein_digest!(Skein1024, consts::U136, &self.buf),
                multicodec::SKEIN1024_144 => skein_digest!(Skein1024, consts::U144, &self.buf),
                multicodec::SKEIN1024_152 => skein_digest!(Skein1024, consts::U152, &self.buf),
                multicodec::SKEIN1024_160 => skein_digest!(Skein1024, consts::U160, &self.buf),
                multicodec::SKEIN1024_168 => skein_digest!(Skein1024, consts::U168, &self.buf),
                multicodec::SKEIN1024_176 => skein_digest!(Skein1024, consts::U176, &self.buf),
                multicodec::SKEIN1024_184 => skein_digest!(Skein1024, consts::U184, &self.buf),
                multicodec::SKEIN1024_192 => skein_digest!(Skein1024, consts::U192, &self.buf),
                multicodec::SKEIN1024_200 => skein_digest!(Skein1024, consts::U200, &self.buf),
                multicodec::SKEIN1024_208 => skein_digest!(Skein1024, consts::U208, &self.buf),
                multicodec::SKEIN1024_216 => skein_digest!(Skein1024, consts::U216, &self.buf),
                multicodec::SKEIN1024_224 => skein_digest!(Skein1024, consts::U224, &self.buf),
                multicodec::SKEIN1024_232 => skein_digest!(Skein1024, consts::U232, &self.buf),
                multicodec::SKEIN1024_240 => skein_digest!(Skein1024, consts::U240, &self.buf),
                multicodec::SKEIN1024_248 => skein_digest!(Skein1024, consts::U248, &self.buf),
                multicodec::SKEIN1024_256 => skein_digest!(Skein1024, consts::U256, &self.buf),
                multicodec::SKEIN1024_264 => skein_digest!(Skein1024, consts::U264, &self.buf),
                multicodec::SKEIN1024_272 => skein_digest!(Skein1024, consts::U272, &self.buf),
                multicodec::SKEIN1024_280 => skein_digest!(Skein1024, consts::U280, &self.buf),
                multicodec::SKEIN1024_288 => skein_digest!(Skein1024, consts::U288, &self.buf),
                multicodec::SKEIN1024_296 => skein_digest!(Skein1024, consts::U296, &self.buf),
                multicodec::SKEIN1024_304 => skein_digest!(Skein1024, consts::U304, &self.buf),
                multicodec::SKEIN1024_312 => skein_digest!(Skein1024, consts::U312, &self.buf),
                multicodec::SKEIN1024_320 => skein_digest!(Skein1024, consts::U320, &self.buf),
                multicodec::SKEIN1024_328 => skein_digest!(Skein1024, consts::U328, &self.buf),
                multicodec::SKEIN1024_336 => skein_digest!(Skein1024, consts::U336, &self.buf),
                multicodec::SKEIN1024_344 => skein_digest!(Skein1024, consts::U344, &self.buf),
                multicodec::SKEIN1024_352 => skein_digest!(Skein1024, consts::U352, &self.buf),
                multicodec::SKEIN1024_360 => skein_digest!(Skein1024, consts::U360, &self.buf),
                multicodec::SKEIN1024_368 => skein_digest!(Skein1024, consts::U368, &self.buf),
                multicodec::SKEIN1024_376 => skein_digest!(Skein1024, consts::U376, &self.buf),
                multicodec::SKEIN1024_384 => skein_digest!(Skein1024, consts::U384, &self.buf),
                multicodec::SKEIN1024_392 => skein_digest!(Skein1024, consts::U392, &self.buf),
                multicodec::SKEIN1024_400 => skein_digest!(Skein1024, consts::U400, &self.buf),
                multicodec::SKEIN1024_408 => skein_digest!(Skein1024, consts::U408, &self.buf),
                multicodec::SKEIN1024_416 => skein_digest!(Skein1024, consts::U416, &self.buf),
                multicodec::SKEIN1024_424 => skein_digest!(Skein1024, consts::U424, &self.buf),
                multicodec::SKEIN1024_432 => skein_digest!(Skein1024, consts::U432, &self.buf),
                multicodec::SKEIN1024_440 => skein_digest!(Skein1024, consts::U440, &self.buf),
                multicodec::SKEIN1024_448 => skein_digest!(Skein1024, consts::U448, &self.buf),
                multicodec::SKEIN1024_456 => skein_digest!(Skein1024, consts::U456, &self.buf),
                multicodec::SKEIN1024_464 => skein_digest!(Skein1024, consts::U464, &self.buf),
                multicodec::SKEIN1024_472 => skein_digest!(Skein1024, consts::U472, &self.buf),
                multicodec::SKEIN1024_480 => skein_digest!(Skein1024, consts::U480, &self.buf),
                multicodec::SKEIN1024_488 => skein_digest!(Skein1024, consts::U488, &self.buf),
                multicodec::SKEIN1024_496 => skein_digest!(Skein1024, consts::U496, &self.buf),
                multicodec::SKEIN1024_504 => skein_digest!(Skein1024, consts::U504, &self.buf),
                multicodec::SKEIN1024_512 => skein_digest!(Skein1024, consts::U512, &self.buf),
                multicodec::SKEIN1024_520 => skein_digest!(Skein1024, consts::U520, &self.buf),
                multicodec::SKEIN1024_528 => skein_digest!(Skein1024, consts::U528, &self.buf),
                multicodec::SKEIN1024_536 => skein_digest!(Skein1024, consts::U536, &self.buf),
                multicodec::SKEIN1024_544 => skein_digest!(Skein1024, consts::U544, &self.buf),
                multicodec::SKEIN1024_552 => skein_digest!(Skein1024, consts::U552, &self.buf),
                multicodec::SKEIN1024_560 => skein_digest!(Skein1024, consts::U560, &self.buf),
                multicodec::SKEIN1024_568 => skein_digest!(Skein1024, consts::U568, &self.buf),
                multicodec::SKEIN1024_576 => skein_digest!(Skein1024, consts::U576, &self.buf),
                multicodec::SKEIN1024_584 => skein_digest!(Skein1024, consts::U584, &self.buf),
                multicodec::SKEIN1024_592 => skein_digest!(Skein1024, consts::U592, &self.buf),
                multicodec::SKEIN1024_600 => skein_digest!(Skein1024, consts::U600, &self.buf),
                multicodec::SKEIN1024_608 => skein_digest!(Skein1024, consts::U608, &self.buf),
                multicodec::SKEIN1024_616 => skein_digest!(Skein1024, consts::U616, &self.buf),
                multicodec::SKEIN1024_624 => skein_digest!(Skein1024, consts::U624, &self.buf),
                multicodec::SKEIN1024_632 => skein_digest!(Skein1024, consts::U632, &self.buf),
                multicodec::SKEIN1024_640 => skein_digest!(Skein1024, consts::U640, &self.buf),
                multicodec::SKEIN1024_648 => skein_digest!(Skein1024, consts::U648, &self.buf),
                multicodec::SKEIN1024_656 => skein_digest!(Skein1024, consts::U656, &self.buf),
                multicodec::SKEIN1024_664 => skein_digest!(Skein1024, consts::U664, &self.buf),
                multicodec::SKEIN1024_672 => skein_digest!(Skein1024, consts::U672, &self.buf),
                multicodec::SKEIN1024_680 => skein_digest!(Skein1024, consts::U680, &self.buf),
                multicodec::SKEIN1024_688 => skein_digest!(Skein1024, consts::U688, &self.buf),
                multicodec::SKEIN1024_696 => skein_digest!(Skein1024, consts::U696, &self.buf),
                multicodec::SKEIN1024_704 => skein_digest!(Skein1024, consts::U704, &self.buf),
                multicodec::SKEIN1024_712 => skein_digest!(Skein1024, consts::U712, &self.buf),
                multicodec::SKEIN1024_720 => skein_digest!(Skein1024, consts::U720, &self.buf),
                multicodec::SKEIN1024_728 => skein_digest!(Skein1024, consts::U728, &self.buf),
                multicodec::SKEIN1024_736 => skein_digest!(Skein1024, consts::U736, &self.buf),
                multicodec::SKEIN1024_744 => skein_digest!(Skein1024, consts::U744, &self.buf),
                multicodec::SKEIN1024_752 => skein_digest!(Skein1024, consts::U752, &self.buf),
                multicodec::SKEIN1024_760 => skein_digest!(Skein1024, consts::U760, &self.buf),
                multicodec::SKEIN1024_768 => skein_digest!(Skein1024, consts::U768, &self.buf),
                multicodec::SKEIN1024_776 => skein_digest!(Skein1024, consts::U776, &self.buf),
                multicodec::SKEIN1024_784 => skein_digest!(Skein1024, consts::U784, &self.buf),
                multicodec::SKEIN1024_792 => skein_digest!(Skein1024, consts::U792, &self.buf),
                multicodec::SKEIN1024_800 => skein_digest!(Skein1024, consts::U800, &self.buf),
                multicodec::SKEIN1024_808 => skein_digest!(Skein1024, consts::U808, &self.buf),
                multicodec::SKEIN1024_816 => skein_digest!(Skein1024, consts::U816, &self.buf),
                multicodec::SKEIN1024_824 => skein_digest!(Skein1024, consts::U824, &self.buf),
                multicodec::SKEIN1024_832 => skein_digest!(Skein1024, consts::U832, &self.buf),
                multicodec::SKEIN1024_840 => skein_digest!(Skein1024, consts::U840, &self.buf),
                multicodec::SKEIN1024_848 => skein_digest!(Skein1024, consts::U848, &self.buf),
                multicodec::SKEIN1024_856 => skein_digest!(Skein1024, consts::U856, &self.buf),
                multicodec::SKEIN1024_864 => skein_digest!(Skein1024, consts::U864, &self.buf),
                multicodec::SKEIN1024_872 => skein_digest!(Skein1024, consts::U872, &self.buf),
                multicodec::SKEIN1024_880 => skein_digest!(Skein1024, consts::U880, &self.buf),
                multicodec::SKEIN1024_888 => skein_digest!(Skein1024, consts::U888, &self.buf),
                multicodec::SKEIN1024_896 => skein_digest!(Skein1024, consts::U896, &self.buf),
                multicodec::SKEIN1024_904 => skein_digest!(Skein1024, consts::U904, &self.buf),
                multicodec::SKEIN1024_912 => skein_digest!(Skein1024, consts::U912, &self.buf),
                multicodec::SKEIN1024_920 => skein_digest!(Skein1024, consts::U920, &self.buf),
                multicodec::SKEIN1024_928 => skein_digest!(Skein1024, consts::U928, &self.buf),
                multicodec::SKEIN1024_936 => skein_digest!(Skein1024, consts::U936, &self.buf),
                multicodec::SKEIN1024_944 => skein_digest!(Skein1024, consts::U944, &self.buf),
                multicodec::SKEIN1024_952 => skein_digest!(Skein1024, consts::U952, &self.buf),
                multicodec::SKEIN1024_960 => skein_digest!(Skein1024, consts::U960, &self.buf),
                multicodec::SKEIN1024_968 => skein_digest!(Skein1024, consts::U968, &self.buf),
                multicodec::SKEIN1024_976 => skein_digest!(Skein1024, consts::U976, &self.buf),
                multicodec::SKEIN1024_984 => skein_digest!(Skein1024, consts::U984, &self.buf),
                multicodec::SKEIN1024_992 => skein_digest!(Skein1024, consts::U992, &self.buf),
                multicodec::SKEIN1024_1000 => skein_digest!(Skein1024, consts::U1000, &self.buf),
                multicodec::SKEIN1024_1008 => skein_digest!(Skein1024, consts::U1008, &self.buf),
                multicodec::SKEIN1024_1016 => skein_digest!(Skein1024, consts::U1016, &self.buf),
                multicodec::SKEIN1024_1024 => skein_digest!(Skein1024, consts::U1024, &self.buf),
                _ => err_at!(Invalid, msg: format!("unreachable"))?,
            },
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        self.digest = Some(digest);
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

#[derive(Clone)]
enum RipeMd {
    Algo160 {
        hasher: ripemd160::Ripemd160,
        digest: Option<Vec<u8>>,
    },
    Algo320 {
        hasher: ripemd320::Ripemd320,
        digest: Option<Vec<u8>>,
    },
}

impl Eq for RipeMd {}

impl PartialEq for RipeMd {
    fn eq(&self, other: &RipeMd) -> bool {
        use RipeMd::*;

        match (self, other) {
            (Algo160 { digest, .. }, Algo160 { digest: other, .. }) => digest == other,
            (Algo320 { digest, .. }, Algo320 { digest: other, .. }) => digest == other,
            _ => false,
        }
    }
}

impl PartialOrd for RipeMd {
    fn partial_cmp(&self, other: &RipeMd) -> Option<cmp::Ordering> {
        use RipeMd::*;

        match (self, other) {
            (Algo160 { digest, .. }, Algo160 { digest: other, .. }) => digest.partial_cmp(other),
            (Algo320 { digest, .. }, Algo320 { digest: other, .. }) => digest.partial_cmp(other),
            _ => None,
        }
    }
}

impl RipeMd {
    fn from_code(code: u128) -> Result<RipeMd> {
        let val = match code {
            multicodec::RIPEMD_160 => RipeMd::Algo160 {
                hasher: ripemd160::Ripemd160::new(),
                digest: None,
            },
            multicodec::RIPEMD_320 => RipeMd::Algo320 {
                hasher: ripemd320::Ripemd320::new(),
                digest: None,
            },
            _ => err_at!(Invalid, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, buf: &[u8]) -> Result<RipeMd> {
        let digest = Some(buf.to_vec());
        let val = match code {
            multicodec::RIPEMD_160 => RipeMd::Algo160 {
                hasher: ripemd160::Ripemd160::new(),
                digest,
            },
            multicodec::RIPEMD_320 => RipeMd::Algo320 {
                hasher: ripemd320::Ripemd320::new(),
                digest,
            },
            _ => err_at!(Invalid, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            RipeMd::Algo160 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            RipeMd::Algo320 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        match self {
            RipeMd::Algo160 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            RipeMd::Algo320 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let digest = match self {
            RipeMd::Algo160 { digest, .. } => digest,
            RipeMd::Algo320 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match self {
            RipeMd::Algo160 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            RipeMd::Algo320 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}
