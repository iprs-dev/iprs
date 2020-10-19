//! Module implement Multihash. _Refer [multihash] spec for detail_.
//!
//! [multihash]: https://multiformats.io/multihash/

// TODO:
// 1. For Shake128 and Shake256 algorithm variable output length
//    `d` must be included as part of the spec and API.
mod blake2b;
mod blake2s;
mod blake3;
mod identity;
mod md4;
mod md5;
mod ripemd;
mod sha1;
mod sha2;
mod sha3;
mod skein;

use std::{fmt, io, result};

use crate::multihash::{
    blake2b::Blake2b, blake2s::Blake2s, blake3::Blake3, identity::Identity, md4::Md4, md5::Md5,
    ripemd::RipeMd, sha1::Sha1, sha2::Sha2, sha3::Sha3, skein::Skein,
};

use crate::{multicodec, multicodec::Multicodec, Error, Result};

/// Type adapts several hashing algorithms within [multihash] specification.
///
/// [multihash]: https://multiformats.io/multihash/
#[derive(Clone, Eq, PartialEq)]
pub struct Multihash {
    inner: Inner,
}

#[derive(Clone, Eq, PartialEq)]
enum Inner {
    Binary(Vec<u8>),
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

impl fmt::Display for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use multibase::Base::Base16Lower;
        use std::iter::FromIterator;
        use Inner::*;

        fn get_parts(inner: &Inner) -> Option<(Multicodec, Vec<u8>)> {
            let (codec, digest) = match inner {
                Identity(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Sha1(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Sha2(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Sha3(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Blake2b(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Blake2s(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Blake3(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Md4(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Md5(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Skein(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                RipeMd(c, h) => (c.clone(), h.as_digest().ok()?.to_vec()),
                Binary(data) => get_parts(&Multihash::decode(&data).ok()?.0.inner)?,
            };

            Some((codec, digest))
        };

        // human readable repr
        // refer: https://github.com/multiformats/cid/blob/master/README.md#human-readable-cids

        match get_parts(&self.inner) {
            Some((codec, digest)) => {
                let text = multibase::encode(Base16Lower, &digest);
                let chars = text.chars();
                // first char is base-prefix
                let text = String::from_iter(chars.skip(1));
                write!(f, "{}-{}-{}", codec, digest.len() * 8, text)
            }
            None => write!(f, "xxx-xxx-xxx..."),
        }
    }
}

impl From<Inner> for Multihash {
    fn from(inner: Inner) -> Multihash {
        Multihash { inner }
    }
}

impl Multihash {
    /// Create a Multihash instance, of type multi-codec for data. Digest
    /// will be created for `data`, using the multi-hash algorithm specified
    /// by `codec`.
    pub fn new(codec: Multicodec, data: &[u8]) -> Result<Multihash> {
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
            codec => err_at!(NotImplemented, msg: "codec {}", codec)?,
        };

        let mut mh: Multihash = inner.into();
        mh.write(data)?.finish()?;

        Ok(mh)
    }

    /// New multihash from digest and multihash-type.
    pub fn from_digest(codec: Multicodec, digest: &[u8]) -> Result<Multihash> {
        let code = codec.to_code();
        let inner = match code {
            multicodec::IDENTITY => {
                let hasher = Identity::decode(code, digest)?;
                Inner::Identity(codec, hasher)
            }
            multicodec::SHA1 => {
                let hasher = Sha1::decode(code, digest)?;
                Inner::Sha1(codec, hasher)
            }
            multicodec::SHA2_256 | multicodec::SHA2_512 | multicodec::DBL_SHA2_256 => {
                let hasher = Sha2::decode(code, digest)?;
                Inner::Sha2(codec, hasher)
            }
            multicodec::SHA3_512..=multicodec::KECCAK_512 => {
                let hasher = Sha3::decode(code, digest)?;
                Inner::Sha3(codec, hasher)
            }
            multicodec::BLAKE3 => {
                let hasher = Blake3::decode(code, digest)?;
                Inner::Blake3(codec, hasher)
            }
            multicodec::BLAKE2B_8..=multicodec::BLAKE2B_512 => {
                let hasher = Blake2b::decode(code, digest)?;
                Inner::Blake2b(codec, hasher)
            }
            multicodec::BLAKE2S_8..=multicodec::BLAKE2S_256 => {
                let hasher = Blake2s::decode(code, digest)?;
                Inner::Blake2s(codec, hasher)
            }
            multicodec::MD4 => {
                let hasher = Md4::decode(code, digest)?;
                Inner::Md4(codec, hasher)
            }
            multicodec::MD5 => {
                let hasher = Md5::decode(code, digest)?;
                Inner::Md5(codec, hasher)
            }
            multicodec::SKEIN256_8..=multicodec::SKEIN1024_1024 => {
                let hasher = Skein::decode(code, digest)?;
                Inner::Skein(codec, hasher)
            }
            multicodec::RIPEMD_128..=multicodec::RIPEMD_320 => {
                let hasher = RipeMd::decode(code, digest)?;
                Inner::RipeMd(codec, hasher)
            }
            codec => err_at!(NotImplemented, msg: "codec {}", codec)?,
        };

        Ok(inner.into())
    }

    /// Create a lazy instance of multihash from `data`, where data contains
    /// encoded multihash. Call [Self::parse] method to de-serialize.
    pub fn decode_lazy(data: &[u8]) -> Result<Multihash> {
        Ok(Inner::Binary(data.to_vec()).into())
    }

    /// Lazy parse. Typically called after creating this instance using
    /// [Self::decode_lazy] constructor.
    pub fn parse(&mut self) -> Result<()> {
        match &self.inner {
            Inner::Binary(data) => *self = Self::decode(data)?.0,
            _ => (),
        }
        Ok(())
    }

    /// Decode a hash-digest that was encoded using multi-format
    /// specification.
    ///
    /// *<hash-func-type><digest-length><digest-value>*
    ///
    /// - The `type` *<hash-func-type>* is an unsigned variable integer
    ///   identifying the hash function. There is a default table, and
    ///   it is configurable. The default table is the [multicodec table].
    /// - The `length` *<digest-length>* is an unsigned variable integer
    ///   counting the length of the digest, in bytes.
    /// - The `value` *<digest-value>* is the hash function digest, with
    ///   a length of exactly `<digest-length>` bytes.
    ///
    /// Return the Multihash value and remaining byte-slice. Caller can
    /// use [Self::to_codec], [Self::to_digest], [Self::unwrap] methods
    /// to get the hash-digest and hash-algorithm used to generate the digest.
    pub fn decode(buf: &[u8]) -> Result<(Multihash, &[u8])> {
        // <hash-func-type><digest-length><digest-value>
        use unsigned_varint::decode;

        let (codec, digest, rem) = {
            let (codec, rem) = Multicodec::decode(buf)?;
            let (n, rem) = err_at!(BadInput, decode::usize(rem))?;
            if n <= rem.len() {
                Ok((codec, &rem[..n], &rem[n..]))
            } else {
                err_at!(BadInput, msg: "hash-len {}", n)
            }
        }?;

        let mh = Self::from_digest(codec, digest)?;
        Ok((mh, rem))
    }

    /// Encode hash-digest and associated headers as per multi-hash
    /// specification.
    ///
    /// `<hash-func-type><digest-length><digest-value>`
    pub fn encode(&self) -> Result<Vec<u8>> {
        let data = match &self.inner {
            Inner::Binary(data) => data.clone(),
            _ => {
                let mut buf = Vec::default();
                self.encode_with(&mut buf)?;
                buf
            }
        };

        Ok(data)
    }

    // Similar to encode() but avoid allocation by using supplied buffer
    // `buf`.
    fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        use unsigned_varint::encode;

        let digest = match &self.inner {
            Inner::Binary(_) => err_at!(Fatal, msg: "unreachable!")?,
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
        let n = {
            let out = self.to_codec()?.encode()?;
            err_at!(IOError, buf.write(&out))?;
            out.len()
        };
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

    // Accumulate bytes for which a hash-digest needs to be generated.
    //
    // Typical usage:
    //
    // ```ignore
    //     let hasher = Multihash::from_code(multicodec::SHA2_256);
    //     hasher.write("hello world".as_bytes());
    //     hasher.write("ciao".as_bytes());
    //     (codec, digest) = hasher.finish().unwrap();
    // ```
    //
    // To reuse the multihash value, call `reset()` and repeat the process.
    //
    fn write(&mut self, data: &[u8]) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.write(data)?,
            Inner::Sha1(_, hasher) => hasher.write(data)?,
            Inner::Sha2(_, hasher) => hasher.write(data)?,
            Inner::Sha3(_, hasher) => hasher.write(data)?,
            Inner::Blake3(_, hasher) => hasher.write(data)?,
            Inner::Blake2b(_, hasher) => hasher.write(data)?,
            Inner::Blake2s(_, hasher) => hasher.write(data)?,
            Inner::Md4(_, hasher) => hasher.write(data)?,
            Inner::Md5(_, hasher) => hasher.write(data)?,
            Inner::Skein(_, hasher) => hasher.write(data)?,
            Inner::RipeMd(_, hasher) => hasher.write(data)?,
            Inner::Binary(_) => err_at!(Invalid, msg: "mh in binary form")?,
        };
        Ok(self)
    }

    // Finish accumulating data for generating digest, calling this value
    // shall actually generate the final digest.
    fn finish(&mut self) -> Result<&mut Self> {
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
            Inner::Binary(_) => err_at!(Invalid, msg: "mh in binary form")?,
        };
        Ok(self)
    }

    // Reset to reuse this value for ingesting new data and generate a
    // new hash digest.
    #[allow(unused)]
    fn reset(&mut self) -> Result<&mut Self> {
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
            Inner::Binary(_) => err_at!(Invalid, msg: "mh in binary form")?,
        };
        Ok(self)
    }
}

impl Multihash {
    /// Return the multihash codec.
    pub fn to_codec(&self) -> Result<Multicodec> {
        match &self.inner {
            Inner::Identity(codec, _) => Ok(codec.clone()),
            Inner::Sha1(codec, _) => Ok(codec.clone()),
            Inner::Sha2(codec, _) => Ok(codec.clone()),
            Inner::Sha3(codec, _) => Ok(codec.clone()),
            Inner::Blake3(codec, _) => Ok(codec.clone()),
            Inner::Blake2b(codec, _) => Ok(codec.clone()),
            Inner::Blake2s(codec, _) => Ok(codec.clone()),
            Inner::Md4(codec, _) => Ok(codec.clone()),
            Inner::Md5(codec, _) => Ok(codec.clone()),
            Inner::Skein(codec, _) => Ok(codec.clone()),
            Inner::RipeMd(codec, _) => Ok(codec.clone()),
            Inner::Binary(data) => Self::decode(data)?.0.to_codec(),
        }
    }

    /// Return the underlying hash digest.
    ///
    /// *Panic if digest is not generated or decoded*.
    pub fn to_digest(&self) -> Result<Vec<u8>> {
        match &self.inner {
            Inner::Identity(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Sha1(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Sha2(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Sha3(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Blake3(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Blake2b(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Blake2s(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Md4(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Md5(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Skein(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::RipeMd(_, h) => Ok(h.as_digest()?.to_vec()),
            Inner::Binary(data) => Self::decode(data)?.0.to_digest(),
        }
    }

    /// Unwrap the underlying codec and hash digest. Panic if digest
    /// is not generated or decoded.
    pub fn unwrap(self) -> Result<(Multicodec, Vec<u8>)> {
        match &self.inner {
            Inner::Identity(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Sha1(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Sha2(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Sha3(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Blake3(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Blake2b(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Blake2s(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Md4(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Md5(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Skein(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::RipeMd(c, h) => Ok((c.clone(), h.as_digest()?.to_vec())),
            Inner::Binary(data) => Self::decode(data)?.0.unwrap(),
        }
    }
}

impl io::Write for Multihash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.finish() {
            Ok(_) => Ok(()),
            Err(e) => {
                let e = e.to_string();
                Err(io::Error::new(io::ErrorKind::Other, e.as_str()))
            }
        }
    }
}

#[cfg(test)]
#[path = "multihash_test.rs"]
mod multihash_test;
