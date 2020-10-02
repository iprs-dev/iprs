// Copyright (c) 2020 R Pratap Chakravarthy

//! Module adapts several hashing algorithms into multiformat
//! specification.

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

/// Type adapts several hashing algorithms that can be encoded/decoded
/// into/from multi-format/multi-hash.
#[derive(Clone, Eq, PartialEq)]
pub struct Multihash {
    inner: Inner,
}

#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Display for Multihash {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use std::iter::FromIterator;
        use Inner::*;

        let empty = vec![];
        let (codec, digest) = match &self.inner {
            Identity(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Sha1(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Sha2(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Sha3(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Blake2b(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Blake2s(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Blake3(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Md4(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Md5(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            Skein(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
            RipeMd(c, hasher) => (c, hasher.as_digest().unwrap_or(&empty)),
        };
        let text = {
            let text = multibase::encode(multibase::Base::Base16Lower, &digest);
            let mut chars = text.chars();
            chars.next();
            String::from_iter(chars)
        };
        write!(f, "{}-{}-{}", codec, digest.len() * 8, text)
    }
}

impl From<Inner> for Multihash {
    fn from(inner: Inner) -> Multihash {
        Multihash { inner }
    }
}

impl Multihash {
    /// Create a Multihash instance, from a multi-codec value for
    /// generating hash-digest and encode them in multi-format.
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
    /// use [to_codec], [to_digest], [unwrap] methods to get the hash-digest
    /// and hash-algorithm used to generate the digest.
    pub fn decode(buf: &[u8]) -> Result<(Multihash, &[u8])> {
        // <hash-func-type><digest-length><digest-value>
        use unsigned_varint::decode;

        let (codec, digest, rem) = {
            let (codec, rem) = Multicodec::decode(buf)?;
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
    ///     hasher.write("ciao".as_bytes());
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

    /// Encode hash-digest and associated headers as per multi-hash
    /// specification.
    ///
    /// `<hash-func-type><digest-length><digest-value>`
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::default();
        self.encode_with(&mut buf)?;
        Ok(buf)
    }

    // Similar to encode() but avoid allocation by using supplied buffer
    // `buf`.
    fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
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
        let n = {
            let out = self.to_codec().encode()?;
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

    /// Return the underlying hash digest.
    ///
    /// *Panic if digest is not generated or decoded*.
    pub fn to_digest(&self) -> Vec<u8> {
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
        digest.to_vec()
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

#[cfg(test)]
#[path = "multihash_test.rs"]
mod multihash_test;
