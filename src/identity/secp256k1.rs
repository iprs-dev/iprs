// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Secp256k1 keys.

use asn1_der::{DerObject, FromDerObject};
use rand::RngCore;
use secp256k1::{Message, Signature};
use sha2::{Digest as ShaDigestTrait, Sha256};
use zeroize::Zeroize;

use std::fmt;

use crate::{Error, Result};

/// A Secp256k1 keypair.
#[derive(Clone)]
pub struct Keypair {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Keypair {
    /// Generate a new sec256k1 `Keypair`.
    pub fn generate() -> Keypair {
        Keypair::from(SecretKey::generate())
    }

    /// Get the reference to public key of this keypair.
    pub fn as_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get a copy of public key of this keypair.
    pub fn to_public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    /// Get the secret key of this keypair.
    pub fn as_secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public_key)
            .finish()
    }
}

/// Promote a Secp256k1 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(val: SecretKey) -> Keypair {
        let public_key = PublicKey {
            public_key: secp256k1::PublicKey::from_secret_key(&val.secret_key),
        };
        Keypair {
            secret_key: SecretKey {
                secret_key: val.secret_key,
            },
            public_key,
        }
    }
}

/// Demote a Secp256k1 keypair into a secret key.
impl From<Keypair> for SecretKey {
    fn from(val: Keypair) -> SecretKey {
        val.secret_key
    }
}

/// A Secp256k1 secret key.
#[derive(Clone)]
pub struct SecretKey {
    secret_key: secp256k1::SecretKey,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    // TODO: should we try drand.love ?
    /// Generate a new Secp256k1 secret key.
    pub fn generate() -> SecretKey {
        let mut r = rand::thread_rng();
        let mut b = [0; secp256k1::util::SECRET_KEY_SIZE];
        // This is how it is done in `secp256k1::SecretKey::random` which
        // we do not use here because it uses `rand::Rng` from rand-0.4.
        loop {
            r.fill_bytes(&mut b);
            if let Ok(secret_key) = secp256k1::SecretKey::parse(&b) {
                break SecretKey { secret_key };
            }
        }
    }

    /// Create a secret key from a byte slice, zeroing the slice on success.
    /// If the bytes do not constitute a valid Secp256k1 secret key, an
    /// error is returned.
    pub fn from_bytes(mut sk: impl AsMut<[u8]>) -> Result<SecretKey> {
        let sk_bytes = sk.as_mut();
        let secret_key = match secp256k1::SecretKey::parse_slice(&*sk_bytes) {
            Ok(secret_key) => Ok(secret_key),
            err @ Err(_) => err_at!(DecodeError, err, "secp256k1 secret key"),
        }?;

        sk_bytes.zeroize();

        Ok(SecretKey { secret_key })
    }

    /// Decode a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915].
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    pub fn from_der(mut der: impl AsMut<[u8]>) -> Result<SecretKey> {
        // TODO: Stricter parsing.
        let val: Vec<DerObject> = {
            match FromDerObject::deserialize(der.as_mut().iter()) {
                Ok(val) => Ok(val),
                err @ Err(_) => err_at!(DecodeError, err, "Secp256k1 from DER"),
            }?
        };

        der.as_mut().zeroize();

        let sk_val = match val.into_iter().nth(1) {
            Some(val) => val,
            None => err_at!(DecodeError, msg: "Not enough elements in DER")?,
        };

        let mut sk_bytes: Vec<u8> = err_at!(
            //
            DecodeError,
            FromDerObject::from_der_object(sk_val)
        )?;

        let sk = SecretKey::from_bytes(&mut sk_bytes)?;
        sk_bytes.zeroize();

        Ok(sk)
    }

    /// Sign a message with this secret key, producing a DER-encoded
    /// ECDSA signature, as defined in [RFC3278].
    ///
    /// [RFC3278]: https://tools.ietf.org/html/rfc3278#section-8.2
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.sign_hash(Sha256::digest(msg).as_ref())
    }

    /// Returns the raw bytes of the secret key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.serialize()
    }

    /// Sign a raw message of length 256 bits with this secret key, produces a DER-encoded
    /// ECDSA signature.
    fn sign_hash(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let m = match Message::parse_slice(msg) {
            Ok(m) => Ok(m),
            err @ Err(_) => err_at!(SigningError, err, "secp256k1 digest"),
        }?;
        Ok(secp256k1::sign(&m, &self.secret_key)
            .0
            .serialize_der()
            .as_ref()
            .into())
    }
}

/// A Secp256k1 public key.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicKey {
    public_key: secp256k1::PublicKey,
}

impl PublicKey {
    /// Verify the Secp256k1 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        let msg = Sha256::digest(msg);
        // Verify the Secp256k1 DER-encoded signature on a raw 256-bit hash
        // using the public key.
        Message::parse_slice(msg.as_ref())
            .and_then(|m| {
                Signature::parse_der(signature).map(|s| secp256k1::verify(&m, &s, &self.public_key))
            })
            .unwrap_or(false)
    }

    /// Encode the public key in compressed form, i.e. with one coordinate
    /// represented by a single bit.
    pub fn encode(&self) -> [u8; 33] {
        self.public_key.serialize_compressed()
    }

    /// Encode the public key in uncompressed form.
    pub fn encode_uncompressed(&self) -> [u8; 65] {
        self.public_key.serialize()
    }

    /// Decode a public key from a byte slice in the the format produced
    /// by `encode`.
    pub fn decode(k: &[u8]) -> Result<PublicKey> {
        let format = Some(secp256k1::PublicKeyFormat::Compressed);
        match secp256k1::PublicKey::parse_slice(k, format) {
            Ok(public_key) => Ok(PublicKey { public_key }),
            Err(err) => err_at!(
                DecodeError,
                Err(err),
                "failed to parse secp256k1 public key"
            ),
        }
    }
}

#[cfg(test)]
#[path = "secp256k1_test.rs"]
mod secp256k1_test;
