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

//! Ed25519 keys.

use ed25519_dalek::{self as ed25519, Signer as _, Verifier as _};
use rand::RngCore;
use zeroize::Zeroize;

use std::{convert::TryFrom, fmt};

use crate::{Error, Result};

// TODO: Should we zeroize key-pair upon drop ?

/// An Ed25519 keypair.
pub struct Keypair {
    key_pair: ed25519::Keypair,
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.key_pair.public)
            .finish()
    }
}

/// Demote an Ed25519 keypair to a secret key.
impl From<Keypair> for SecretKey {
    fn from(val: Keypair) -> SecretKey {
        SecretKey {
            secret_key: val.key_pair.secret,
        }
    }
}

/// Promote an Ed25519 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(val: SecretKey) -> Keypair {
        let secret: ed25519::ExpandedSecretKey = (&val.secret_key).into();
        let public = ed25519::PublicKey::from(&secret);
        let key_pair = ed25519::Keypair {
            secret: val.secret_key,
            public,
        };
        Keypair { key_pair }
    }
}

impl Keypair {
    /// Generate a new Ed25519 keypair.
    pub fn generate() -> Result<Keypair> {
        Ok(Keypair::from(SecretKey::generate()?))
    }

    /// Get the public key of this keypair.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            public_key: self.key_pair.public,
        }
    }

    /// Get the secret key of this keypair.
    pub fn to_secret_key(&self) -> Result<SecretKey> {
        match SecretKey::from_bytes(&mut self.key_pair.secret.to_bytes()) {
            Ok(secret_key) => Ok(secret_key),
            Err(err) => err_at!(DecodeError, Err(err), "to secret key"),
        }
    }

    /// Encode the keypair into a byte array by concatenating the bytes
    /// of the secret scalar and the compressed public point,
    /// an informal standard for encoding Ed25519 keypairs.
    pub fn encode(&self) -> [u8; 64] {
        self.key_pair.to_bytes()
    }

    /// Decode a keypair from the format produced by `encode`,
    /// zeroing the input on success.
    pub fn decode(kp: &mut [u8]) -> Result<Keypair> {
        match ed25519::Keypair::from_bytes(kp) {
            Ok(key_pair) => {
                kp.zeroize();
                Ok(Keypair { key_pair })
            }
            Err(err) => err_at!(DecodeError, Err(err), "Ed25519 keypair"),
        }
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key_pair.sign(msg).to_bytes().to_vec())
    }

    pub fn try_clone(&self) -> Result<Self> {
        let secret = {
            let mut sk_bytes = self.key_pair.secret.to_bytes();
            match SecretKey::from_bytes(&mut sk_bytes) {
                Ok(val) => Ok(val.secret_key),
                Err(err) => err_at!(DecodeError, Err(err), "try_clone ed25519::SecretKey"),
            }?
        };
        let public = {
            let pk_bytes = self.key_pair.public.to_bytes();
            match ed25519::PublicKey::from_bytes(&pk_bytes) {
                Ok(public_key) => Ok(public_key),
                Err(err) => err_at!(DecodeError, Err(err), "try_clone ed25519::PublicKey"),
            }?
        };

        let key_pair = ed25519::Keypair { secret, public };
        Ok(Keypair { key_pair })
    }
}

/// An Ed25519 public key.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PublicKey {
    public_key: ed25519::PublicKey,
}

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        ed25519::Signature::try_from(signature)
            .and_then(|s| self.public_key.verify(msg, &s))
            .is_ok()
    }

    /// Encode the public key into a byte array in compressed form, i.e.
    /// where one coordinate is represented by a single bit.
    pub fn encode(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    /// Decode a public key from a byte array as produced by `encode`.
    pub fn decode(k: &[u8]) -> Result<PublicKey> {
        match ed25519::PublicKey::from_bytes(k) {
            Ok(public_key) => Ok(PublicKey { public_key }),
            Err(err) => err_at!(DecodeError, Err(err), "Ed25519 public key"),
        }
    }
}

/// An Ed25519 secret key. Secret key is the meat of the Ed25519 algorithm.
pub struct SecretKey {
    secret_key: ed25519::SecretKey,
}

/// View the bytes of the secret key.
impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    // TODO: should we try drand.love ?
    /// Generate a new Ed25519 secret key.
    pub fn generate() -> Result<SecretKey> {
        let secret_key = {
            let mut bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            match ed25519::SecretKey::from_bytes(&bytes) {
                Ok(secret_key) => Ok(secret_key),
                Err(err) => err_at!(BadInput, Err(err), "Ed25519 generate bad length"),
            }?
        };
        Ok(SecretKey { secret_key })
    }

    /// Create an Ed25519 secret key from a byte slice, zeroing the input on
    /// success. If the bytes do not constitute a valid Ed25519 secret key,
    /// an error is returned.
    pub fn from_bytes(mut sk_bytes: impl AsMut<[u8]>) -> Result<SecretKey> {
        let sk_bytes = sk_bytes.as_mut();
        let secret_key = match ed25519::SecretKey::from_bytes(&*sk_bytes) {
            Ok(secret_key) => Ok(secret_key),
            Err(err) => err_at!(DecodeError, Err(err), "Ed25519 secret key"),
        }?;

        sk_bytes.zeroize();

        Ok(SecretKey { secret_key })
    }

    pub fn try_clone(&self) -> Result<Self> {
        let mut sk_bytes = self.secret_key.to_bytes();
        match Self::from_bytes(&mut sk_bytes) {
            Ok(val) => Ok(val),
            Err(err) => err_at!(DecodeError, Err(err), "try_clone ed25519::SecretKey"),
        }
    }
}

#[cfg(test)]
#[path = "ed25519_test.rs"]
mod ed25519_test;
