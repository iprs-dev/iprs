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

//! A node's network identity, its public-key is its identity.

pub mod ed25519;
#[cfg(not(target_arch = "wasm32"))]
pub mod rsa;
#[cfg(feature = "secp256k1")]
pub mod secp256k1;

use crate::{pb::key_pair_proto, peer_id::PeerId, Error, Result};

// TODO: implement protobuf store for Private-key/Secret-key.

/// Identity keypair of a node.
///
/// # Example: Generating RSA keys with OpenSSL
///
/// ```text
/// openssl genrsa -out private.pem 2048
/// openssl pkcs8 -in private.pem -inform PEM -topk8 -out private.pk8 -outform DER -nocrypt
/// rm private.pem      # optional
/// ```
///
/// Loading the keys:
///
/// ```text
/// let mut bytes = std::fs::read("private.pem").unwrap();
/// let keypair = Keypair::rsa_from_pkcs8(&mut bytes);
/// ```
///
pub enum Keypair {
    Ed25519(ed25519::Keypair),
    #[cfg(not(target_arch = "wasm32"))]
    Rsa(rsa::Keypair),
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::Keypair),
}

impl Keypair {
    /// Generate a new Ed25519 keypair.
    pub fn generate_ed25519() -> Result<Keypair> {
        Ok(Keypair::Ed25519(ed25519::Keypair::generate()?))
    }

    /// Generate a new Secp256k1 keypair.
    #[cfg(feature = "secp256k1")]
    pub fn generate_secp256k1() -> Result<Keypair> {
        Ok(Keypair::Secp256k1(secp256k1::Keypair::generate()))
    }

    /// Decode an keypair from a DER-encoded secret key in PKCS#8
    /// PrivateKeyInfo format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_rsa_pkcs8(pkcs8_der: &mut [u8]) -> Result<Keypair> {
        rsa::Keypair::from_pkcs8(pkcs8_der).map(Keypair::Rsa)
    }

    /// Decode an keypair from serialized ED25519.
    pub fn from_ed25519_bytes(data: &mut [u8]) -> Result<Keypair> {
        ed25519::Keypair::decode(data).map(Keypair::Ed25519)
    }

    /// Decode a keypair from a DER-encoded Secp256k1 secret key in an
    /// ECPrivateKey structure as defined in [RFC5915].
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    #[cfg(feature = "secp256k1")]
    pub fn from_secp256k1_der(der: &mut [u8]) -> Result<Keypair> {
        let secret_key = secp256k1::SecretKey::from_der(der)?;
        Ok(Keypair::Secp256k1(secp256k1::Keypair::from(secret_key)))
    }
}

impl Keypair {
    /// Get the public key of this keypair.
    pub fn to_public_key(&self) -> PublicKey {
        use Keypair::*;

        match self {
            Ed25519(pair) => PublicKey::Ed25519(pair.to_public_key()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pair) => PublicKey::Rsa(pair.to_public_key()),
            #[cfg(feature = "secp256k1")]
            Secp256k1(pair) => PublicKey::Secp256k1(pair.to_public_key().clone()),
        }
    }

    /// Sign a message using the private key of this keypair, producing
    /// a signature that can be verified using the corresponding public key.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        use Keypair::*;

        match self {
            Ed25519(ref pair) => pair.sign(msg),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(ref pair) => pair.sign(msg),
            #[cfg(feature = "secp256k1")]
            Secp256k1(ref pair) => pair.as_secret_key().sign(msg),
        }
    }

    pub fn try_clone(&self) -> Result<Self> {
        use Keypair::*;

        match self {
            Ed25519(ref pair) => pair.try_clone().map(Ed25519),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(ref pair) => Ok(pair.clone()).map(Rsa),
            #[cfg(feature = "secp256k1")]
            Secp256k1(ref pair) => Ok(pair.clone()).map(Secp256k1),
        }
    }
}

/// The public key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519::PublicKey),
    #[cfg(not(target_arch = "wasm32"))]
    Rsa(rsa::PublicKey),
    #[cfg(feature = "secp256k1")]
    Secp256k1(secp256k1::PublicKey),
}

impl PublicKey {
    /// Verify a signature for a message using this public key, i.e. check
    /// that the signature has been produced by the corresponding
    /// private key (authenticity), and that the message has not been
    /// tampered with (integrity).
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        use PublicKey::*;

        match self {
            Ed25519(pk) => pk.verify(msg, sig),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => pk.verify(msg, sig),
            #[cfg(feature = "secp256k1")]
            Secp256k1(pk) => pk.verify(msg, sig),
        }
    }

    /// Encode the public key into a protobuf structure for storage and/or
    /// exchange with other nodes.
    pub fn into_protobuf_encoding(self) -> Result<Vec<u8>> {
        use prost::Message;

        let public_key = match self {
            PublicKey::Ed25519(key) => key_pair_proto::PublicKey {
                r#type: key_pair_proto::KeyType::Ed25519 as i32,
                data: key.encode().to_vec(),
            },
            #[cfg(not(target_arch = "wasm32"))]
            PublicKey::Rsa(key) => key_pair_proto::PublicKey {
                r#type: key_pair_proto::KeyType::Rsa as i32,
                data: key.encode_x509()?,
            },
            #[cfg(feature = "secp256k1")]
            PublicKey::Secp256k1(key) => key_pair_proto::PublicKey {
                r#type: key_pair_proto::KeyType::Secp256k1 as i32,
                data: key.encode().to_vec(),
            },
        };

        let mut buf = Vec::with_capacity(public_key.encoded_len());
        err_at!(EncodeError, public_key.encode(&mut buf))?;
        Ok(buf)
    }

    /// Decode a public key from a protobuf structure,
    /// e.g. read from storage or received from another node.
    pub fn from_protobuf_encoding(bytes: &[u8]) -> Result<PublicKey> {
        use prost::Message;

        #[allow(unused_mut)] // Due to conditional compilation.
        let mut pubkey = err_at!(DecodeError, key_pair_proto::PublicKey::decode(bytes))?;

        let key_type = match key_pair_proto::KeyType::from_i32(pubkey.r#type) {
            Some(typ) => Ok(typ),
            None => err_at!(DecodeError, msg: "unknown key type: {}", pubkey.r#type)?,
        }?;

        match key_type {
            key_pair_proto::KeyType::Ed25519 => {
                ed25519::PublicKey::decode(&pubkey.data).map(PublicKey::Ed25519)
            }
            #[cfg(not(target_arch = "wasm32"))]
            key_pair_proto::KeyType::Rsa => {
                rsa::PublicKey::decode_x509(&pubkey.data).map(PublicKey::Rsa)
            }
            #[cfg(target_arch = "wasm32")]
            key_pair_proto::KeyType::Rsa => {
                err_at!(DecodeError, msg: "RSA disabled at compile-time")
            }
            #[cfg(feature = "secp256k1")]
            key_pair_proto::KeyType::Secp256k1 => {
                secp256k1::PublicKey::decode(&pubkey.data).map(PublicKey::Secp256k1)
            }
            #[cfg(not(feature = "secp256k1"))]
            key_pair_proto::KeyType::Secp256k1 => {
                err_at!(DecodeError, msg: "secp256k1 disabled at compile-time")
            }
        }
    }

    /// Convert the `PublicKey` into the corresponding `PeerId`.
    pub fn into_peer_id(self) -> Result<PeerId> {
        PeerId::from_public_key(self)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn print_keys_proto_path() {
        let file_path = concat!(env!("OUT_DIR"), "/key_pair_proto.rs");
        println!(".... key_pair_proto file: {}", file_path);
    }
}

#[cfg(test)]
#[path = "identity_test.rs"]
mod identity_test;
