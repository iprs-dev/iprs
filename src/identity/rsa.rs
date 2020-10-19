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

//! RSA keys

use asn1_der::{Asn1Der, Asn1DerError, DerObject, DerTag, DerValue, FromDerObject, IntoDerObject};
use lazy_static::lazy_static;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use ring::signature::{RsaKeyPair, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256};
use zeroize::Zeroize;

use std::{
    fmt::{self, Write},
    result,
    sync::Arc,
};

use crate::{Error, Result};

// TODO: should we zeroize Keypair upon Drop ?

/// An RSA keypair.
#[derive(Clone)]
pub struct Keypair {
    key_pair: Arc<RsaKeyPair>,
}

impl Keypair {
    /// Decode an RSA keypair from a DER-encoded private key in PKCS#8
    /// PrivateKeyInfo format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    pub fn from_pkcs8(der: &mut [u8]) -> Result<Keypair> {
        let key_pair = match RsaKeyPair::from_pkcs8(&der) {
            Ok(val) => Ok(val),
            Err(err) => err_at!(DecodeError, Err(err), "RSA PKCS#8 PrivateKeyInfo"),
        }?;

        der.zeroize();

        Ok(Keypair {
            key_pair: Arc::new(key_pair),
        })
    }

    /// Get public key from the keypair.
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            bin: self.key_pair.public_key().as_ref().to_vec(),
        }
    }

    // TODO: should we try drand.love ?
    /// Sign a message with this keypair.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0; self.key_pair.public_modulus_len()];
        let rng = SystemRandom::new();
        match self.key_pair.sign(&RSA_PKCS1_SHA256, &rng, &data, &mut sig) {
            Ok(()) => Ok(sig),
            Err(err) => err_at!(SigningError, Err(err), "RSA PublicKey Signing"),
        }
    }
}

/// An RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey {
    bin: Vec<u8>,
}

impl PublicKey {
    /// Verify an RSA signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        use ring::signature::UnparsedPublicKey;

        let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.bin);
        key.verify(msg, signature).is_ok()
    }

    /// Encode the RSA public key in DER as a PKCS#1 RSAPublicKey structure,
    /// as defined in [RFC3447].
    ///
    /// [RFC3447]: https://tools.ietf.org/html/rfc3447#appendix-A.1.1
    pub fn encode_pkcs1(&self) -> Vec<u8> {
        // This is the encoding currently used in-memory, so it is trivial.
        self.bin.clone()
    }

    /// Encode the RSA public key in DER as a X.509 SubjectPublicKeyInfo
    /// structure, as defined in [RFC5280].
    ///
    /// [RFC5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    pub fn encode_x509(&self) -> Result<Vec<u8>> {
        let spki = Asn1SubjectPublicKeyInfo {
            algo: Asn1RsaEncryption {
                algorithm: Asn1OidRsaEncryption(),
                parameters: (),
            },
            subject_public_key: Asn1SubjectPublicKey(self.clone()),
        };

        let mut buf = vec![0u8; spki.serialized_len()];

        match spki.serialize(buf.iter_mut()) {
            Ok(_) => Ok(buf),
            Err(err) => err_at!(
                EncodeError,
                Err(err),
                "RSA X.509 public key encoding failed"
            ),
        }
    }

    /// Decode an RSA public key from a DER-encoded X.509 SubjectPublicKeyInfo
    /// structure. See also `encode_x509`.
    pub fn decode_x509(data: &[u8]) -> Result<PublicKey> {
        match Asn1SubjectPublicKeyInfo::deserialize(data.iter()) {
            Ok(val) => Ok(val.subject_public_key.0),
            Err(err) => err_at!(DecodeError, Err(err), "RSA X.509")?,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.bin;
        let mut hex = String::with_capacity(bytes.len() * 2);

        for byte in bytes {
            write!(hex, "{:02x}", byte).expect("Can't fail on writing to string");
        }

        f.debug_struct("PublicKey").field("pkcs1", &hex).finish()
    }
}

//////////////////////////////////////////////////////////////////////////////
// DER encoding / decoding of public keys
//
// Primer: http://luca.ntop.org/Teaching/Appunti/asn1.html
// Playground: https://lapo.it/asn1js/

lazy_static! {
    /// The DER encoding of the object identifier (OID) 'rsaEncryption' for
    /// RSA public keys defined for X.509 in [RFC-3279] and used in
    /// SubjectPublicKeyInfo structures defined in [RFC-5280].
    ///
    /// [RFC-3279]: https://tools.ietf.org/html/rfc3279#section-2.3.1
    /// [RFC-5280]: https://tools.ietf.org/html/rfc5280#section-4.1
    static ref OID_RSA_ENCRYPTION_DER: DerObject =
        DerObject {
            tag: DerTag::x06,
            value: DerValue {
                data: vec![ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 ]
            }
        };
}

/// The ASN.1 OID for "rsaEncryption".
#[derive(Clone)]
struct Asn1OidRsaEncryption();

impl IntoDerObject for Asn1OidRsaEncryption {
    fn into_der_object(self) -> DerObject {
        OID_RSA_ENCRYPTION_DER.clone()
    }
    fn serialized_len(&self) -> usize {
        OID_RSA_ENCRYPTION_DER.serialized_len()
    }
}

impl FromDerObject for Asn1OidRsaEncryption {
    fn from_der_object(o: DerObject) -> result::Result<Self, Asn1DerError> {
        if o.tag != DerTag::x06 {
            return Err(Asn1DerError::InvalidTag);
        }
        if o.value != OID_RSA_ENCRYPTION_DER.value {
            return Err(Asn1DerError::InvalidEncoding);
        }
        Ok(Asn1OidRsaEncryption())
    }
}

/// The ASN.1 AlgorithmIdentifier for "rsaEncryption".
#[derive(Asn1Der)]
struct Asn1RsaEncryption {
    algorithm: Asn1OidRsaEncryption,
    parameters: (),
}

/// The ASN.1 SubjectPublicKey inside a SubjectPublicKeyInfo,
/// i.e. encoded as a DER BIT STRING.
struct Asn1SubjectPublicKey(PublicKey);

impl IntoDerObject for Asn1SubjectPublicKey {
    fn into_der_object(self) -> DerObject {
        let pk_der = (self.0).bin;
        let mut bit_string = Vec::with_capacity(pk_der.len() + 1);
        // The number of bits in pk_der is trivially always a multiple of 8,
        // so there are always 0 "unused bits" signaled by the first byte.
        bit_string.push(0u8);
        bit_string.extend(pk_der);
        DerObject::new(DerTag::x03, bit_string.into())
    }
    fn serialized_len(&self) -> usize {
        DerObject::compute_serialized_len((self.0).bin.len() + 1)
    }
}

impl FromDerObject for Asn1SubjectPublicKey {
    fn from_der_object(o: DerObject) -> result::Result<Self, Asn1DerError> {
        if o.tag != DerTag::x03 {
            return Err(Asn1DerError::InvalidTag);
        }
        let pk_der: Vec<u8> = o.value.data.into_iter().skip(1).collect();
        // We don't parse pk_der further as an ASN.1 RsaPublicKey, since
        // we only need the DER encoding for `verify`.
        Ok(Asn1SubjectPublicKey(PublicKey { bin: pk_der }))
    }
}

/// ASN.1 SubjectPublicKeyInfo
#[derive(Asn1Der)]
#[allow(non_snake_case)]
struct Asn1SubjectPublicKeyInfo {
    algo: Asn1RsaEncryption,
    subject_public_key: Asn1SubjectPublicKey,
}

#[cfg(test)]
#[path = "rsa_test.rs"]
mod rsa_test;
