#[cfg(not(target_arch = "wasm32"))]
use ring::signature::RsaKeyPair;

#[allow(unused_imports)]
use crate::{Error, Result};

pub enum KeyPair {
    #[cfg(not(target_arch = "wasm32"))]
    Rsa {
        key_pair: RsaKeyPair,
    },
    _None,
}

impl KeyPair {
    /// Read RSA keypair from a DER-encoded private key in PKCS#8
    /// PrivateKeyInfo format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_pkcs8(mut der: Vec<u8>) -> Result<Self> {
        use zeroize::Zeroize;

        let key_pair = match RsaKeyPair::from_pkcs8(&der) {
            Ok(val) => Ok(val),
            err @ Err(_) => {
                let msg = format!("RSA from_pkcs8 bad DER");
                err_at!(InvalidKeyPair, err, msg)
            }
        }?;
        der.zeroize();
        Ok(KeyPair::Rsa { key_pair })
    }

    /// Return the underlying public-key.
    pub fn to_public_key(&self) -> PublicKey {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            KeyPair::Rsa { key_pair } => {
                use ring::signature::KeyPair as TraitKeyPair;
                let bin = key_pair.public_key().as_ref().to_vec();
                PublicKey { bin }
            }
            KeyPair::_None => unreachable!(),
        }
    }

    /// Sign the data using this key-pair.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(not(target_arch = "wasm32"))]
            KeyPair::Rsa { key_pair } => Self::sign_rsa(key_pair, data),
            KeyPair::_None => {
                let _ = data;
                unreachable!();
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn sign_rsa(key_pair: &RsaKeyPair, data: &[u8]) -> Result<Vec<u8>> {
        use ring::rand::SystemRandom;
        use ring::signature::RSA_PKCS1_SHA256;

        let mut signature = vec![0; key_pair.public_modulus_len()];
        let rng = SystemRandom::new();
        match key_pair.sign(&RSA_PKCS1_SHA256, &rng, &data, &mut signature) {
            Ok(()) => Ok(signature),
            Err(err) => err_at!(InvalidKeyPair, Err(err), format!("RSA signature")),
        }
    }
}

pub struct PublicKey {
    bin: Vec<u8>,
}
