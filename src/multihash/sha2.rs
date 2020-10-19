use digest::Digest;

use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) enum Sha2 {
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

impl Sha2 {
    pub(crate) fn from_code(code: u128) -> Result<Sha2> {
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
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn decode(code: u128, digest: &[u8]) -> Result<Sha2> {
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
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
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
            _ => err_at!(Invalid, msg: "finalized")?,
        };
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
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
            _ => err_at!(Invalid, msg: "double finalize")?,
        };
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        let digest = match self {
            Sha2::Algo32 { digest, .. } => digest,
            Sha2::Algo64 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    pub(crate) fn as_digest(&self) -> Result<&[u8]> {
        match self {
            Sha2::Algo32 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha2::Algo64 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: "no digest"),
        }
    }
}
