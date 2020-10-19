use digest::Digest;

use std::io::Read;

use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) enum Sha3 {
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

impl Sha3 {
    pub(crate) fn from_code(code: u128) -> Result<Sha3> {
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
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn decode(code: u128, digest: &[u8]) -> Result<Sha3> {
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
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
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
            _ => err_at!(Invalid, msg: "finalized")?,
        };
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
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
            _ => err_at!(Invalid, msg: "double finalize")?,
        };
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
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

    pub(crate) fn as_digest(&self) -> Result<&[u8]> {
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
            _ => err_at!(Invalid, msg: "no digest"),
        }
    }
}
