use digest::Digest;

use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) enum RipeMd {
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

impl RipeMd {
    pub(crate) fn from_code(code: u128) -> Result<RipeMd> {
        let val = match code {
            multicodec::RIPEMD_160 => RipeMd::Algo160 {
                hasher: ripemd160::Ripemd160::new(),
                digest: None,
            },
            multicodec::RIPEMD_320 => RipeMd::Algo320 {
                hasher: ripemd320::Ripemd320::new(),
                digest: None,
            },
            _ => err_at!(Invalid, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn decode(code: u128, buf: &[u8]) -> Result<RipeMd> {
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
            _ => err_at!(Invalid, msg: "unreachable")?,
        };
        Ok(val)
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            RipeMd::Algo160 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            RipeMd::Algo320 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            _ => err_at!(Invalid, msg: "finalized")?,
        };
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
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
            _ => err_at!(Invalid, msg: "double finalize")?,
        };
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        let digest = match self {
            RipeMd::Algo160 { digest, .. } => digest,
            RipeMd::Algo320 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    pub(crate) fn as_digest(&self) -> Result<&[u8]> {
        match self {
            RipeMd::Algo160 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            RipeMd::Algo320 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: "no digest"),
        }
    }
}
