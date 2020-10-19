use digest::Digest;

use crate::{Error, Result};

#[derive(Clone)]
pub(crate) struct Sha1 {
    hasher: sha1::Sha1,
    digest: Option<Vec<u8>>,
}

impl Eq for Sha1 {}

impl PartialEq for Sha1 {
    fn eq(&self, other: &Sha1) -> bool {
        self.digest == other.digest
    }
}

impl Sha1 {
    pub(crate) fn from_code(_code: u128) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: None,
        })
    }

    pub(crate) fn decode(_code: u128, digest: &[u8]) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: Some(digest.to_vec()),
        })
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: "finalized")?,
        };
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.hasher.finalize_reset().to_vec()),
            Some(_) => err_at!(Invalid, msg: "double finalize")?,
        };
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    pub(crate) fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: "no digest"),
        }
    }
}
