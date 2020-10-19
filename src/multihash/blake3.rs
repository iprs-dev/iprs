use crate::{Error, Result};

#[derive(Clone)]
pub(crate) struct Blake3 {
    hasher: blake3::Hasher,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake3 {}

impl PartialEq for Blake3 {
    fn eq(&self, other: &Blake3) -> bool {
        self.digest == other.digest
    }
}

impl Blake3 {
    pub(crate) fn from_code(_code: u128) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
            digest: None,
        })
    }

    pub(crate) fn decode(_code: u128, digest: &[u8]) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
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
            None => {
                let hash = blake3::Hasher::finalize(&self.hasher);
                Some(hash.as_bytes().to_vec())
            }
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
