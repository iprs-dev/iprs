use crate::{Error, Result};

#[derive(Clone)]
pub(crate) struct Identity {
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Identity {}

impl PartialEq for Identity {
    fn eq(&self, other: &Identity) -> bool {
        self.digest == other.digest
    }
}

impl Identity {
    pub(crate) fn from_code(_code: u128) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: None,
        })
    }

    pub(crate) fn decode(_code: u128, digest: &[u8]) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: Some(digest.to_vec()),
        })
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.buf.extend_from_slice(bytes),
            Some(_) => err_at!(Invalid, msg: "finalized")?,
        };
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.buf.drain(..).collect()),
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
