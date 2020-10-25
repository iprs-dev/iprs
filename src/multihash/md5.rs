use crate::{Error, Result};

#[derive(Clone)]
pub(crate) struct Md5 {
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Md5 {}

impl PartialEq for Md5 {
    fn eq(&self, other: &Md5) -> bool {
        self.digest == other.digest
    }
}

impl Md5 {
    pub(crate) fn from_code(_code: u128) -> Result<Md5> {
        Ok(Md5 {
            buf: Vec::default(),
            digest: None,
        })
    }

    pub(crate) fn decode(_code: u128, buf: &[u8]) -> Result<Md5> {
        Ok(Md5 {
            buf: Vec::default(),
            digest: Some(buf.to_vec()),
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
            None => {
                let digest: [u8; 16] = md5::compute(&self.buf).into();
                Some(digest.to_vec())
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
