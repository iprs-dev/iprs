//! Module implement IPLD data structures, [Block].
//!
//! A block is raw data accompanied by a CID. The [CID] contains the
//! multihash corresponding to the block.
//!
//! [cid]: https://github.com/multiformats/cid

use std::{fmt, result};

use crate::{cid::Cid, multihash::Multihash, Result};

/// Block composed of Cid and opaque-data.
pub struct Block {
    cid: Cid,
    data: Vec<u8>,
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "[Block {}]", self.cid)
    }
}

impl From<(Cid, Vec<u8>)> for Block {
    fn from((cid, data): (Cid, Vec<u8>)) -> Self {
        Self::new(cid, data)
    }
}

impl Block {
    /// New block from Cid and opaque-data.
    pub fn new(cid: Cid, data: Vec<u8>) -> Self {
        Block { cid, data }
    }

    /// Return the underlying opaque-data.
    pub fn to_block_data(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }

    /// Return reference to underlying opaque-data.
    pub fn as_block_data(&self) -> Result<&[u8]> {
        Ok(&self.data)
    }

    /// Return the Cid for this block.
    pub fn to_cid(&self) -> Result<Cid> {
        Ok(self.cid.clone())
    }

    /// Return the Multihash for this block.
    pub fn to_multihash(&self) -> Result<Multihash> {
        Ok(self.cid.to_multihash())
    }
    /// Verify whether the multihash in Cid, matches with the block's
    /// opaque data.
    pub fn verify(&self) -> Result<bool> {
        let mh = match &self.cid {
            Cid::Zero(mh) => mh,
            Cid::One(_, _, mh) => mh,
        };
        let computed_mh = Multihash::new(mh.to_codec()?, &self.data)?;
        Ok(mh == &computed_mh)
    }
}
