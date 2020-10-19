use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) struct Blake2s {
    code: u128,
    hasher: blake2s_simd::State,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake2s {}

impl PartialEq for Blake2s {
    fn eq(&self, other: &Blake2s) -> bool {
        self.digest == other.digest
    }
}

impl Blake2s {
    pub(crate) fn from_code(code: u128) -> Result<Blake2s> {
        use blake2s_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2s {
            code,
            hasher: hasher.to_state(),
            digest: None,
        })
    }

    pub(crate) fn decode(code: u128, digest: &[u8]) -> Result<Blake2s> {
        use blake2s_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2s {
            code,
            hasher: hasher.to_state(),
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
            None => Some(self.hasher.finalize().as_bytes().to_vec()),
            Some(_) => err_at!(Invalid, msg: "double finalize")?,
        };
        Ok(())
    }

    pub(crate) fn reset(&mut self) -> Result<()> {
        use blake2s_simd::Params;

        self.hasher = {
            let mut hasher = Params::new();
            hasher.hash_length(Self::to_digest_bits(self.code)?);
            hasher.to_state()
        };
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

impl Blake2s {
    fn to_digest_bits(code: u128) -> Result<usize> {
        let len = match code {
            multicodec::BLAKE2S_8 => 8,
            multicodec::BLAKE2S_16 => 16,
            multicodec::BLAKE2S_24 => 24,
            multicodec::BLAKE2S_32 => 32,
            multicodec::BLAKE2S_40 => 40,
            multicodec::BLAKE2S_48 => 48,
            multicodec::BLAKE2S_56 => 56,
            multicodec::BLAKE2S_64 => 64,
            multicodec::BLAKE2S_72 => 72,
            multicodec::BLAKE2S_80 => 80,
            multicodec::BLAKE2S_88 => 88,
            multicodec::BLAKE2S_96 => 96,
            multicodec::BLAKE2S_104 => 104,
            multicodec::BLAKE2S_112 => 112,
            multicodec::BLAKE2S_120 => 120,
            multicodec::BLAKE2S_128 => 128,
            multicodec::BLAKE2S_136 => 136,
            multicodec::BLAKE2S_144 => 144,
            multicodec::BLAKE2S_152 => 152,
            multicodec::BLAKE2S_160 => 160,
            multicodec::BLAKE2S_168 => 168,
            multicodec::BLAKE2S_176 => 176,
            multicodec::BLAKE2S_184 => 184,
            multicodec::BLAKE2S_192 => 192,
            multicodec::BLAKE2S_200 => 200,
            multicodec::BLAKE2S_208 => 208,
            multicodec::BLAKE2S_216 => 216,
            multicodec::BLAKE2S_224 => 224,
            multicodec::BLAKE2S_232 => 232,
            multicodec::BLAKE2S_240 => 240,
            multicodec::BLAKE2S_248 => 248,
            multicodec::BLAKE2S_256 => 256,
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(len)
    }
}
