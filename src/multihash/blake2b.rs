use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) struct Blake2b {
    code: u128,
    hasher: blake2b_simd::State,
    digest: Option<Vec<u8>>,
}

impl Eq for Blake2b {}

impl PartialEq for Blake2b {
    fn eq(&self, other: &Blake2b) -> bool {
        self.digest == other.digest
    }
}

impl Blake2b {
    fn to_digest_bits(code: u128) -> Result<usize> {
        let len = match code {
            multicodec::BLAKE2B_8 => 8,
            multicodec::BLAKE2B_16 => 16,
            multicodec::BLAKE2B_24 => 24,
            multicodec::BLAKE2B_32 => 32,
            multicodec::BLAKE2B_40 => 40,
            multicodec::BLAKE2B_48 => 48,
            multicodec::BLAKE2B_56 => 56,
            multicodec::BLAKE2B_64 => 64,
            multicodec::BLAKE2B_72 => 72,
            multicodec::BLAKE2B_80 => 80,
            multicodec::BLAKE2B_88 => 88,
            multicodec::BLAKE2B_96 => 96,
            multicodec::BLAKE2B_104 => 104,
            multicodec::BLAKE2B_112 => 112,
            multicodec::BLAKE2B_120 => 120,
            multicodec::BLAKE2B_128 => 128,
            multicodec::BLAKE2B_136 => 136,
            multicodec::BLAKE2B_144 => 144,
            multicodec::BLAKE2B_152 => 152,
            multicodec::BLAKE2B_160 => 160,
            multicodec::BLAKE2B_168 => 168,
            multicodec::BLAKE2B_176 => 176,
            multicodec::BLAKE2B_184 => 184,
            multicodec::BLAKE2B_192 => 192,
            multicodec::BLAKE2B_200 => 200,
            multicodec::BLAKE2B_208 => 208,
            multicodec::BLAKE2B_216 => 216,
            multicodec::BLAKE2B_224 => 224,
            multicodec::BLAKE2B_232 => 232,
            multicodec::BLAKE2B_240 => 240,
            multicodec::BLAKE2B_248 => 248,
            multicodec::BLAKE2B_256 => 256,
            multicodec::BLAKE2B_264 => 264,
            multicodec::BLAKE2B_272 => 272,
            multicodec::BLAKE2B_280 => 280,
            multicodec::BLAKE2B_288 => 288,
            multicodec::BLAKE2B_296 => 296,
            multicodec::BLAKE2B_304 => 304,
            multicodec::BLAKE2B_312 => 312,
            multicodec::BLAKE2B_320 => 320,
            multicodec::BLAKE2B_328 => 328,
            multicodec::BLAKE2B_336 => 336,
            multicodec::BLAKE2B_344 => 344,
            multicodec::BLAKE2B_352 => 352,
            multicodec::BLAKE2B_360 => 360,
            multicodec::BLAKE2B_368 => 368,
            multicodec::BLAKE2B_376 => 376,
            multicodec::BLAKE2B_384 => 384,
            multicodec::BLAKE2B_392 => 392,
            multicodec::BLAKE2B_400 => 400,
            multicodec::BLAKE2B_408 => 408,
            multicodec::BLAKE2B_416 => 416,
            multicodec::BLAKE2B_424 => 424,
            multicodec::BLAKE2B_432 => 432,
            multicodec::BLAKE2B_440 => 440,
            multicodec::BLAKE2B_448 => 448,
            multicodec::BLAKE2B_456 => 456,
            multicodec::BLAKE2B_464 => 464,
            multicodec::BLAKE2B_472 => 472,
            multicodec::BLAKE2B_480 => 480,
            multicodec::BLAKE2B_488 => 488,
            multicodec::BLAKE2B_496 => 496,
            multicodec::BLAKE2B_504 => 504,
            multicodec::BLAKE2B_512 => 512,
            _ => err_at!(Fatal, msg: "unreachable")?,
        };
        Ok(len)
    }
}

impl Blake2b {
    pub(crate) fn from_code(code: u128) -> Result<Blake2b> {
        use blake2b_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2b {
            code,
            hasher: hasher.to_state(),
            digest: None,
        })
    }

    pub(crate) fn decode(code: u128, digest: &[u8]) -> Result<Blake2b> {
        use blake2b_simd::Params;

        let mut hasher = Params::new();
        hasher.hash_length(Self::to_digest_bits(code)?);
        Ok(Blake2b {
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
        use blake2b_simd::Params;

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
