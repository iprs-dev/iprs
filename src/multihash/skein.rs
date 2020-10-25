use crate::{multicodec, Error, Result};

#[derive(Clone)]
pub(crate) struct Skein {
    code: u128,
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Eq for Skein {}

impl PartialEq for Skein {
    fn eq(&self, other: &Skein) -> bool {
        self.digest == other.digest
    }
}

macro_rules! skein_digest {
    ($type:ident, $dtype:ty, $data:expr) => {{
        use skein_hash::Digest;

        let mut hasher: skein_hash::$type<$dtype> = Default::default();
        hasher.input($data);
        hasher.result().to_vec()
    }};
}

impl Skein {
    pub(crate) fn from_code(code: u128) -> Result<Skein> {
        Ok(Skein {
            code,
            buf: Vec::default(),
            digest: None,
        })
    }

    pub(crate) fn decode(code: u128, buf: &[u8]) -> Result<Skein> {
        Ok(Skein {
            code,
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
        use digest::consts;

        let digest = match &self.digest {
            None => match self.code {
                multicodec::SKEIN256_8 => skein_digest!(Skein256, consts::U8, &self.buf),
                multicodec::SKEIN256_16 => skein_digest!(Skein256, consts::U16, &self.buf),
                multicodec::SKEIN256_24 => skein_digest!(Skein256, consts::U24, &self.buf),
                multicodec::SKEIN256_32 => skein_digest!(Skein256, consts::U32, &self.buf),
                multicodec::SKEIN256_40 => skein_digest!(Skein256, consts::U40, &self.buf),
                multicodec::SKEIN256_48 => skein_digest!(Skein256, consts::U48, &self.buf),
                multicodec::SKEIN256_56 => skein_digest!(Skein256, consts::U56, &self.buf),
                multicodec::SKEIN256_64 => skein_digest!(Skein256, consts::U64, &self.buf),
                multicodec::SKEIN256_72 => skein_digest!(Skein256, consts::U72, &self.buf),
                multicodec::SKEIN256_80 => skein_digest!(Skein256, consts::U80, &self.buf),
                multicodec::SKEIN256_88 => skein_digest!(Skein256, consts::U88, &self.buf),
                multicodec::SKEIN256_96 => skein_digest!(Skein256, consts::U96, &self.buf),
                multicodec::SKEIN256_104 => skein_digest!(Skein256, consts::U104, &self.buf),
                multicodec::SKEIN256_112 => skein_digest!(Skein256, consts::U112, &self.buf),
                multicodec::SKEIN256_120 => skein_digest!(Skein256, consts::U120, &self.buf),
                multicodec::SKEIN256_128 => skein_digest!(Skein256, consts::U128, &self.buf),
                multicodec::SKEIN256_136 => skein_digest!(Skein256, consts::U136, &self.buf),
                multicodec::SKEIN256_144 => skein_digest!(Skein256, consts::U144, &self.buf),
                multicodec::SKEIN256_152 => skein_digest!(Skein256, consts::U152, &self.buf),
                multicodec::SKEIN256_160 => skein_digest!(Skein256, consts::U160, &self.buf),
                multicodec::SKEIN256_168 => skein_digest!(Skein256, consts::U168, &self.buf),
                multicodec::SKEIN256_176 => skein_digest!(Skein256, consts::U176, &self.buf),
                multicodec::SKEIN256_184 => skein_digest!(Skein256, consts::U184, &self.buf),
                multicodec::SKEIN256_192 => skein_digest!(Skein256, consts::U192, &self.buf),
                multicodec::SKEIN256_200 => skein_digest!(Skein256, consts::U200, &self.buf),
                multicodec::SKEIN256_208 => skein_digest!(Skein256, consts::U208, &self.buf),
                multicodec::SKEIN256_216 => skein_digest!(Skein256, consts::U216, &self.buf),
                multicodec::SKEIN256_224 => skein_digest!(Skein256, consts::U224, &self.buf),
                multicodec::SKEIN256_232 => skein_digest!(Skein256, consts::U232, &self.buf),
                multicodec::SKEIN256_240 => skein_digest!(Skein256, consts::U240, &self.buf),
                multicodec::SKEIN256_248 => skein_digest!(Skein256, consts::U248, &self.buf),
                multicodec::SKEIN256_256 => skein_digest!(Skein256, consts::U256, &self.buf),
                multicodec::SKEIN512_8 => skein_digest!(Skein512, consts::U8, &self.buf),
                multicodec::SKEIN512_16 => skein_digest!(Skein512, consts::U16, &self.buf),
                multicodec::SKEIN512_24 => skein_digest!(Skein512, consts::U24, &self.buf),
                multicodec::SKEIN512_32 => skein_digest!(Skein512, consts::U32, &self.buf),
                multicodec::SKEIN512_40 => skein_digest!(Skein512, consts::U40, &self.buf),
                multicodec::SKEIN512_48 => skein_digest!(Skein512, consts::U48, &self.buf),
                multicodec::SKEIN512_56 => skein_digest!(Skein512, consts::U56, &self.buf),
                multicodec::SKEIN512_64 => skein_digest!(Skein512, consts::U64, &self.buf),
                multicodec::SKEIN512_72 => skein_digest!(Skein512, consts::U72, &self.buf),
                multicodec::SKEIN512_80 => skein_digest!(Skein512, consts::U80, &self.buf),
                multicodec::SKEIN512_88 => skein_digest!(Skein512, consts::U88, &self.buf),
                multicodec::SKEIN512_96 => skein_digest!(Skein512, consts::U96, &self.buf),
                multicodec::SKEIN512_104 => skein_digest!(Skein512, consts::U104, &self.buf),
                multicodec::SKEIN512_112 => skein_digest!(Skein512, consts::U112, &self.buf),
                multicodec::SKEIN512_120 => skein_digest!(Skein512, consts::U120, &self.buf),
                multicodec::SKEIN512_128 => skein_digest!(Skein512, consts::U128, &self.buf),
                multicodec::SKEIN512_136 => skein_digest!(Skein512, consts::U136, &self.buf),
                multicodec::SKEIN512_144 => skein_digest!(Skein512, consts::U144, &self.buf),
                multicodec::SKEIN512_152 => skein_digest!(Skein512, consts::U152, &self.buf),
                multicodec::SKEIN512_160 => skein_digest!(Skein512, consts::U160, &self.buf),
                multicodec::SKEIN512_168 => skein_digest!(Skein512, consts::U168, &self.buf),
                multicodec::SKEIN512_176 => skein_digest!(Skein512, consts::U176, &self.buf),
                multicodec::SKEIN512_184 => skein_digest!(Skein512, consts::U184, &self.buf),
                multicodec::SKEIN512_192 => skein_digest!(Skein512, consts::U192, &self.buf),
                multicodec::SKEIN512_200 => skein_digest!(Skein512, consts::U200, &self.buf),
                multicodec::SKEIN512_208 => skein_digest!(Skein512, consts::U208, &self.buf),
                multicodec::SKEIN512_216 => skein_digest!(Skein512, consts::U216, &self.buf),
                multicodec::SKEIN512_224 => skein_digest!(Skein512, consts::U224, &self.buf),
                multicodec::SKEIN512_232 => skein_digest!(Skein512, consts::U232, &self.buf),
                multicodec::SKEIN512_240 => skein_digest!(Skein512, consts::U240, &self.buf),
                multicodec::SKEIN512_248 => skein_digest!(Skein512, consts::U248, &self.buf),
                multicodec::SKEIN512_256 => skein_digest!(Skein512, consts::U256, &self.buf),
                multicodec::SKEIN512_264 => skein_digest!(Skein512, consts::U264, &self.buf),
                multicodec::SKEIN512_272 => skein_digest!(Skein512, consts::U272, &self.buf),
                multicodec::SKEIN512_280 => skein_digest!(Skein512, consts::U280, &self.buf),
                multicodec::SKEIN512_288 => skein_digest!(Skein512, consts::U288, &self.buf),
                multicodec::SKEIN512_296 => skein_digest!(Skein512, consts::U296, &self.buf),
                multicodec::SKEIN512_304 => skein_digest!(Skein512, consts::U304, &self.buf),
                multicodec::SKEIN512_312 => skein_digest!(Skein512, consts::U312, &self.buf),
                multicodec::SKEIN512_320 => skein_digest!(Skein512, consts::U320, &self.buf),
                multicodec::SKEIN512_328 => skein_digest!(Skein512, consts::U328, &self.buf),
                multicodec::SKEIN512_336 => skein_digest!(Skein512, consts::U336, &self.buf),
                multicodec::SKEIN512_344 => skein_digest!(Skein512, consts::U344, &self.buf),
                multicodec::SKEIN512_352 => skein_digest!(Skein512, consts::U352, &self.buf),
                multicodec::SKEIN512_360 => skein_digest!(Skein512, consts::U360, &self.buf),
                multicodec::SKEIN512_368 => skein_digest!(Skein512, consts::U368, &self.buf),
                multicodec::SKEIN512_376 => skein_digest!(Skein512, consts::U376, &self.buf),
                multicodec::SKEIN512_384 => skein_digest!(Skein512, consts::U384, &self.buf),
                multicodec::SKEIN512_392 => skein_digest!(Skein512, consts::U392, &self.buf),
                multicodec::SKEIN512_400 => skein_digest!(Skein512, consts::U400, &self.buf),
                multicodec::SKEIN512_408 => skein_digest!(Skein512, consts::U408, &self.buf),
                multicodec::SKEIN512_416 => skein_digest!(Skein512, consts::U416, &self.buf),
                multicodec::SKEIN512_424 => skein_digest!(Skein512, consts::U424, &self.buf),
                multicodec::SKEIN512_432 => skein_digest!(Skein512, consts::U432, &self.buf),
                multicodec::SKEIN512_440 => skein_digest!(Skein512, consts::U440, &self.buf),
                multicodec::SKEIN512_448 => skein_digest!(Skein512, consts::U448, &self.buf),
                multicodec::SKEIN512_456 => skein_digest!(Skein512, consts::U456, &self.buf),
                multicodec::SKEIN512_464 => skein_digest!(Skein512, consts::U464, &self.buf),
                multicodec::SKEIN512_472 => skein_digest!(Skein512, consts::U472, &self.buf),
                multicodec::SKEIN512_480 => skein_digest!(Skein512, consts::U480, &self.buf),
                multicodec::SKEIN512_488 => skein_digest!(Skein512, consts::U488, &self.buf),
                multicodec::SKEIN512_496 => skein_digest!(Skein512, consts::U496, &self.buf),
                multicodec::SKEIN512_504 => skein_digest!(Skein512, consts::U504, &self.buf),
                multicodec::SKEIN512_512 => skein_digest!(Skein512, consts::U512, &self.buf),
                multicodec::SKEIN1024_8 => skein_digest!(Skein1024, consts::U8, &self.buf),
                multicodec::SKEIN1024_16 => skein_digest!(Skein1024, consts::U16, &self.buf),
                multicodec::SKEIN1024_24 => skein_digest!(Skein1024, consts::U24, &self.buf),
                multicodec::SKEIN1024_32 => skein_digest!(Skein1024, consts::U32, &self.buf),
                multicodec::SKEIN1024_40 => skein_digest!(Skein1024, consts::U40, &self.buf),
                multicodec::SKEIN1024_48 => skein_digest!(Skein1024, consts::U48, &self.buf),
                multicodec::SKEIN1024_56 => skein_digest!(Skein1024, consts::U56, &self.buf),
                multicodec::SKEIN1024_64 => skein_digest!(Skein1024, consts::U64, &self.buf),
                multicodec::SKEIN1024_72 => skein_digest!(Skein1024, consts::U72, &self.buf),
                multicodec::SKEIN1024_80 => skein_digest!(Skein1024, consts::U80, &self.buf),
                multicodec::SKEIN1024_88 => skein_digest!(Skein1024, consts::U88, &self.buf),
                multicodec::SKEIN1024_96 => skein_digest!(Skein1024, consts::U96, &self.buf),
                multicodec::SKEIN1024_104 => skein_digest!(Skein1024, consts::U104, &self.buf),
                multicodec::SKEIN1024_112 => skein_digest!(Skein1024, consts::U112, &self.buf),
                multicodec::SKEIN1024_120 => skein_digest!(Skein1024, consts::U120, &self.buf),
                multicodec::SKEIN1024_128 => skein_digest!(Skein1024, consts::U128, &self.buf),
                multicodec::SKEIN1024_136 => skein_digest!(Skein1024, consts::U136, &self.buf),
                multicodec::SKEIN1024_144 => skein_digest!(Skein1024, consts::U144, &self.buf),
                multicodec::SKEIN1024_152 => skein_digest!(Skein1024, consts::U152, &self.buf),
                multicodec::SKEIN1024_160 => skein_digest!(Skein1024, consts::U160, &self.buf),
                multicodec::SKEIN1024_168 => skein_digest!(Skein1024, consts::U168, &self.buf),
                multicodec::SKEIN1024_176 => skein_digest!(Skein1024, consts::U176, &self.buf),
                multicodec::SKEIN1024_184 => skein_digest!(Skein1024, consts::U184, &self.buf),
                multicodec::SKEIN1024_192 => skein_digest!(Skein1024, consts::U192, &self.buf),
                multicodec::SKEIN1024_200 => skein_digest!(Skein1024, consts::U200, &self.buf),
                multicodec::SKEIN1024_208 => skein_digest!(Skein1024, consts::U208, &self.buf),
                multicodec::SKEIN1024_216 => skein_digest!(Skein1024, consts::U216, &self.buf),
                multicodec::SKEIN1024_224 => skein_digest!(Skein1024, consts::U224, &self.buf),
                multicodec::SKEIN1024_232 => skein_digest!(Skein1024, consts::U232, &self.buf),
                multicodec::SKEIN1024_240 => skein_digest!(Skein1024, consts::U240, &self.buf),
                multicodec::SKEIN1024_248 => skein_digest!(Skein1024, consts::U248, &self.buf),
                multicodec::SKEIN1024_256 => skein_digest!(Skein1024, consts::U256, &self.buf),
                multicodec::SKEIN1024_264 => skein_digest!(Skein1024, consts::U264, &self.buf),
                multicodec::SKEIN1024_272 => skein_digest!(Skein1024, consts::U272, &self.buf),
                multicodec::SKEIN1024_280 => skein_digest!(Skein1024, consts::U280, &self.buf),
                multicodec::SKEIN1024_288 => skein_digest!(Skein1024, consts::U288, &self.buf),
                multicodec::SKEIN1024_296 => skein_digest!(Skein1024, consts::U296, &self.buf),
                multicodec::SKEIN1024_304 => skein_digest!(Skein1024, consts::U304, &self.buf),
                multicodec::SKEIN1024_312 => skein_digest!(Skein1024, consts::U312, &self.buf),
                multicodec::SKEIN1024_320 => skein_digest!(Skein1024, consts::U320, &self.buf),
                multicodec::SKEIN1024_328 => skein_digest!(Skein1024, consts::U328, &self.buf),
                multicodec::SKEIN1024_336 => skein_digest!(Skein1024, consts::U336, &self.buf),
                multicodec::SKEIN1024_344 => skein_digest!(Skein1024, consts::U344, &self.buf),
                multicodec::SKEIN1024_352 => skein_digest!(Skein1024, consts::U352, &self.buf),
                multicodec::SKEIN1024_360 => skein_digest!(Skein1024, consts::U360, &self.buf),
                multicodec::SKEIN1024_368 => skein_digest!(Skein1024, consts::U368, &self.buf),
                multicodec::SKEIN1024_376 => skein_digest!(Skein1024, consts::U376, &self.buf),
                multicodec::SKEIN1024_384 => skein_digest!(Skein1024, consts::U384, &self.buf),
                multicodec::SKEIN1024_392 => skein_digest!(Skein1024, consts::U392, &self.buf),
                multicodec::SKEIN1024_400 => skein_digest!(Skein1024, consts::U400, &self.buf),
                multicodec::SKEIN1024_408 => skein_digest!(Skein1024, consts::U408, &self.buf),
                multicodec::SKEIN1024_416 => skein_digest!(Skein1024, consts::U416, &self.buf),
                multicodec::SKEIN1024_424 => skein_digest!(Skein1024, consts::U424, &self.buf),
                multicodec::SKEIN1024_432 => skein_digest!(Skein1024, consts::U432, &self.buf),
                multicodec::SKEIN1024_440 => skein_digest!(Skein1024, consts::U440, &self.buf),
                multicodec::SKEIN1024_448 => skein_digest!(Skein1024, consts::U448, &self.buf),
                multicodec::SKEIN1024_456 => skein_digest!(Skein1024, consts::U456, &self.buf),
                multicodec::SKEIN1024_464 => skein_digest!(Skein1024, consts::U464, &self.buf),
                multicodec::SKEIN1024_472 => skein_digest!(Skein1024, consts::U472, &self.buf),
                multicodec::SKEIN1024_480 => skein_digest!(Skein1024, consts::U480, &self.buf),
                multicodec::SKEIN1024_488 => skein_digest!(Skein1024, consts::U488, &self.buf),
                multicodec::SKEIN1024_496 => skein_digest!(Skein1024, consts::U496, &self.buf),
                multicodec::SKEIN1024_504 => skein_digest!(Skein1024, consts::U504, &self.buf),
                multicodec::SKEIN1024_512 => skein_digest!(Skein1024, consts::U512, &self.buf),
                multicodec::SKEIN1024_520 => skein_digest!(Skein1024, consts::U520, &self.buf),
                multicodec::SKEIN1024_528 => skein_digest!(Skein1024, consts::U528, &self.buf),
                multicodec::SKEIN1024_536 => skein_digest!(Skein1024, consts::U536, &self.buf),
                multicodec::SKEIN1024_544 => skein_digest!(Skein1024, consts::U544, &self.buf),
                multicodec::SKEIN1024_552 => skein_digest!(Skein1024, consts::U552, &self.buf),
                multicodec::SKEIN1024_560 => skein_digest!(Skein1024, consts::U560, &self.buf),
                multicodec::SKEIN1024_568 => skein_digest!(Skein1024, consts::U568, &self.buf),
                multicodec::SKEIN1024_576 => skein_digest!(Skein1024, consts::U576, &self.buf),
                multicodec::SKEIN1024_584 => skein_digest!(Skein1024, consts::U584, &self.buf),
                multicodec::SKEIN1024_592 => skein_digest!(Skein1024, consts::U592, &self.buf),
                multicodec::SKEIN1024_600 => skein_digest!(Skein1024, consts::U600, &self.buf),
                multicodec::SKEIN1024_608 => skein_digest!(Skein1024, consts::U608, &self.buf),
                multicodec::SKEIN1024_616 => skein_digest!(Skein1024, consts::U616, &self.buf),
                multicodec::SKEIN1024_624 => skein_digest!(Skein1024, consts::U624, &self.buf),
                multicodec::SKEIN1024_632 => skein_digest!(Skein1024, consts::U632, &self.buf),
                multicodec::SKEIN1024_640 => skein_digest!(Skein1024, consts::U640, &self.buf),
                multicodec::SKEIN1024_648 => skein_digest!(Skein1024, consts::U648, &self.buf),
                multicodec::SKEIN1024_656 => skein_digest!(Skein1024, consts::U656, &self.buf),
                multicodec::SKEIN1024_664 => skein_digest!(Skein1024, consts::U664, &self.buf),
                multicodec::SKEIN1024_672 => skein_digest!(Skein1024, consts::U672, &self.buf),
                multicodec::SKEIN1024_680 => skein_digest!(Skein1024, consts::U680, &self.buf),
                multicodec::SKEIN1024_688 => skein_digest!(Skein1024, consts::U688, &self.buf),
                multicodec::SKEIN1024_696 => skein_digest!(Skein1024, consts::U696, &self.buf),
                multicodec::SKEIN1024_704 => skein_digest!(Skein1024, consts::U704, &self.buf),
                multicodec::SKEIN1024_712 => skein_digest!(Skein1024, consts::U712, &self.buf),
                multicodec::SKEIN1024_720 => skein_digest!(Skein1024, consts::U720, &self.buf),
                multicodec::SKEIN1024_728 => skein_digest!(Skein1024, consts::U728, &self.buf),
                multicodec::SKEIN1024_736 => skein_digest!(Skein1024, consts::U736, &self.buf),
                multicodec::SKEIN1024_744 => skein_digest!(Skein1024, consts::U744, &self.buf),
                multicodec::SKEIN1024_752 => skein_digest!(Skein1024, consts::U752, &self.buf),
                multicodec::SKEIN1024_760 => skein_digest!(Skein1024, consts::U760, &self.buf),
                multicodec::SKEIN1024_768 => skein_digest!(Skein1024, consts::U768, &self.buf),
                multicodec::SKEIN1024_776 => skein_digest!(Skein1024, consts::U776, &self.buf),
                multicodec::SKEIN1024_784 => skein_digest!(Skein1024, consts::U784, &self.buf),
                multicodec::SKEIN1024_792 => skein_digest!(Skein1024, consts::U792, &self.buf),
                multicodec::SKEIN1024_800 => skein_digest!(Skein1024, consts::U800, &self.buf),
                multicodec::SKEIN1024_808 => skein_digest!(Skein1024, consts::U808, &self.buf),
                multicodec::SKEIN1024_816 => skein_digest!(Skein1024, consts::U816, &self.buf),
                multicodec::SKEIN1024_824 => skein_digest!(Skein1024, consts::U824, &self.buf),
                multicodec::SKEIN1024_832 => skein_digest!(Skein1024, consts::U832, &self.buf),
                multicodec::SKEIN1024_840 => skein_digest!(Skein1024, consts::U840, &self.buf),
                multicodec::SKEIN1024_848 => skein_digest!(Skein1024, consts::U848, &self.buf),
                multicodec::SKEIN1024_856 => skein_digest!(Skein1024, consts::U856, &self.buf),
                multicodec::SKEIN1024_864 => skein_digest!(Skein1024, consts::U864, &self.buf),
                multicodec::SKEIN1024_872 => skein_digest!(Skein1024, consts::U872, &self.buf),
                multicodec::SKEIN1024_880 => skein_digest!(Skein1024, consts::U880, &self.buf),
                multicodec::SKEIN1024_888 => skein_digest!(Skein1024, consts::U888, &self.buf),
                multicodec::SKEIN1024_896 => skein_digest!(Skein1024, consts::U896, &self.buf),
                multicodec::SKEIN1024_904 => skein_digest!(Skein1024, consts::U904, &self.buf),
                multicodec::SKEIN1024_912 => skein_digest!(Skein1024, consts::U912, &self.buf),
                multicodec::SKEIN1024_920 => skein_digest!(Skein1024, consts::U920, &self.buf),
                multicodec::SKEIN1024_928 => skein_digest!(Skein1024, consts::U928, &self.buf),
                multicodec::SKEIN1024_936 => skein_digest!(Skein1024, consts::U936, &self.buf),
                multicodec::SKEIN1024_944 => skein_digest!(Skein1024, consts::U944, &self.buf),
                multicodec::SKEIN1024_952 => skein_digest!(Skein1024, consts::U952, &self.buf),
                multicodec::SKEIN1024_960 => skein_digest!(Skein1024, consts::U960, &self.buf),
                multicodec::SKEIN1024_968 => skein_digest!(Skein1024, consts::U968, &self.buf),
                multicodec::SKEIN1024_976 => skein_digest!(Skein1024, consts::U976, &self.buf),
                multicodec::SKEIN1024_984 => skein_digest!(Skein1024, consts::U984, &self.buf),
                multicodec::SKEIN1024_992 => skein_digest!(Skein1024, consts::U992, &self.buf),
                multicodec::SKEIN1024_1000 => skein_digest!(Skein1024, consts::U1000, &self.buf),
                multicodec::SKEIN1024_1008 => skein_digest!(Skein1024, consts::U1008, &self.buf),
                multicodec::SKEIN1024_1016 => skein_digest!(Skein1024, consts::U1016, &self.buf),
                multicodec::SKEIN1024_1024 => skein_digest!(Skein1024, consts::U1024, &self.buf),
                _ => err_at!(Invalid, msg: "unreachable")?,
            },
            Some(_) => err_at!(Invalid, msg: "double finalize")?,
        };
        self.digest = Some(digest);
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
