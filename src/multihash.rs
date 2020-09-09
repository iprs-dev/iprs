use blake3;
use digest::Digest;
use sha1;

use std::io::{self, Read};

use crate::{multicodec, Error, Multicodec, Result};

pub struct Multihash {
    inner: Inner,
}

enum Inner {
    Identity(Multicodec, Identity),
    Sha1(Multicodec, Sha1),
    Sha2(Multicodec, Sha2),
    Sha3(Multicodec, Sha3),
    Blake3(Multicodec, Blake3),
    Murmur3(Multicodec, Murmur3),
}

impl From<Inner> for Multihash {
    fn from(inner: Inner) -> Multihash {
        Multihash { inner }
    }
}

impl Multihash {
    pub fn from_codec(codec: Multicodec) -> Result<Multihash> {
        let code = codec.to_code();
        let inner = match code {
            multicodec::IDENTITY => {
                let hasher = Identity::from_code(code)?;
                Inner::Identity(codec, hasher)
            }
            multicodec::SHA1 => {
                let hasher = Sha1::from_code(code)?;
                Inner::Sha1(codec, hasher)
            }
            multicodec::SHA2_256 | multicodec::SHA2_512 => {
                let hasher = Sha2::from_code(code)?;
                Inner::Sha2(codec, hasher)
            }
            multicodec::SHA3_512
            | multicodec::SHA3_384
            | multicodec::SHA3_256
            | multicodec::SHA3_224
            | multicodec::SHAKE_128
            | multicodec::SHAKE_256
            | multicodec::KECCAK_224
            | multicodec::KECCAK_256
            | multicodec::KECCAK_384
            | multicodec::KECCAK_512 => {
                let hasher = Sha3::from_code(code)?;
                Inner::Sha3(codec, hasher)
            }
            multicodec::BLAKE3 => {
                let hasher = Blake3::from_code(code)?;
                Inner::Blake3(codec, hasher)
            }
            multicodec::MURMUR3_32 | multicodec::MURMUR3_128 => {
                let hasher = Murmur3::from_code(code, u32::default())?;
                Inner::Murmur3(codec, hasher)
            }
            //multicodec::DBL_SHA2_256 => (), // "dbl-sha2-256"
            //multicodec::MD4 => (), // "md4"
            //multicodec::MD5 => (), // "md5"
            //multicodec::BMT => (), // "bmt"
            //multicodec::SHA2_256_TRUNC254_PADDED,
            //multicodec::RIPEMD_128 => (), // "ripemd-128"
            //multicodec::RIPEMD_160 => (), // "ripemd-160"
            //multicodec::RIPEMD_256 => (), // "ripemd-256"
            //multicodec::RIPEMD_320 => (), // "ripemd-320"
            //multicodec::X11 => (), // "x11"
            //multicodec::KANGAROOTWELVE => (), // "kangarootwelve"
            //multicodec::SM3_256 => (), // "sm3-256"
            //multicodec::BLAKE2B_8 => (), // "blake2b-8"
            //multicodec::BLAKE2B_16 => (), // "blake2b-16"
            //multicodec::BLAKE2B_24 => (), // "blake2b-24"
            //multicodec::BLAKE2B_32 => (), // "blake2b-32"
            //multicodec::BLAKE2B_40 => (), // "blake2b-40"
            //multicodec::BLAKE2B_48 => (), // "blake2b-48"
            //multicodec::BLAKE2B_56 => (), // "blake2b-56"
            //multicodec::BLAKE2B_64 => (), // "blake2b-64"
            //multicodec::BLAKE2B_72 => (), // "blake2b-72"
            //multicodec::BLAKE2B_80 => (), // "blake2b-80"
            //multicodec::BLAKE2B_88 => (), // "blake2b-88"
            //multicodec::BLAKE2B_96 => (), // "blake2b-96"
            //multicodec::BLAKE2B_104 => (), // "blake2b-104"
            //multicodec::BLAKE2B_112 => (), // "blake2b-112"
            //multicodec::BLAKE2B_120 => (), // "blake2b-120"
            //multicodec::BLAKE2B_128 => (), // "blake2b-128"
            //multicodec::BLAKE2B_136 => (), // "blake2b-136"
            //multicodec::BLAKE2B_144 => (), // "blake2b-144"
            //multicodec::BLAKE2B_152 => (), // "blake2b-152"
            //multicodec::BLAKE2B_160 => (), // "blake2b-160"
            //multicodec::BLAKE2B_168 => (), // "blake2b-168"
            //multicodec::BLAKE2B_176 => (), // "blake2b-176"
            //multicodec::BLAKE2B_184 => (), // "blake2b-184"
            //multicodec::BLAKE2B_192 => (), // "blake2b-192"
            //multicodec::BLAKE2B_200 => (), // "blake2b-200"
            //multicodec::BLAKE2B_208 => (), // "blake2b-208"
            //multicodec::BLAKE2B_216 => (), // "blake2b-216"
            //multicodec::BLAKE2B_224 => (), // "blake2b-224"
            //multicodec::BLAKE2B_232 => (), // "blake2b-232"
            //multicodec::BLAKE2B_240 => (), // "blake2b-240"
            //multicodec::BLAKE2B_248 => (), // "blake2b-248"
            //multicodec::BLAKE2B_256 => (), // "blake2b-256"
            //multicodec::BLAKE2B_264 => (), // "blake2b-264"
            //multicodec::BLAKE2B_272 => (), // "blake2b-272"
            //multicodec::BLAKE2B_280 => (), // "blake2b-280"
            //multicodec::BLAKE2B_288 => (), // "blake2b-288"
            //multicodec::BLAKE2B_296 => (), // "blake2b-296"
            //multicodec::BLAKE2B_304 => (), // "blake2b-304"
            //multicodec::BLAKE2B_312 => (), // "blake2b-312"
            //multicodec::BLAKE2B_320 => (), // "blake2b-320"
            //multicodec::BLAKE2B_328 => (), // "blake2b-328"
            //multicodec::BLAKE2B_336 => (), // "blake2b-336"
            //multicodec::BLAKE2B_344 => (), // "blake2b-344"
            //multicodec::BLAKE2B_352 => (), // "blake2b-352"
            //multicodec::BLAKE2B_360 => (), // "blake2b-360"
            //multicodec::BLAKE2B_368 => (), // "blake2b-368"
            //multicodec::BLAKE2B_376 => (), // "blake2b-376"
            //multicodec::BLAKE2B_384 => (), // "blake2b-384"
            //multicodec::BLAKE2B_392 => (), // "blake2b-392"
            //multicodec::BLAKE2B_400 => (), // "blake2b-400"
            //multicodec::BLAKE2B_408 => (), // "blake2b-408"
            //multicodec::BLAKE2B_416 => (), // "blake2b-416"
            //multicodec::BLAKE2B_424 => (), // "blake2b-424"
            //multicodec::BLAKE2B_432 => (), // "blake2b-432"
            //multicodec::BLAKE2B_440 => (), // "blake2b-440"
            //multicodec::BLAKE2B_448 => (), // "blake2b-448"
            //multicodec::BLAKE2B_456 => (), // "blake2b-456"
            //multicodec::BLAKE2B_464 => (), // "blake2b-464"
            //multicodec::BLAKE2B_472 => (), // "blake2b-472"
            //multicodec::BLAKE2B_480 => (), // "blake2b-480"
            //multicodec::BLAKE2B_488 => (), // "blake2b-488"
            //multicodec::BLAKE2B_496 => (), // "blake2b-496"
            //multicodec::BLAKE2B_504 => (), // "blake2b-504"
            //multicodec::BLAKE2B_512 => (), // "blake2b-512"
            //multicodec::BLAKE2S_8 => (), // "blake2s-8"
            //multicodec::BLAKE2S_16 => (), // "blake2s-16"
            //multicodec::BLAKE2S_24 => (), // "blake2s-24"
            //multicodec::BLAKE2S_32 => (), // "blake2s-32"
            //multicodec::BLAKE2S_40 => (), // "blake2s-40"
            //multicodec::BLAKE2S_48 => (), // "blake2s-48"
            //multicodec::BLAKE2S_56 => (), // "blake2s-56"
            //multicodec::BLAKE2S_64 => (), // "blake2s-64"
            //multicodec::BLAKE2S_72 => (), // "blake2s-72"
            //multicodec::BLAKE2S_80 => (), // "blake2s-80"
            //multicodec::BLAKE2S_88 => (), // "blake2s-88"
            //multicodec::BLAKE2S_96 => (), // "blake2s-96"
            //multicodec::BLAKE2S_104 => (), // "blake2s-104"
            //multicodec::BLAKE2S_112 => (), // "blake2s-112"
            //multicodec::BLAKE2S_120 => (), // "blake2s-120"
            //multicodec::BLAKE2S_128 => (), // "blake2s-128"
            //multicodec::BLAKE2S_136 => (), // "blake2s-136"
            //multicodec::BLAKE2S_144 => (), // "blake2s-144"
            //multicodec::BLAKE2S_152 => (), // "blake2s-152"
            //multicodec::BLAKE2S_160 => (), // "blake2s-160"
            //multicodec::BLAKE2S_168 => (), // "blake2s-168"
            //multicodec::BLAKE2S_176 => (), // "blake2s-176"
            //multicodec::BLAKE2S_184 => (), // "blake2s-184"
            //multicodec::BLAKE2S_192 => (), // "blake2s-192"
            //multicodec::BLAKE2S_200 => (), // "blake2s-200"
            //multicodec::BLAKE2S_208 => (), // "blake2s-208"
            //multicodec::BLAKE2S_216 => (), // "blake2s-216"
            //multicodec::BLAKE2S_224 => (), // "blake2s-224"
            //multicodec::BLAKE2S_232 => (), // "blake2s-232"
            //multicodec::BLAKE2S_240 => (), // "blake2s-240"
            //multicodec::BLAKE2S_248 => (), // "blake2s-248"
            //multicodec::BLAKE2S_256 => (), // "blake2s-256"
            //multicodec::SKEIN256_8 => (), // "skein256-8"
            //multicodec::SKEIN256_16 => (), // "skein256-16"
            //multicodec::SKEIN256_24 => (), // "skein256-24"
            //multicodec::SKEIN256_32 => (), // "skein256-32"
            //multicodec::SKEIN256_40 => (), // "skein256-40"
            //multicodec::SKEIN256_48 => (), // "skein256-48"
            //multicodec::SKEIN256_56 => (), // "skein256-56"
            //multicodec::SKEIN256_64 => (), // "skein256-64"
            //multicodec::SKEIN256_72 => (), // "skein256-72"
            //multicodec::SKEIN256_80 => (), // "skein256-80"
            //multicodec::SKEIN256_88 => (), // "skein256-88"
            //multicodec::SKEIN256_96 => (), // "skein256-96"
            //multicodec::SKEIN256_104 => (), // "skein256-104"
            //multicodec::SKEIN256_112 => (), // "skein256-112"
            //multicodec::SKEIN256_120 => (), // "skein256-120"
            //multicodec::SKEIN256_128 => (), // "skein256-128"
            //multicodec::SKEIN256_136 => (), // "skein256-136"
            //multicodec::SKEIN256_144 => (), // "skein256-144"
            //multicodec::SKEIN256_152 => (), // "skein256-152"
            //multicodec::SKEIN256_160 => (), // "skein256-160"
            //multicodec::SKEIN256_168 => (), // "skein256-168"
            //multicodec::SKEIN256_176 => (), // "skein256-176"
            //multicodec::SKEIN256_184 => (), // "skein256-184"
            //multicodec::SKEIN256_192 => (), // "skein256-192"
            //multicodec::SKEIN256_200 => (), // "skein256-200"
            //multicodec::SKEIN256_208 => (), // "skein256-208"
            //multicodec::SKEIN256_216 => (), // "skein256-216"
            //multicodec::SKEIN256_224 => (), // "skein256-224"
            //multicodec::SKEIN256_232 => (), // "skein256-232"
            //multicodec::SKEIN256_240 => (), // "skein256-240"
            //multicodec::SKEIN256_248 => (), // "skein256-248"
            //multicodec::SKEIN256_256 => (), // "skein256-256"
            //multicodec::SKEIN512_8 => (), // "skein512-8"
            //multicodec::SKEIN512_16 => (), // "skein512-16"
            //multicodec::SKEIN512_24 => (), // "skein512-24"
            //multicodec::SKEIN512_32 => (), // "skein512-32"
            //multicodec::SKEIN512_40 => (), // "skein512-40"
            //multicodec::SKEIN512_48 => (), // "skein512-48"
            //multicodec::SKEIN512_56 => (), // "skein512-56"
            //multicodec::SKEIN512_64 => (), // "skein512-64"
            //multicodec::SKEIN512_72 => (), // "skein512-72"
            //multicodec::SKEIN512_80 => (), // "skein512-80"
            //multicodec::SKEIN512_88 => (), // "skein512-88"
            //multicodec::SKEIN512_96 => (), // "skein512-96"
            //multicodec::SKEIN512_104 => (), // "skein512-104"
            //multicodec::SKEIN512_112 => (), // "skein512-112"
            //multicodec::SKEIN512_120 => (), // "skein512-120"
            //multicodec::SKEIN512_128 => (), // "skein512-128"
            //multicodec::SKEIN512_136 => (), // "skein512-136"
            //multicodec::SKEIN512_144 => (), // "skein512-144"
            //multicodec::SKEIN512_152 => (), // "skein512-152"
            //multicodec::SKEIN512_160 => (), // "skein512-160"
            //multicodec::SKEIN512_168 => (), // "skein512-168"
            //multicodec::SKEIN512_176 => (), // "skein512-176"
            //multicodec::SKEIN512_184 => (), // "skein512-184"
            //multicodec::SKEIN512_192 => (), // "skein512-192"
            //multicodec::SKEIN512_200 => (), // "skein512-200"
            //multicodec::SKEIN512_208 => (), // "skein512-208"
            //multicodec::SKEIN512_216 => (), // "skein512-216"
            //multicodec::SKEIN512_224 => (), // "skein512-224"
            //multicodec::SKEIN512_232 => (), // "skein512-232"
            //multicodec::SKEIN512_240 => (), // "skein512-240"
            //multicodec::SKEIN512_248 => (), // "skein512-248"
            //multicodec::SKEIN512_256 => (), // "skein512-256"
            //multicodec::SKEIN512_264 => (), // "skein512-264"
            //multicodec::SKEIN512_272 => (), // "skein512-272"
            //multicodec::SKEIN512_280 => (), // "skein512-280"
            //multicodec::SKEIN512_288 => (), // "skein512-288"
            //multicodec::SKEIN512_296 => (), // "skein512-296"
            //multicodec::SKEIN512_304 => (), // "skein512-304"
            //multicodec::SKEIN512_312 => (), // "skein512-312"
            //multicodec::SKEIN512_320 => (), // "skein512-320"
            //multicodec::SKEIN512_328 => (), // "skein512-328"
            //multicodec::SKEIN512_336 => (), // "skein512-336"
            //multicodec::SKEIN512_344 => (), // "skein512-344"
            //multicodec::SKEIN512_352 => (), // "skein512-352"
            //multicodec::SKEIN512_360 => (), // "skein512-360"
            //multicodec::SKEIN512_368 => (), // "skein512-368"
            //multicodec::SKEIN512_376 => (), // "skein512-376"
            //multicodec::SKEIN512_384 => (), // "skein512-384"
            //multicodec::SKEIN512_392 => (), // "skein512-392"
            //multicodec::SKEIN512_400 => (), // "skein512-400"
            //multicodec::SKEIN512_408 => (), // "skein512-408"
            //multicodec::SKEIN512_416 => (), // "skein512-416"
            //multicodec::SKEIN512_424 => (), // "skein512-424"
            //multicodec::SKEIN512_432 => (), // "skein512-432"
            //multicodec::SKEIN512_440 => (), // "skein512-440"
            //multicodec::SKEIN512_448 => (), // "skein512-448"
            //multicodec::SKEIN512_456 => (), // "skein512-456"
            //multicodec::SKEIN512_464 => (), // "skein512-464"
            //multicodec::SKEIN512_472 => (), // "skein512-472"
            //multicodec::SKEIN512_480 => (), // "skein512-480"
            //multicodec::SKEIN512_488 => (), // "skein512-488"
            //multicodec::SKEIN512_496 => (), // "skein512-496"
            //multicodec::SKEIN512_504 => (), // "skein512-504"
            //multicodec::SKEIN512_512 => (), // "skein512-512"
            //multicodec::SKEIN1024_8 => (), // "skein1024-8"
            //multicodec::SKEIN1024_16 => (), // "skein1024-16"
            //multicodec::SKEIN1024_24 => (), // "skein1024-24"
            //multicodec::SKEIN1024_32 => (), // "skein1024-32"
            //multicodec::SKEIN1024_40 => (), // "skein1024-40"
            //multicodec::SKEIN1024_48 => (), // "skein1024-48"
            //multicodec::SKEIN1024_56 => (), // "skein1024-56"
            //multicodec::SKEIN1024_64 => (), // "skein1024-64"
            //multicodec::SKEIN1024_72 => (), // "skein1024-72"
            //multicodec::SKEIN1024_80 => (), // "skein1024-80"
            //multicodec::SKEIN1024_88 => (), // "skein1024-88"
            //multicodec::SKEIN1024_96 => (), // "skein1024-96"
            //multicodec::SKEIN1024_104 => (), // "skein1024-104"
            //multicodec::SKEIN1024_112 => (), // "skein1024-112"
            //multicodec::SKEIN1024_120 => (), // "skein1024-120"
            //multicodec::SKEIN1024_128 => (), // "skein1024-128"
            //multicodec::SKEIN1024_136 => (), // "skein1024-136"
            //multicodec::SKEIN1024_144 => (), // "skein1024-144"
            //multicodec::SKEIN1024_152 => (), // "skein1024-152"
            //multicodec::SKEIN1024_160 => (), // "skein1024-160"
            //multicodec::SKEIN1024_168 => (), // "skein1024-168"
            //multicodec::SKEIN1024_176 => (), // "skein1024-176"
            //multicodec::SKEIN1024_184 => (), // "skein1024-184"
            //multicodec::SKEIN1024_192 => (), // "skein1024-192"
            //multicodec::SKEIN1024_200 => (), // "skein1024-200"
            //multicodec::SKEIN1024_208 => (), // "skein1024-208"
            //multicodec::SKEIN1024_216 => (), // "skein1024-216"
            //multicodec::SKEIN1024_224 => (), // "skein1024-224"
            //multicodec::SKEIN1024_232 => (), // "skein1024-232"
            //multicodec::SKEIN1024_240 => (), // "skein1024-240"
            //multicodec::SKEIN1024_248 => (), // "skein1024-248"
            //multicodec::SKEIN1024_256 => (), // "skein1024-256"
            //multicodec::SKEIN1024_264 => (), // "skein1024-264"
            //multicodec::SKEIN1024_272 => (), // "skein1024-272"
            //multicodec::SKEIN1024_280 => (), // "skein1024-280"
            //multicodec::SKEIN1024_288 => (), // "skein1024-288"
            //multicodec::SKEIN1024_296 => (), // "skein1024-296"
            //multicodec::SKEIN1024_304 => (), // "skein1024-304"
            //multicodec::SKEIN1024_312 => (), // "skein1024-312"
            //multicodec::SKEIN1024_320 => (), // "skein1024-320"
            //multicodec::SKEIN1024_328 => (), // "skein1024-328"
            //multicodec::SKEIN1024_336 => (), // "skein1024-336"
            //multicodec::SKEIN1024_344 => (), // "skein1024-344"
            //multicodec::SKEIN1024_352 => (), // "skein1024-352"
            //multicodec::SKEIN1024_360 => (), // "skein1024-360"
            //multicodec::SKEIN1024_368 => (), // "skein1024-368"
            //multicodec::SKEIN1024_376 => (), // "skein1024-376"
            //multicodec::SKEIN1024_384 => (), // "skein1024-384"
            //multicodec::SKEIN1024_392 => (), // "skein1024-392"
            //multicodec::SKEIN1024_400 => (), // "skein1024-400"
            //multicodec::SKEIN1024_408 => (), // "skein1024-408"
            //multicodec::SKEIN1024_416 => (), // "skein1024-416"
            //multicodec::SKEIN1024_424 => (), // "skein1024-424"
            //multicodec::SKEIN1024_432 => (), // "skein1024-432"
            //multicodec::SKEIN1024_440 => (), // "skein1024-440"
            //multicodec::SKEIN1024_448 => (), // "skein1024-448"
            //multicodec::SKEIN1024_456 => (), // "skein1024-456"
            //multicodec::SKEIN1024_464 => (), // "skein1024-464"
            //multicodec::SKEIN1024_472 => (), // "skein1024-472"
            //multicodec::SKEIN1024_480 => (), // "skein1024-480"
            //multicodec::SKEIN1024_488 => (), // "skein1024-488"
            //multicodec::SKEIN1024_496 => (), // "skein1024-496"
            //multicodec::SKEIN1024_504 => (), // "skein1024-504"
            //multicodec::SKEIN1024_512 => (), // "skein1024-512"
            //multicodec::SKEIN1024_520 => (), // "skein1024-520"
            //multicodec::SKEIN1024_528 => (), // "skein1024-528"
            //multicodec::SKEIN1024_536 => (), // "skein1024-536"
            //multicodec::SKEIN1024_544 => (), // "skein1024-544"
            //multicodec::SKEIN1024_552 => (), // "skein1024-552"
            //multicodec::SKEIN1024_560 => (), // "skein1024-560"
            //multicodec::SKEIN1024_568 => (), // "skein1024-568"
            //multicodec::SKEIN1024_576 => (), // "skein1024-576"
            //multicodec::SKEIN1024_584 => (), // "skein1024-584"
            //multicodec::SKEIN1024_592 => (), // "skein1024-592"
            //multicodec::SKEIN1024_600 => (), // "skein1024-600"
            //multicodec::SKEIN1024_608 => (), // "skein1024-608"
            //multicodec::SKEIN1024_616 => (), // "skein1024-616"
            //multicodec::SKEIN1024_624 => (), // "skein1024-624"
            //multicodec::SKEIN1024_632 => (), // "skein1024-632"
            //multicodec::SKEIN1024_640 => (), // "skein1024-640"
            //multicodec::SKEIN1024_648 => (), // "skein1024-648"
            //multicodec::SKEIN1024_656 => (), // "skein1024-656"
            //multicodec::SKEIN1024_664 => (), // "skein1024-664"
            //multicodec::SKEIN1024_672 => (), // "skein1024-672"
            //multicodec::SKEIN1024_680 => (), // "skein1024-680"
            //multicodec::SKEIN1024_688 => (), // "skein1024-688"
            //multicodec::SKEIN1024_696 => (), // "skein1024-696"
            //multicodec::SKEIN1024_704 => (), // "skein1024-704"
            //multicodec::SKEIN1024_712 => (), // "skein1024-712"
            //multicodec::SKEIN1024_720 => (), // "skein1024-720"
            //multicodec::SKEIN1024_728 => (), // "skein1024-728"
            //multicodec::SKEIN1024_736 => (), // "skein1024-736"
            //multicodec::SKEIN1024_744 => (), // "skein1024-744"
            //multicodec::SKEIN1024_752 => (), // "skein1024-752"
            //multicodec::SKEIN1024_760 => (), // "skein1024-760"
            //multicodec::SKEIN1024_768 => (), // "skein1024-768"
            //multicodec::SKEIN1024_776 => (), // "skein1024-776"
            //multicodec::SKEIN1024_784 => (), // "skein1024-784"
            //multicodec::SKEIN1024_792 => (), // "skein1024-792"
            //multicodec::SKEIN1024_800 => (), // "skein1024-800"
            //multicodec::SKEIN1024_808 => (), // "skein1024-808"
            //multicodec::SKEIN1024_816 => (), // "skein1024-816"
            //multicodec::SKEIN1024_824 => (), // "skein1024-824"
            //multicodec::SKEIN1024_832 => (), // "skein1024-832"
            //multicodec::SKEIN1024_840 => (), // "skein1024-840"
            //multicodec::SKEIN1024_848 => (), // "skein1024-848"
            //multicodec::SKEIN1024_856 => (), // "skein1024-856"
            //multicodec::SKEIN1024_864 => (), // "skein1024-864"
            //multicodec::SKEIN1024_872 => (), // "skein1024-872"
            //multicodec::SKEIN1024_880 => (), // "skein1024-880"
            //multicodec::SKEIN1024_888 => (), // "skein1024-888"
            //multicodec::SKEIN1024_896 => (), // "skein1024-896"
            //multicodec::SKEIN1024_904 => (), // "skein1024-904"
            //multicodec::SKEIN1024_912 => (), // "skein1024-912"
            //multicodec::SKEIN1024_920 => (), // "skein1024-920"
            //multicodec::SKEIN1024_928 => (), // "skein1024-928"
            //multicodec::SKEIN1024_936 => (), // "skein1024-936"
            //multicodec::SKEIN1024_944 => (), // "skein1024-944"
            //multicodec::SKEIN1024_952 => (), // "skein1024-952"
            //multicodec::SKEIN1024_960 => (), // "skein1024-960"
            //multicodec::SKEIN1024_968 => (), // "skein1024-968"
            //multicodec::SKEIN1024_976 => (), // "skein1024-976"
            //multicodec::SKEIN1024_984 => (), // "skein1024-984"
            //multicodec::SKEIN1024_992 => (), // "skein1024-992"
            //multicodec::SKEIN1024_1000 => (), // "skein1024-1000"
            //multicodec::SKEIN1024_1008 => (), // "skein1024-1008"
            //multicodec::SKEIN1024_1016 => (), // "skein1024-1016"
            //multicodec::SKEIN1024_1024 => (), // "skein1024-1024"
            //multicodec::POSEIDON_BLS12_381_A2_FC1 => (),
            //multicodec::POSEIDON_BLS12_381_A2_FC1_SC => (),
            codec => err_at!(NotImplemented, msg: format!("codec {}", codec))?,
        };
        Ok(inner.into())
    }

    // <hash-func-type><digest-length><digest-value>
    pub fn from_slice(buf: &[u8]) -> Result<(Multihash, &[u8])> {
        use unsigned_varint::decode;

        let (codec, digest, rem) = {
            let (codec, rem) = Multicodec::from_slice(buf)?;
            let (n, rem) = err_at!(BadInput, decode::usize(rem))?;
            if n <= rem.len() {
                Ok((codec, &rem[..n], &rem[n..]))
            } else {
                err_at!(BadInput, msg: format!("hash-len {}", n))
            }
        }?;

        let code = codec.to_code();
        let inner = match code {
            multicodec::IDENTITY => {
                let hasher = Identity::from_slice(code, digest)?;
                Inner::Identity(codec, hasher)
            }
            multicodec::SHA1 => {
                let hasher = Sha1::from_slice(code, digest)?;
                Inner::Sha1(codec, hasher)
            }
            multicodec::SHA2_512 | multicodec::SHA2_256 => {
                let hasher = Sha2::from_slice(code, digest)?;
                Inner::Sha2(codec, hasher)
            }
            multicodec::SHA3_512
            | multicodec::SHA3_384
            | multicodec::SHA3_256
            | multicodec::SHA3_224
            | multicodec::SHAKE_128
            | multicodec::SHAKE_256
            | multicodec::KECCAK_224
            | multicodec::KECCAK_256
            | multicodec::KECCAK_384
            | multicodec::KECCAK_512 => {
                let hasher = Sha3::from_slice(code, digest)?;
                Inner::Sha3(codec, hasher)
            }
            multicodec::BLAKE3 => {
                let hasher = Blake3::from_slice(code, digest)?;
                Inner::Blake3(codec, hasher)
            }
            multicodec::MURMUR3_32 | multicodec::MURMUR3_128 => {
                let hasher = Murmur3::from_slice(code, digest)?;
                Inner::Murmur3(codec, hasher)
            }
            codec => err_at!(NotImplemented, msg: format!("codec {}", codec))?,
        };

        Ok((inner.into(), rem))
    }

    pub fn set_murmur3_seed(&mut self, seed: u32) {
        match &mut self.inner {
            Inner::Murmur3(_, hasher) => hasher.set_seed(seed),
            _ => (),
        }
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.write(bytes)?,
            Inner::Sha1(_, hasher) => hasher.write(bytes)?,
            Inner::Sha2(_, hasher) => hasher.write(bytes)?,
            Inner::Sha3(_, hasher) => hasher.write(bytes)?,
            Inner::Blake3(_, hasher) => hasher.write(bytes)?,
            Inner::Murmur3(_, hasher) => hasher.write(bytes)?,
        };
        Ok(self)
    }

    pub fn finish(&mut self) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.finish()?,
            Inner::Sha1(_, hasher) => hasher.finish()?,
            Inner::Sha2(_, hasher) => hasher.finish()?,
            Inner::Sha3(_, hasher) => hasher.finish()?,
            Inner::Blake3(_, hasher) => hasher.finish()?,
            Inner::Murmur3(_, hasher) => hasher.finish()?,
        };
        Ok(self)
    }

    pub fn reset(&mut self) -> Result<&mut Self> {
        match &mut self.inner {
            Inner::Identity(_, hasher) => hasher.reset()?,
            Inner::Sha1(_, hasher) => hasher.reset()?,
            Inner::Sha2(_, hasher) => hasher.reset()?,
            Inner::Sha3(_, hasher) => hasher.reset()?,
            Inner::Blake3(_, hasher) => hasher.reset()?,
            Inner::Murmur3(_, hasher) => hasher.reset()?,
        };
        Ok(self)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::default();
        self.encode_with(&mut buf)?;
        Ok(buf)
    }

    pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        use unsigned_varint::encode;

        let digest = match &self.inner {
            Inner::Identity(_, hasher) => hasher.as_digest()?,
            Inner::Sha1(_, hasher) => hasher.as_digest()?,
            Inner::Sha2(_, hasher) => hasher.as_digest()?,
            Inner::Sha3(_, hasher) => hasher.as_digest()?,
            Inner::Blake3(_, hasher) => hasher.as_digest()?,
            Inner::Murmur3(_, hasher) => hasher.as_digest()?,
        };
        let n = self.to_codec().encode_with(buf)?;
        let m = {
            let mut scratch: [u8; 10] = Default::default();
            let slice = encode::usize(digest.len(), &mut scratch);
            err_at!(IOError, buf.write(slice))?;
            slice.len()
        };
        err_at!(IOError, buf.write(digest))?;
        Ok(n + m + digest.len())
    }

    pub fn to_codec(&self) -> Multicodec {
        match &self.inner {
            Inner::Identity(codec, _) => codec.clone(),
            Inner::Sha1(codec, _) => codec.clone(),
            Inner::Sha2(codec, _) => codec.clone(),
            Inner::Sha3(codec, _) => codec.clone(),
            Inner::Blake3(codec, _) => codec.clone(),
            Inner::Murmur3(codec, _) => codec.clone(),
        }
    }

    pub fn unwrap(self) -> (Multicodec, Vec<u8>) {
        let digest = match &self.inner {
            Inner::Identity(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha1(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha2(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Sha3(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Blake3(_, hasher) => hasher.as_digest().unwrap(),
            Inner::Murmur3(_, hasher) => hasher.as_digest().unwrap(),
        };
        (self.to_codec(), digest.to_vec())
    }
}

impl io::Write for Multihash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> ::std::io::Result<()> {
        Ok(())
    }
}

struct Identity {
    buf: Vec<u8>,
    digest: Option<Vec<u8>>,
}

impl Identity {
    fn from_code(_code: u128) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Identity> {
        Ok(Identity {
            buf: Vec::default(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.buf.extend(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => Some(self.buf.drain(..).collect()),
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

struct Sha1 {
    hasher: sha1::Sha1,
    digest: Option<Vec<u8>>,
}

impl Sha1 {
    fn from_code(_code: u128) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Sha1> {
        Ok(Sha1 {
            hasher: sha1::Sha1::new(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => {
                let digest = self.hasher.finalize_reset().to_vec();
                self.hasher.reset();
                Some(digest)
            }
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

enum Sha2 {
    Algo32 {
        hasher: sha2::Sha256,
        digest: Option<Vec<u8>>,
    },
    Algo64 {
        hasher: sha2::Sha512,
        digest: Option<Vec<u8>>,
    },
}

impl Sha2 {
    fn from_code(code: u128) -> Result<Sha2> {
        let digest = None;
        let val = match code {
            multicodec::SHA2_256 => {
                let hasher = sha2::Sha256::new();
                Sha2::Algo32 { hasher, digest }
            }
            multicodec::SHA2_512 => {
                let hasher = sha2::Sha512::new();
                Sha2::Algo64 { hasher, digest }
            }
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Sha2> {
        let val = match code {
            multicodec::SHA2_256 => Sha2::Algo32 {
                hasher: sha2::Sha256::new(),
                digest: Some(digest.to_vec()),
            },
            multicodec::SHA2_512 => Sha2::Algo64 {
                hasher: sha2::Sha512::new(),
                digest: Some(digest.to_vec()),
            },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Sha2::Algo32 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            Sha2::Algo64 {
                hasher,
                digest: None,
            } => hasher.update(bytes),
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        match self {
            Sha2::Algo32 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            Sha2::Algo64 {
                hasher,
                digest: digest @ None,
            } => {
                *digest = Some(hasher.finalize_reset().as_slice().to_vec());
            }
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let digest = match self {
            Sha2::Algo32 { digest, .. } => digest,
            Sha2::Algo64 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match self {
            Sha2::Algo32 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Sha2::Algo64 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

enum Sha3 {
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

impl Sha3 {
    fn from_code(code: u128) -> Result<Sha3> {
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
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, digest: &[u8]) -> Result<Sha3> {
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
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
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
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
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
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
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

    fn as_digest(&self) -> Result<&[u8]> {
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
            _ => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

struct Blake3 {
    hasher: blake3::Hasher,
    digest: Option<Vec<u8>>,
}

impl Blake3 {
    fn from_code(_code: u128) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
            digest: None,
        })
    }

    fn from_slice(_code: u128, digest: &[u8]) -> Result<Blake3> {
        Ok(Blake3 {
            hasher: blake3::Hasher::new(),
            digest: Some(digest.to_vec()),
        })
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match &self.digest {
            None => self.hasher.update(bytes),
            Some(_) => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        self.digest = match &self.digest {
            None => {
                let hash = blake3::Hasher::finalize(&self.hasher);
                Some(hash.as_bytes().to_vec())
            }
            Some(_) => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        self.digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match &self.digest {
            Some(digest) => Ok(digest),
            None => err_at!(Invalid, msg: format!("no digest")),
        }
    }
}

enum Murmur3 {
    Algo32 {
        seed: u32,
        buf: Vec<u8>,
        digest: Option<Vec<u8>>,
    },
    Algo128 {
        seed: u32,
        buf: Vec<u8>,
        digest: Option<Vec<u8>>,
    },
}

impl Murmur3 {
    fn from_code(code: u128, seed: u32) -> Result<Murmur3> {
        let buf = Vec::default();
        let digest = None;
        let val = match code {
            multicodec::MURMUR3_32 => Murmur3::Algo32 { seed, buf, digest },
            multicodec::MURMUR3_128 => Murmur3::Algo128 { seed, buf, digest },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn from_slice(code: u128, buf: &[u8]) -> Result<Murmur3> {
        use unsigned_varint::decode;

        let out = Vec::default();
        let (seed, digest) = err_at!(BadInput, decode::u32(&buf))?;
        let val = match code {
            multicodec::MURMUR3_32 => Murmur3::Algo32 {
                seed,
                digest: Some(digest.to_vec()),
                buf: out,
            },
            multicodec::MURMUR3_128 => Murmur3::Algo128 {
                seed,
                digest: Some(digest.to_vec()),
                buf: out,
            },
            _ => err_at!(Fatal, msg: format!("unreachable"))?,
        };
        Ok(val)
    }

    fn set_seed(&mut self, new_seed: u32) {
        match self {
            Murmur3::Algo32 { seed, .. } => *seed = new_seed,
            Murmur3::Algo128 { seed, .. } => *seed = new_seed,
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Murmur3::Algo32 {
                buf, digest: None, ..
            } => buf.extend(bytes),
            Murmur3::Algo128 {
                buf, digest: None, ..
            } => buf.extend(bytes),
            _ => err_at!(Invalid, msg: format!("finalized"))?,
        };
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        use unsigned_varint::encode;

        match self {
            Murmur3::Algo32 {
                seed,
                buf,
                digest: digest @ None,
            } => {
                let mut out = Vec::default();
                {
                    let mut scratch: [u8; 5] = Default::default();
                    out.extend(encode::u32(*seed, &mut scratch));
                }
                {
                    let mut r = io::Cursor::new(buf.as_slice());
                    let dval = err_at!(HashFail, murmur3::murmur3_32(&mut r, *seed))?;
                    out.extend(&dval.to_be_bytes());
                }
                *digest = Some(out);
                buf.truncate(0);
            }
            Murmur3::Algo128 {
                seed,
                buf,
                digest: digest @ None,
            } => {
                let mut out = Vec::default();
                {
                    let mut scratch: [u8; 5] = Default::default();
                    out.extend(encode::u32(*seed, &mut scratch));
                };
                {
                    let mut r = io::Cursor::new(buf.as_slice());
                    let dval = if cfg!(target_arch = "x86_64") {
                        err_at!(HashFail, murmur3::murmur3_x64_128(&mut r, *seed))?
                    } else {
                        err_at!(HashFail, murmur3::murmur3_x86_128(&mut r, *seed))?
                    };
                    out.extend(&dval.to_be_bytes());
                }
                *digest = Some(out);
                buf.truncate(0);
            }
            _ => err_at!(Invalid, msg: format!("double finalize"))?,
        };
        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let digest = match self {
            Murmur3::Algo32 { digest, .. } => digest,
            Murmur3::Algo128 { digest, .. } => digest,
        };
        digest.take();
        Ok(())
    }

    fn as_digest(&self) -> Result<&[u8]> {
        match self {
            Murmur3::Algo32 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            Murmur3::Algo128 {
                digest: Some(digest),
                ..
            } => Ok(digest),
            _ => err_at!(Invalid, msg: format!("no digest"))?,
        }
    }
}
