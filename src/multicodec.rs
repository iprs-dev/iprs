//! Module implement [multicodec][multicodec] specification.
//!
//! [multicodec]: https://github.com/multiformats/multicodec

use lazy_static::lazy_static;

use std::{convert::TryFrom, fmt, io, result};

use crate::{Error, Result};

/// Multicodec carries a code that confirms to
/// [multicode][multicodec] and [unsigned_varint][unsigned-varint] specs.
///
/// Instantiate a Multicode, from a codec like MULTIHASH.
///
/// ```ignore
///     let codec: Multicodec = multicode::MULTIHASH.into();
/// ```
///
/// [multicodec]: https://github.com/multiformats/multicodec
/// [unsigned-varint]: https://github.com/multiformats/unsigned-varint
#[derive(Clone, Eq, PartialEq)]
pub struct Multicodec {
    code: u128,
}

impl fmt::Debug for Multicodec {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "Multicodec<{}", self.code)
    }
}

impl From<u128> for Multicodec {
    fn from(code: u128) -> Self {
        Multicodec { code: code.into() }
    }
}

impl From<u64> for Multicodec {
    fn from(code: u64) -> Self {
        Multicodec { code: code.into() }
    }
}

impl From<u32> for Multicodec {
    fn from(code: u32) -> Self {
        Multicodec { code: code.into() }
    }
}

impl From<u16> for Multicodec {
    fn from(code: u16) -> Self {
        Multicodec { code: code.into() }
    }
}

impl From<u8> for Multicodec {
    fn from(code: u8) -> Self {
        Multicodec { code: code.into() }
    }
}

impl<'a> From<&'a Codepoint> for Multicodec {
    fn from(cpoint: &'a Codepoint) -> Self {
        cpoint.code.into()
    }
}

impl<'a> TryFrom<&'a str> for Multicodec {
    type Error = Error;

    fn try_from(name: &'a str) -> Result<Multicodec> {
        for entry in TABLE.iter() {
            if entry.name == name {
                return Ok(Multicodec { code: entry.code });
            }
        }
        err_at!(Err(Error::Invalid(
            "".to_string(),
            format!("multicode-name {}", name)
        )))
    }
}

impl Multicodec {
    /// Convert incoming stream of bytes into multicodec value.
    ///
    /// Return [Error::Invalid] if buf's content can't be recognised.
    pub fn from_slice(buf: &[u8]) -> Result<(Multicodec, &[u8])> {
        let (code, rem) = err_at!(Invalid, unsigned_varint::decode::u128(buf))?;
        Ok((Multicodec { code }, rem))
    }

    /// Encode Multicodec to unsigned_varint bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut buf);
        Ok(slice.to_vec())
    }

    /// Similar to encode() by avoids allocation, by using supplied
    /// buffer `buf`.
    pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        let mut scratch: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut scratch);
        err_at!(IOError, buf.write(&slice))?;
        Ok(slice.len())
    }

    pub fn to_code(&self) -> u128 {
        self.code
    }
}

/// Description of single code-point.
#[derive(Clone, Eq, PartialEq)]
pub struct Codepoint {
    /// Unsigned varint code-point.
    pub code: u128,
    /// Name the code-point.
    pub name: String,
    /// Tag the code-point.
    pub tag: String,
}

macro_rules! code_points {
    ($(($label:ident, $code:expr, $name:expr, $tag:expr),)*) => (

        $(pub const $label: u128 = $code;)*

        lazy_static! {
            /// Default codec table.
            ///
            /// Refer [multicodec][multicodec] for details.
            ///
            /// [multicodec]: https://github.com/multiformats/multicodec
            pub static ref TABLE: Vec<Codepoint> = vec![
                $(Codepoint {
                    code: $code,
                    name: $name.to_string(),
                    tag: $tag.to_string()
                },)*
            ];

            pub static ref TABLE_MULTIHASH: Vec<Codepoint> = {
                let mut codes = Vec::default();
                $(
                    match $tag {
                        "multihash" => codes.push(Codepoint {
                            code: $code,
                            name: $name.to_string(),
                            tag: $tag.to_string()
                        }),
                        _ => ()
                    };
                )*
                codes
            };
        }
    );
}

code_points![
    (IDENTITY, 0x00, "identity", "multihash"),
    (CID_V1, 0x01, "cidv1", "ipld"),
    (CID_V2, 0x02, "cidv2", "ipld"),
    (CID_V3, 0x03, "cidv3", "ipld"),
    (IP4, 0x04, "ip4", "multiaddr"),
    (TCP, 0x06, "tcp", "multiaddr"),
    (SHA1, 0x11, "sha1", "multihash"),
    (SHA2_256, 0x12, "sha2-256", "multihash"),
    (SHA2_512, 0x13, "sha2-512", "multihash"),
    (SHA3_512, 0x14, "sha3-512", "multihash"),
    (SHA3_384, 0x15, "sha3-384", "multihash"),
    (SHA3_256, 0x16, "sha3-256", "multihash"),
    (SHA3_224, 0x17, "sha3-224", "multihash"),
    (SHAKE_128, 0x18, "shake-128", "multihash"),
    (SHAKE_256, 0x19, "shake-256", "multihash"),
    (KECCAK_224, 0x1a, "keccak-224", "multihash"),
    (KECCAK_256, 0x1b, "keccak-256", "multihash"),
    (KECCAK_384, 0x1c, "keccak-384", "multihash"),
    (KECCAK_512, 0x1d, "keccak-512", "multihash"),
    (BLAKE3, 0x1e, "blake3", "multihash"),
    (DCCP, 0x21, "dccp", "multiaddr"),
    (MURMUR3_128, 0x22, "murmur3-128", "multihash"),
    (MURMUR3_32, 0x23, "murmur3-32", "multihash"),
    (IP6, 0x29, "ip6", "multiaddr"),
    (IP6ZONE, 0x2a, "ip6zone", "multiaddr"),
    (PATH, 0x2f, "path", "namespace"),
    (MULTICODEC, 0x30, "multicodec", "multiformat"),
    (MULTIHASH, 0x31, "multihash", "multiformat"),
    (MULTIADDR, 0x32, "multiaddr", "multiformat"),
    (MULTIBASE, 0x33, "multibase", "multiformat"),
    (DNS, 0x35, "dns", "multiaddr"),
    (DNS4, 0x36, "dns4", "multiaddr"),
    (DNS6, 0x37, "dns6", "multiaddr"),
    (DNSADDR, 0x38, "dnsaddr", "multiaddr"),
    (PROTOBUF, 0x50, "protobuf", "serialization"),
    (CBOR, 0x51, "cbor", "serialization"),
    (RAW, 0x55, "raw", "ipld"),
    (DBL_SHA2_256, 0x56, "dbl-sha2-256", "multihash"),
    (RLP, 0x60, "rlp", "serialization"),
    (BENCODE, 0x63, "bencode", "serialization"),
    (DAG_PB, 0x70, "dag-pb", "ipld"),
    (DAG_CBOR, 0x71, "dag-cbor", "ipld"),
    (LIBP2P_KEY, 0x72, "libp2p-key", "ipld"),
    (GIT_RAW, 0x78, "git-raw", "ipld"),
    (TORRENT_INFO, 0x7b, "torrent-info", "ipld"),
    (TORRENT_FILE, 0x7c, "torrent-file", "ipld"),
    (LEOFCOIN_BLOCK, 0x81, "leofcoin-block", "ipld"),
    (LEOFCOIN_TX, 0x82, "leofcoin-tx", "ipld"),
    (LEOFCOIN_PR, 0x83, "leofcoin-pr", "ipld"),
    (SCTP, 0x84, "sctp", "multiaddr"),
    (DAG_JOSE, 0x85, "dag-jose", "ipld"),
    (DAG_COSE, 0x86, "dag-cose", "ipld"),
    (ETH_BLOCK, 0x90, "eth-block", "ipld"),
    (ETH_BLOCK_LIST, 0x91, "eth-block-list", "ipld"),
    (ETH_TX_TRIE, 0x92, "eth-tx-trie", "ipld"),
    (ETH_TX, 0x93, "eth-tx", "ipld"),
    (ETH_TX_RECEIPT_TRIE, 0x94, "eth-tx-receipt-trie", "ipld"),
    (ETH_TX_RECEIPT, 0x95, "eth-tx-receipt", "ipld"),
    (ETH_STATE_TRIE, 0x96, "eth-state-trie", "ipld"),
    (ETH_ACCOUNT_SNAPSHOT, 0x97, "eth-account-snapshot", "ipld"),
    (ETH_STORAGE_TRIE, 0x98, "eth-storage-trie", "ipld"),
    (BITCOIN_BLOCK, 0xb0, "bitcoin-block", "ipld"),
    (BITCOIN_TX, 0xb1, "bitcoin-tx", "ipld"),
    (
        BITCOIN_WITNESS_COMMITMENT,
        0xb2,
        "bitcoin-witness-commitment",
        "ipld"
    ),
    (ZCASH_BLOCK, 0xc0, "zcash-block", "ipld"),
    (ZCASH_TX, 0xc1, "zcash-tx", "ipld"),
    (STELLAR_BLOCK, 0xd0, "stellar-block", "ipld"),
    (STELLAR_TX, 0xd1, "stellar-tx", "ipld"),
    (MD4, 0xd4, "md4", "multihash"),
    (MD5, 0xd5, "md5", "multihash"),
    (BMT, 0xd6, "bmt", "multihash"),
    (DECRED_BLOCK, 0xe0, "decred-block", "ipld"),
    (DECRED_TX, 0xe1, "decred-tx", "ipld"),
    (IPLD_NS, 0xe2, "ipld-ns", "namespace"),
    (IPFS_NS, 0xe3, "ipfs-ns", "namespace"),
    (SWARM_NS, 0xe4, "swarm-ns", "namespace"),
    (IPNS_NS, 0xe5, "ipns-ns", "namespace"),
    (ZERONET, 0xe6, "zeronet", "namespace"),
    (SECP256K1_PUB, 0xe7, "secp256k1-pub", "key"),
    (BLS12_381_G1_PUB, 0xea, "bls12_381-g1-pub", "key"),
    (BLS12_381_G2_PUB, 0xeb, "bls12_381-g2-pub", "key"),
    (X25519_PUB, 0xec, "x25519-pub", "key"),
    (ED25519_PUB, 0xed, "ed25519-pub", "key"),
    (DASH_BLOCK, 0xf0, "dash-block", "ipld"),
    (DASH_TX, 0xf1, "dash-tx", "ipld"),
    (SWARM_MANIFEST, 0xfa, "swarm-manifest", "ipld"),
    (SWARM_FEED, 0xfb, "swarm-feed", "ipld"),
    (UDP, 0x0111, "udp", "multiaddr"),
    (P2P_WEBRTC_STAR, 0x0113, "p2p-webrtc-star", "multiaddr"),
    (P2P_WEBRTC_DIRECT, 0x0114, "p2p-webrtc-direct", "multiaddr"),
    (P2P_STARDUST, 0x0115, "p2p-stardust", "multiaddr"),
    (P2P_CIRCUIT, 0x0122, "p2p-circuit", "multiaddr"),
    (DAG_JSON, 0x0129, "dag-json", "ipld"),
    (UDT, 0x012d, "udt", "multiaddr"),
    (UTP, 0x012e, "utp", "multiaddr"),
    (UNIX, 0x0190, "unix", "multiaddr"),
    (P2P, 0x01a5, "p2p", "multiaddr"),
    (HTTPS, 0x01bb, "https", "multiaddr"),
    (ONION, 0x01bc, "onion", "multiaddr"),
    (ONION3, 0x01bd, "onion3", "multiaddr"),
    (GARLIC64, 0x01be, "garlic64", "multiaddr"),
    (GARLIC32, 0x01bf, "garlic32", "multiaddr"),
    (TLS, 0x01c0, "tls", "multiaddr"),
    (QUIC, 0x01cc, "quic", "multiaddr"),
    (WS, 0x01dd, "ws", "multiaddr"),
    (WSS, 0x01de, "wss", "multiaddr"),
    (
        P2P_WEBSOCKET_STAR,
        0x01df,
        "p2p-websocket-star",
        "multiaddr"
    ),
    (HTTP, 0x01e0, "http", "multiaddr"),
    (JSON, 0x0200, "json", "serialization"),
    (MESSAGEPACK, 0x0201, "messagepack", "serialization"),
    (LIBP2P_PEER_RECORD, 0x0301, "libp2p-peer-record", "libp2p"),
    (
        SHA2_256_TRUNC254_PADDED,
        0x1012,
        "sha2-256-trunc254-padded",
        "multihash"
    ),
    (RIPEMD_128, 0x1052, "ripemd-128", "multihash"),
    (RIPEMD_160, 0x1053, "ripemd-160", "multihash"),
    (RIPEMD_256, 0x1054, "ripemd-256", "multihash"),
    (RIPEMD_320, 0x1055, "ripemd-320", "multihash"),
    (X11, 0x1100, "x11", "multihash"),
    (P256_PUB, 0x1200, "p256-pub", "key"),
    (P384_PUB, 0x1201, "p384-pub", "key"),
    (P521_PUB, 0x1202, "p521-pub", "key"),
    (ED448_PUB, 0x1203, "ed448-pub", "key"),
    (X448_PUB, 0x1204, "x448-pub", "key"),
    (KANGAROOTWELVE, 0x1d01, "kangarootwelve", "multihash"),
    (SM3_256, 0x534d, "sm3-256", "multihash"),
    (BLAKE2B_8, 0xb201, "blake2b-8", "multihash"),
    (BLAKE2B_16, 0xb202, "blake2b-16", "multihash"),
    (BLAKE2B_24, 0xb203, "blake2b-24", "multihash"),
    (BLAKE2B_32, 0xb204, "blake2b-32", "multihash"),
    (BLAKE2B_40, 0xb205, "blake2b-40", "multihash"),
    (BLAKE2B_48, 0xb206, "blake2b-48", "multihash"),
    (BLAKE2B_56, 0xb207, "blake2b-56", "multihash"),
    (BLAKE2B_64, 0xb208, "blake2b-64", "multihash"),
    (BLAKE2B_72, 0xb209, "blake2b-72", "multihash"),
    (BLAKE2B_80, 0xb20a, "blake2b-80", "multihash"),
    (BLAKE2B_88, 0xb20b, "blake2b-88", "multihash"),
    (BLAKE2B_96, 0xb20c, "blake2b-96", "multihash"),
    (BLAKE2B_104, 0xb20d, "blake2b-104", "multihash"),
    (BLAKE2B_112, 0xb20e, "blake2b-112", "multihash"),
    (BLAKE2B_120, 0xb20f, "blake2b-120", "multihash"),
    (BLAKE2B_128, 0xb210, "blake2b-128", "multihash"),
    (BLAKE2B_136, 0xb211, "blake2b-136", "multihash"),
    (BLAKE2B_144, 0xb212, "blake2b-144", "multihash"),
    (BLAKE2B_152, 0xb213, "blake2b-152", "multihash"),
    (BLAKE2B_160, 0xb214, "blake2b-160", "multihash"),
    (BLAKE2B_168, 0xb215, "blake2b-168", "multihash"),
    (BLAKE2B_176, 0xb216, "blake2b-176", "multihash"),
    (BLAKE2B_184, 0xb217, "blake2b-184", "multihash"),
    (BLAKE2B_192, 0xb218, "blake2b-192", "multihash"),
    (BLAKE2B_200, 0xb219, "blake2b-200", "multihash"),
    (BLAKE2B_208, 0xb21a, "blake2b-208", "multihash"),
    (BLAKE2B_216, 0xb21b, "blake2b-216", "multihash"),
    (BLAKE2B_224, 0xb21c, "blake2b-224", "multihash"),
    (BLAKE2B_232, 0xb21d, "blake2b-232", "multihash"),
    (BLAKE2B_240, 0xb21e, "blake2b-240", "multihash"),
    (BLAKE2B_248, 0xb21f, "blake2b-248", "multihash"),
    (BLAKE2B_256, 0xb220, "blake2b-256", "multihash"),
    (BLAKE2B_264, 0xb221, "blake2b-264", "multihash"),
    (BLAKE2B_272, 0xb222, "blake2b-272", "multihash"),
    (BLAKE2B_280, 0xb223, "blake2b-280", "multihash"),
    (BLAKE2B_288, 0xb224, "blake2b-288", "multihash"),
    (BLAKE2B_296, 0xb225, "blake2b-296", "multihash"),
    (BLAKE2B_304, 0xb226, "blake2b-304", "multihash"),
    (BLAKE2B_312, 0xb227, "blake2b-312", "multihash"),
    (BLAKE2B_320, 0xb228, "blake2b-320", "multihash"),
    (BLAKE2B_328, 0xb229, "blake2b-328", "multihash"),
    (BLAKE2B_336, 0xb22a, "blake2b-336", "multihash"),
    (BLAKE2B_344, 0xb22b, "blake2b-344", "multihash"),
    (BLAKE2B_352, 0xb22c, "blake2b-352", "multihash"),
    (BLAKE2B_360, 0xb22d, "blake2b-360", "multihash"),
    (BLAKE2B_368, 0xb22e, "blake2b-368", "multihash"),
    (BLAKE2B_376, 0xb22f, "blake2b-376", "multihash"),
    (BLAKE2B_384, 0xb230, "blake2b-384", "multihash"),
    (BLAKE2B_392, 0xb231, "blake2b-392", "multihash"),
    (BLAKE2B_400, 0xb232, "blake2b-400", "multihash"),
    (BLAKE2B_408, 0xb233, "blake2b-408", "multihash"),
    (BLAKE2B_416, 0xb234, "blake2b-416", "multihash"),
    (BLAKE2B_424, 0xb235, "blake2b-424", "multihash"),
    (BLAKE2B_432, 0xb236, "blake2b-432", "multihash"),
    (BLAKE2B_440, 0xb237, "blake2b-440", "multihash"),
    (BLAKE2B_448, 0xb238, "blake2b-448", "multihash"),
    (BLAKE2B_456, 0xb239, "blake2b-456", "multihash"),
    (BLAKE2B_464, 0xb23a, "blake2b-464", "multihash"),
    (BLAKE2B_472, 0xb23b, "blake2b-472", "multihash"),
    (BLAKE2B_480, 0xb23c, "blake2b-480", "multihash"),
    (BLAKE2B_488, 0xb23d, "blake2b-488", "multihash"),
    (BLAKE2B_496, 0xb23e, "blake2b-496", "multihash"),
    (BLAKE2B_504, 0xb23f, "blake2b-504", "multihash"),
    (BLAKE2B_512, 0xb240, "blake2b-512", "multihash"),
    (BLAKE2S_8, 0xb241, "blake2s-8", "multihash"),
    (BLAKE2S_16, 0xb242, "blake2s-16", "multihash"),
    (BLAKE2S_24, 0xb243, "blake2s-24", "multihash"),
    (BLAKE2S_32, 0xb244, "blake2s-32", "multihash"),
    (BLAKE2S_40, 0xb245, "blake2s-40", "multihash"),
    (BLAKE2S_48, 0xb246, "blake2s-48", "multihash"),
    (BLAKE2S_56, 0xb247, "blake2s-56", "multihash"),
    (BLAKE2S_64, 0xb248, "blake2s-64", "multihash"),
    (BLAKE2S_72, 0xb249, "blake2s-72", "multihash"),
    (BLAKE2S_80, 0xb24a, "blake2s-80", "multihash"),
    (BLAKE2S_88, 0xb24b, "blake2s-88", "multihash"),
    (BLAKE2S_96, 0xb24c, "blake2s-96", "multihash"),
    (BLAKE2S_104, 0xb24d, "blake2s-104", "multihash"),
    (BLAKE2S_112, 0xb24e, "blake2s-112", "multihash"),
    (BLAKE2S_120, 0xb24f, "blake2s-120", "multihash"),
    (BLAKE2S_128, 0xb250, "blake2s-128", "multihash"),
    (BLAKE2S_136, 0xb251, "blake2s-136", "multihash"),
    (BLAKE2S_144, 0xb252, "blake2s-144", "multihash"),
    (BLAKE2S_152, 0xb253, "blake2s-152", "multihash"),
    (BLAKE2S_160, 0xb254, "blake2s-160", "multihash"),
    (BLAKE2S_168, 0xb255, "blake2s-168", "multihash"),
    (BLAKE2S_176, 0xb256, "blake2s-176", "multihash"),
    (BLAKE2S_184, 0xb257, "blake2s-184", "multihash"),
    (BLAKE2S_192, 0xb258, "blake2s-192", "multihash"),
    (BLAKE2S_200, 0xb259, "blake2s-200", "multihash"),
    (BLAKE2S_208, 0xb25a, "blake2s-208", "multihash"),
    (BLAKE2S_216, 0xb25b, "blake2s-216", "multihash"),
    (BLAKE2S_224, 0xb25c, "blake2s-224", "multihash"),
    (BLAKE2S_232, 0xb25d, "blake2s-232", "multihash"),
    (BLAKE2S_240, 0xb25e, "blake2s-240", "multihash"),
    (BLAKE2S_248, 0xb25f, "blake2s-248", "multihash"),
    (BLAKE2S_256, 0xb260, "blake2s-256", "multihash"),
    (SKEIN256_8, 0xb301, "skein256-8", "multihash"),
    (SKEIN256_16, 0xb302, "skein256-16", "multihash"),
    (SKEIN256_24, 0xb303, "skein256-24", "multihash"),
    (SKEIN256_32, 0xb304, "skein256-32", "multihash"),
    (SKEIN256_40, 0xb305, "skein256-40", "multihash"),
    (SKEIN256_48, 0xb306, "skein256-48", "multihash"),
    (SKEIN256_56, 0xb307, "skein256-56", "multihash"),
    (SKEIN256_64, 0xb308, "skein256-64", "multihash"),
    (SKEIN256_72, 0xb309, "skein256-72", "multihash"),
    (SKEIN256_80, 0xb30a, "skein256-80", "multihash"),
    (SKEIN256_88, 0xb30b, "skein256-88", "multihash"),
    (SKEIN256_96, 0xb30c, "skein256-96", "multihash"),
    (SKEIN256_104, 0xb30d, "skein256-104", "multihash"),
    (SKEIN256_112, 0xb30e, "skein256-112", "multihash"),
    (SKEIN256_120, 0xb30f, "skein256-120", "multihash"),
    (SKEIN256_128, 0xb310, "skein256-128", "multihash"),
    (SKEIN256_136, 0xb311, "skein256-136", "multihash"),
    (SKEIN256_144, 0xb312, "skein256-144", "multihash"),
    (SKEIN256_152, 0xb313, "skein256-152", "multihash"),
    (SKEIN256_160, 0xb314, "skein256-160", "multihash"),
    (SKEIN256_168, 0xb315, "skein256-168", "multihash"),
    (SKEIN256_176, 0xb316, "skein256-176", "multihash"),
    (SKEIN256_184, 0xb317, "skein256-184", "multihash"),
    (SKEIN256_192, 0xb318, "skein256-192", "multihash"),
    (SKEIN256_200, 0xb319, "skein256-200", "multihash"),
    (SKEIN256_208, 0xb31a, "skein256-208", "multihash"),
    (SKEIN256_216, 0xb31b, "skein256-216", "multihash"),
    (SKEIN256_224, 0xb31c, "skein256-224", "multihash"),
    (SKEIN256_232, 0xb31d, "skein256-232", "multihash"),
    (SKEIN256_240, 0xb31e, "skein256-240", "multihash"),
    (SKEIN256_248, 0xb31f, "skein256-248", "multihash"),
    (SKEIN256_256, 0xb320, "skein256-256", "multihash"),
    (SKEIN512_8, 0xb321, "skein512-8", "multihash"),
    (SKEIN512_16, 0xb322, "skein512-16", "multihash"),
    (SKEIN512_24, 0xb323, "skein512-24", "multihash"),
    (SKEIN512_32, 0xb324, "skein512-32", "multihash"),
    (SKEIN512_40, 0xb325, "skein512-40", "multihash"),
    (SKEIN512_48, 0xb326, "skein512-48", "multihash"),
    (SKEIN512_56, 0xb327, "skein512-56", "multihash"),
    (SKEIN512_64, 0xb328, "skein512-64", "multihash"),
    (SKEIN512_72, 0xb329, "skein512-72", "multihash"),
    (SKEIN512_80, 0xb32a, "skein512-80", "multihash"),
    (SKEIN512_88, 0xb32b, "skein512-88", "multihash"),
    (SKEIN512_96, 0xb32c, "skein512-96", "multihash"),
    (SKEIN512_104, 0xb32d, "skein512-104", "multihash"),
    (SKEIN512_112, 0xb32e, "skein512-112", "multihash"),
    (SKEIN512_120, 0xb32f, "skein512-120", "multihash"),
    (SKEIN512_128, 0xb330, "skein512-128", "multihash"),
    (SKEIN512_136, 0xb331, "skein512-136", "multihash"),
    (SKEIN512_144, 0xb332, "skein512-144", "multihash"),
    (SKEIN512_152, 0xb333, "skein512-152", "multihash"),
    (SKEIN512_160, 0xb334, "skein512-160", "multihash"),
    (SKEIN512_168, 0xb335, "skein512-168", "multihash"),
    (SKEIN512_176, 0xb336, "skein512-176", "multihash"),
    (SKEIN512_184, 0xb337, "skein512-184", "multihash"),
    (SKEIN512_192, 0xb338, "skein512-192", "multihash"),
    (SKEIN512_200, 0xb339, "skein512-200", "multihash"),
    (SKEIN512_208, 0xb33a, "skein512-208", "multihash"),
    (SKEIN512_216, 0xb33b, "skein512-216", "multihash"),
    (SKEIN512_224, 0xb33c, "skein512-224", "multihash"),
    (SKEIN512_232, 0xb33d, "skein512-232", "multihash"),
    (SKEIN512_240, 0xb33e, "skein512-240", "multihash"),
    (SKEIN512_248, 0xb33f, "skein512-248", "multihash"),
    (SKEIN512_256, 0xb340, "skein512-256", "multihash"),
    (SKEIN512_264, 0xb341, "skein512-264", "multihash"),
    (SKEIN512_272, 0xb342, "skein512-272", "multihash"),
    (SKEIN512_280, 0xb343, "skein512-280", "multihash"),
    (SKEIN512_288, 0xb344, "skein512-288", "multihash"),
    (SKEIN512_296, 0xb345, "skein512-296", "multihash"),
    (SKEIN512_304, 0xb346, "skein512-304", "multihash"),
    (SKEIN512_312, 0xb347, "skein512-312", "multihash"),
    (SKEIN512_320, 0xb348, "skein512-320", "multihash"),
    (SKEIN512_328, 0xb349, "skein512-328", "multihash"),
    (SKEIN512_336, 0xb34a, "skein512-336", "multihash"),
    (SKEIN512_344, 0xb34b, "skein512-344", "multihash"),
    (SKEIN512_352, 0xb34c, "skein512-352", "multihash"),
    (SKEIN512_360, 0xb34d, "skein512-360", "multihash"),
    (SKEIN512_368, 0xb34e, "skein512-368", "multihash"),
    (SKEIN512_376, 0xb34f, "skein512-376", "multihash"),
    (SKEIN512_384, 0xb350, "skein512-384", "multihash"),
    (SKEIN512_392, 0xb351, "skein512-392", "multihash"),
    (SKEIN512_400, 0xb352, "skein512-400", "multihash"),
    (SKEIN512_408, 0xb353, "skein512-408", "multihash"),
    (SKEIN512_416, 0xb354, "skein512-416", "multihash"),
    (SKEIN512_424, 0xb355, "skein512-424", "multihash"),
    (SKEIN512_432, 0xb356, "skein512-432", "multihash"),
    (SKEIN512_440, 0xb357, "skein512-440", "multihash"),
    (SKEIN512_448, 0xb358, "skein512-448", "multihash"),
    (SKEIN512_456, 0xb359, "skein512-456", "multihash"),
    (SKEIN512_464, 0xb35a, "skein512-464", "multihash"),
    (SKEIN512_472, 0xb35b, "skein512-472", "multihash"),
    (SKEIN512_480, 0xb35c, "skein512-480", "multihash"),
    (SKEIN512_488, 0xb35d, "skein512-488", "multihash"),
    (SKEIN512_496, 0xb35e, "skein512-496", "multihash"),
    (SKEIN512_504, 0xb35f, "skein512-504", "multihash"),
    (SKEIN512_512, 0xb360, "skein512-512", "multihash"),
    (SKEIN1024_8, 0xb361, "skein1024-8", "multihash"),
    (SKEIN1024_16, 0xb362, "skein1024-16", "multihash"),
    (SKEIN1024_24, 0xb363, "skein1024-24", "multihash"),
    (SKEIN1024_32, 0xb364, "skein1024-32", "multihash"),
    (SKEIN1024_40, 0xb365, "skein1024-40", "multihash"),
    (SKEIN1024_48, 0xb366, "skein1024-48", "multihash"),
    (SKEIN1024_56, 0xb367, "skein1024-56", "multihash"),
    (SKEIN1024_64, 0xb368, "skein1024-64", "multihash"),
    (SKEIN1024_72, 0xb369, "skein1024-72", "multihash"),
    (SKEIN1024_80, 0xb36a, "skein1024-80", "multihash"),
    (SKEIN1024_88, 0xb36b, "skein1024-88", "multihash"),
    (SKEIN1024_96, 0xb36c, "skein1024-96", "multihash"),
    (SKEIN1024_104, 0xb36d, "skein1024-104", "multihash"),
    (SKEIN1024_112, 0xb36e, "skein1024-112", "multihash"),
    (SKEIN1024_120, 0xb36f, "skein1024-120", "multihash"),
    (SKEIN1024_128, 0xb370, "skein1024-128", "multihash"),
    (SKEIN1024_136, 0xb371, "skein1024-136", "multihash"),
    (SKEIN1024_144, 0xb372, "skein1024-144", "multihash"),
    (SKEIN1024_152, 0xb373, "skein1024-152", "multihash"),
    (SKEIN1024_160, 0xb374, "skein1024-160", "multihash"),
    (SKEIN1024_168, 0xb375, "skein1024-168", "multihash"),
    (SKEIN1024_176, 0xb376, "skein1024-176", "multihash"),
    (SKEIN1024_184, 0xb377, "skein1024-184", "multihash"),
    (SKEIN1024_192, 0xb378, "skein1024-192", "multihash"),
    (SKEIN1024_200, 0xb379, "skein1024-200", "multihash"),
    (SKEIN1024_208, 0xb37a, "skein1024-208", "multihash"),
    (SKEIN1024_216, 0xb37b, "skein1024-216", "multihash"),
    (SKEIN1024_224, 0xb37c, "skein1024-224", "multihash"),
    (SKEIN1024_232, 0xb37d, "skein1024-232", "multihash"),
    (SKEIN1024_240, 0xb37e, "skein1024-240", "multihash"),
    (SKEIN1024_248, 0xb37f, "skein1024-248", "multihash"),
    (SKEIN1024_256, 0xb380, "skein1024-256", "multihash"),
    (SKEIN1024_264, 0xb381, "skein1024-264", "multihash"),
    (SKEIN1024_272, 0xb382, "skein1024-272", "multihash"),
    (SKEIN1024_280, 0xb383, "skein1024-280", "multihash"),
    (SKEIN1024_288, 0xb384, "skein1024-288", "multihash"),
    (SKEIN1024_296, 0xb385, "skein1024-296", "multihash"),
    (SKEIN1024_304, 0xb386, "skein1024-304", "multihash"),
    (SKEIN1024_312, 0xb387, "skein1024-312", "multihash"),
    (SKEIN1024_320, 0xb388, "skein1024-320", "multihash"),
    (SKEIN1024_328, 0xb389, "skein1024-328", "multihash"),
    (SKEIN1024_336, 0xb38a, "skein1024-336", "multihash"),
    (SKEIN1024_344, 0xb38b, "skein1024-344", "multihash"),
    (SKEIN1024_352, 0xb38c, "skein1024-352", "multihash"),
    (SKEIN1024_360, 0xb38d, "skein1024-360", "multihash"),
    (SKEIN1024_368, 0xb38e, "skein1024-368", "multihash"),
    (SKEIN1024_376, 0xb38f, "skein1024-376", "multihash"),
    (SKEIN1024_384, 0xb390, "skein1024-384", "multihash"),
    (SKEIN1024_392, 0xb391, "skein1024-392", "multihash"),
    (SKEIN1024_400, 0xb392, "skein1024-400", "multihash"),
    (SKEIN1024_408, 0xb393, "skein1024-408", "multihash"),
    (SKEIN1024_416, 0xb394, "skein1024-416", "multihash"),
    (SKEIN1024_424, 0xb395, "skein1024-424", "multihash"),
    (SKEIN1024_432, 0xb396, "skein1024-432", "multihash"),
    (SKEIN1024_440, 0xb397, "skein1024-440", "multihash"),
    (SKEIN1024_448, 0xb398, "skein1024-448", "multihash"),
    (SKEIN1024_456, 0xb399, "skein1024-456", "multihash"),
    (SKEIN1024_464, 0xb39a, "skein1024-464", "multihash"),
    (SKEIN1024_472, 0xb39b, "skein1024-472", "multihash"),
    (SKEIN1024_480, 0xb39c, "skein1024-480", "multihash"),
    (SKEIN1024_488, 0xb39d, "skein1024-488", "multihash"),
    (SKEIN1024_496, 0xb39e, "skein1024-496", "multihash"),
    (SKEIN1024_504, 0xb39f, "skein1024-504", "multihash"),
    (SKEIN1024_512, 0xb3a0, "skein1024-512", "multihash"),
    (SKEIN1024_520, 0xb3a1, "skein1024-520", "multihash"),
    (SKEIN1024_528, 0xb3a2, "skein1024-528", "multihash"),
    (SKEIN1024_536, 0xb3a3, "skein1024-536", "multihash"),
    (SKEIN1024_544, 0xb3a4, "skein1024-544", "multihash"),
    (SKEIN1024_552, 0xb3a5, "skein1024-552", "multihash"),
    (SKEIN1024_560, 0xb3a6, "skein1024-560", "multihash"),
    (SKEIN1024_568, 0xb3a7, "skein1024-568", "multihash"),
    (SKEIN1024_576, 0xb3a8, "skein1024-576", "multihash"),
    (SKEIN1024_584, 0xb3a9, "skein1024-584", "multihash"),
    (SKEIN1024_592, 0xb3aa, "skein1024-592", "multihash"),
    (SKEIN1024_600, 0xb3ab, "skein1024-600", "multihash"),
    (SKEIN1024_608, 0xb3ac, "skein1024-608", "multihash"),
    (SKEIN1024_616, 0xb3ad, "skein1024-616", "multihash"),
    (SKEIN1024_624, 0xb3ae, "skein1024-624", "multihash"),
    (SKEIN1024_632, 0xb3af, "skein1024-632", "multihash"),
    (SKEIN1024_640, 0xb3b0, "skein1024-640", "multihash"),
    (SKEIN1024_648, 0xb3b1, "skein1024-648", "multihash"),
    (SKEIN1024_656, 0xb3b2, "skein1024-656", "multihash"),
    (SKEIN1024_664, 0xb3b3, "skein1024-664", "multihash"),
    (SKEIN1024_672, 0xb3b4, "skein1024-672", "multihash"),
    (SKEIN1024_680, 0xb3b5, "skein1024-680", "multihash"),
    (SKEIN1024_688, 0xb3b6, "skein1024-688", "multihash"),
    (SKEIN1024_696, 0xb3b7, "skein1024-696", "multihash"),
    (SKEIN1024_704, 0xb3b8, "skein1024-704", "multihash"),
    (SKEIN1024_712, 0xb3b9, "skein1024-712", "multihash"),
    (SKEIN1024_720, 0xb3ba, "skein1024-720", "multihash"),
    (SKEIN1024_728, 0xb3bb, "skein1024-728", "multihash"),
    (SKEIN1024_736, 0xb3bc, "skein1024-736", "multihash"),
    (SKEIN1024_744, 0xb3bd, "skein1024-744", "multihash"),
    (SKEIN1024_752, 0xb3be, "skein1024-752", "multihash"),
    (SKEIN1024_760, 0xb3bf, "skein1024-760", "multihash"),
    (SKEIN1024_768, 0xb3c0, "skein1024-768", "multihash"),
    (SKEIN1024_776, 0xb3c1, "skein1024-776", "multihash"),
    (SKEIN1024_784, 0xb3c2, "skein1024-784", "multihash"),
    (SKEIN1024_792, 0xb3c3, "skein1024-792", "multihash"),
    (SKEIN1024_800, 0xb3c4, "skein1024-800", "multihash"),
    (SKEIN1024_808, 0xb3c5, "skein1024-808", "multihash"),
    (SKEIN1024_816, 0xb3c6, "skein1024-816", "multihash"),
    (SKEIN1024_824, 0xb3c7, "skein1024-824", "multihash"),
    (SKEIN1024_832, 0xb3c8, "skein1024-832", "multihash"),
    (SKEIN1024_840, 0xb3c9, "skein1024-840", "multihash"),
    (SKEIN1024_848, 0xb3ca, "skein1024-848", "multihash"),
    (SKEIN1024_856, 0xb3cb, "skein1024-856", "multihash"),
    (SKEIN1024_864, 0xb3cc, "skein1024-864", "multihash"),
    (SKEIN1024_872, 0xb3cd, "skein1024-872", "multihash"),
    (SKEIN1024_880, 0xb3ce, "skein1024-880", "multihash"),
    (SKEIN1024_888, 0xb3cf, "skein1024-888", "multihash"),
    (SKEIN1024_896, 0xb3d0, "skein1024-896", "multihash"),
    (SKEIN1024_904, 0xb3d1, "skein1024-904", "multihash"),
    (SKEIN1024_912, 0xb3d2, "skein1024-912", "multihash"),
    (SKEIN1024_920, 0xb3d3, "skein1024-920", "multihash"),
    (SKEIN1024_928, 0xb3d4, "skein1024-928", "multihash"),
    (SKEIN1024_936, 0xb3d5, "skein1024-936", "multihash"),
    (SKEIN1024_944, 0xb3d6, "skein1024-944", "multihash"),
    (SKEIN1024_952, 0xb3d7, "skein1024-952", "multihash"),
    (SKEIN1024_960, 0xb3d8, "skein1024-960", "multihash"),
    (SKEIN1024_968, 0xb3d9, "skein1024-968", "multihash"),
    (SKEIN1024_976, 0xb3da, "skein1024-976", "multihash"),
    (SKEIN1024_984, 0xb3db, "skein1024-984", "multihash"),
    (SKEIN1024_992, 0xb3dc, "skein1024-992", "multihash"),
    (SKEIN1024_1000, 0xb3dd, "skein1024-1000", "multihash"),
    (SKEIN1024_1008, 0xb3de, "skein1024-1008", "multihash"),
    (SKEIN1024_1016, 0xb3df, "skein1024-1016", "multihash"),
    (SKEIN1024_1024, 0xb3e0, "skein1024-1024", "multihash"),
    (
        POSEIDON_BLS12_381_A2_FC1,
        0xb401,
        "poseidon-bls12_381-a2-fc1",
        "multihash"
    ),
    (
        POSEIDON_BLS12_381_A2_FC1_SC,
        0xb402,
        "poseidon-bls12_381-a2-fc1-sc",
        "multihash"
    ),
    (
        ZEROXCERT_IMPRINT_256,
        0xce11,
        "zeroxcert-imprint-256",
        "zeroxcert"
    ),
    (
        FIL_COMMITMENT_UNSEALED,
        0xf101,
        "fil-commitment-unsealed",
        "filecoin"
    ),
    (
        FIL_COMMITMENT_SEALED,
        0xf102,
        "fil-commitment-sealed",
        "filecoin"
    ),
    (HOLOCHAIN_ADR_V0, 0x807124, "holochain-adr-v0", "holochain"),
    (HOLOCHAIN_ADR_V1, 0x817124, "holochain-adr-v1", "holochain"),
    (HOLOCHAIN_KEY_V0, 0x947124, "holochain-key-v0", "holochain"),
    (HOLOCHAIN_KEY_V1, 0x957124, "holochain-key-v1", "holochain"),
    (HOLOCHAIN_SIG_V0, 0xa27124, "holochain-sig-v0", "holochain"),
    (HOLOCHAIN_SIG_V1, 0xa37124, "holochain-sig-v1", "holochain"),
];

#[cfg(test)]
mod tests {
    use parse_int;
    use reqwest::blocking::get;

    use super::*;

    #[test]
    fn test_table() {
        let spec = {
            let uri = "https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv";
            get(uri).unwrap().text().unwrap()
        };
        let spec_lines: Vec<Vec<String>> = {
            let mut total_lines: Vec<String> = {
                let iter = spec.lines().map(|s| s.to_string());
                iter.collect()
            };
            total_lines.remove(0); // remove the column header.
            let mut total_lines: Vec<Vec<String>> = total_lines
                .into_iter()
                .map(|s| {
                    let mut row = s
                        .split(",")
                        .map(|col| col.trim().to_string())
                        .collect::<Vec<String>>();
                    row.pop(); // remove the description;
                    if row[2] == "0x00" {
                        row[2] = "0".to_string();
                    }
                    let code: u32 = parse_int::parse(&row[2]).expect(&format!("{}", row[2]));
                    vec![row.remove(0), format!("0x{:x}", code), row.remove(0)] // re-order colums
                })
                .collect();
            // remove (ipfs, multiaddr, 0x01a5, libp2p (deprecated))
            assert_eq!(total_lines[97][0], "ipfs", "{:?}", total_lines[97]);
            assert_eq!(total_lines[97][1], "0x1a5", "{:?}", total_lines[97]);
            assert_eq!(total_lines[97][2], "multiaddr", "{:?}", total_lines[97]);
            total_lines.remove(97);
            total_lines
        };
        let pkg_lines: Vec<Vec<String>> = (&TABLE)
            .to_vec()
            .into_iter()
            .map(|cp| vec![cp.name, format!("0x{:x}", cp.code), cp.tag])
            .collect();
        assert_eq!(
            spec_lines.len(),
            pkg_lines.len(),
            "{} {}",
            spec_lines.len(),
            pkg_lines.len()
        );

        for (x, y) in spec_lines.into_iter().zip(pkg_lines.into_iter()) {
            assert_eq!(x[0], y[0], "{:?}, {:?}", x, y);
            assert_eq!(x[1], y[1], "{:?}, {:?}", x, y);
            assert_eq!(x[2], y[2], "{:?}, {:?}", x, y);
        }
    }

    #[test]
    fn test_codec() {
        for entry in TABLE.iter() {
            let code: Multicodec = entry.into();

            let buf = code.encode().unwrap();

            let mut buf_with = Vec::default();
            assert_eq!(
                code.encode_with(&mut buf_with).unwrap(),
                buf.len(),
                "{:?}",
                code
            );
            assert_eq!(&buf_with[..buf.len()], buf.as_slice(), "{:?}", code);

            let (res_code, res_buf) = Multicodec::from_slice(&buf).unwrap();
            assert_eq!(res_code, code, "{:?}", code);
            assert_eq!(res_buf, vec![].as_slice(), "{:?}", code);
        }
    }
}
