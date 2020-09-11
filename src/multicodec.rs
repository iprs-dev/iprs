//! Module implement [multicodec] specification.
//!
//! Multicodec is an agreed-upon codec table. It is designed for
//! use in binary representations, such as keys or identifiers. This
//! package implement default [TABLE] defined in multicodec specification.
//!
//! [multicodec]: https://github.com/multiformats/multicodec
//! [TABLE]: https://github.com/multiformats/multicodec/blob/master/table.csv

use lazy_static::lazy_static;

use std::{convert::TryFrom, fmt, io, result};

use crate::{Error, Result};

/// Type implements [multicodec] and [unsigned-varint] specs.
///
/// [multicodec]: https://github.com/multiformats/multicodec
/// [unsigned-varint]: https://github.com/multiformats/unsigned-varint
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Multicodec {
    code: u128,
}

impl fmt::Debug for Multicodec {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "Multicodec<{}>", self.code)
    }
}

impl fmt::Display for Multicodec {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", self.code)
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

impl From<Multicodec> for u128 {
    fn from(val: Multicodec) -> u128 {
        val.code
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
        err_at!(Err(Error::BadCodec(
            "".to_string(),
            format!("multicode-name {}", name)
        )))
    }
}

impl Multicodec {
    /// Create a new Multicodec from u128 code value.
    pub fn from_code(code: u128) -> Result<Multicodec> {
        Ok(Multicodec { code })
    }

    /// Convert incoming stream of bytes into multicodec value. Return
    /// remaining unparsed slice.
    ///
    /// Return [Error::Invalid] if `buf's` content can't be recognised.
    pub fn from_slice(buf: &[u8]) -> Result<(Multicodec, &[u8])> {
        let (code, rem) = err_at!(Invalid, unsigned_varint::decode::u128(buf))?;
        Ok((Multicodec { code }, rem))
    }

    /// Encode Multicodec to unsigned-varint bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut buf);
        Ok(slice.to_vec())
    }

    /// Similar to encode() by avoid allocation by using supplied buffer
    /// `buf`.
    pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        let mut scratch: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut scratch);
        err_at!(IOError, buf.write(&slice))?;
        Ok(slice.len())
    }

    /// Return the underling code-value.
    pub fn to_code(&self) -> u128 {
        self.code
    }
}

/// Type describing a single code-point in the multicodec table.
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
    ($(
        #[$doc:meta]
        ($label:ident, $code:expr, $name:expr, $tag:expr),
    )*) => (
        $(
            #[$doc]
            pub const $label: u128 = $code;
        )*

        lazy_static! {
            /// Default codec table. Refer [table] for details.
            ///
            /// Constructed using lazy_static!() macro, use this as
            /// `Vec<Codepoint>`.
            ///
            /// [table]: https://github.com/multiformats/multicodec/blob/master/table.csv
            pub static ref TABLE: Vec<Codepoint> = vec![
                $(Codepoint {
                    code: $code,
                    name: $name.to_string(),
                    tag: $tag.to_string()
                },)*
            ];

            // Pre-sorted table of multihash code values, only codes tagged as
            // "multihash" will be gathered in this table.
            static ref TABLE_MULTIHASH: Vec<Codepoint> = {
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

            // Pre-sorted table of multibase code values, only codes tagged as
            // "multibase" will be gathered in this table.
            static ref TABLE_MULTIBASE: Vec<Codepoint> = {
                let mut codes = Vec::default();
                $(
                    match $tag {
                        "multibase" => codes.push(Codepoint {
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
    /// _multihash_, Raw binary
    (IDENTITY, 0x00, "identity", "multihash"),
    /// _ipld_, Content identifier for IPFS, version 1
    (CID_V1, 0x01, "cidv1", "ipld"),
    /// _ipld_, Content identifier for IPFS, version 2
    (CID_V2, 0x02, "cidv2", "ipld"),
    /// _ipld_, Content identifier for IPFS, version 3
    (CID_V3, 0x03, "cidv3", "ipld"),
    /// _multiaddr_, Internet Protocol version 4
    (IP4, 0x04, "ip4", "multiaddr"),
    /// _multiaddr_, Transport Control Protocol
    (TCP, 0x06, "tcp", "multiaddr"),
    /// _multihash_, Secure Hash Algorithm 1
    (SHA1, 0x11, "sha1", "multihash"),
    /// _multihash_, Secure Hash Algorithm 2, 256 bits
    (SHA2_256, 0x12, "sha2-256", "multihash"),
    /// _multihash_, Secure Hash Algorithm 2, 512 bits
    (SHA2_512, 0x13, "sha2-512", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 512 bits
    (SHA3_512, 0x14, "sha3-512", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 384 bits
    (SHA3_384, 0x15, "sha3-384", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 256 bits
    (SHA3_256, 0x16, "sha3-256", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 224 bits
    (SHA3_224, 0x17, "sha3-224", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 128 bit security and variable output.
    (SHAKE_128, 0x18, "shake-128", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3, 256 bit security and variable output.
    (SHAKE_256, 0x19, "shake-256", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3
    (KECCAK_224, 0x1a, "keccak-224", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3
    (KECCAK_256, 0x1b, "keccak-256", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3
    (KECCAK_384, 0x1c, "keccak-384", "multihash"),
    /// _multihash_, Secure Hash Algorithm 3
    (KECCAK_512, 0x1d, "keccak-512", "multihash"),
    /// _multihash_, Blake3 Algorithm
    (BLAKE3, 0x1e, "blake3", "multihash"),
    /// _multiaddr_, Datagram congestion protocol
    (DCCP, 0x21, "dccp", "multiaddr"),
    /// _multihash_, Murmur3 hash algorithm, 128-bit security
    (MURMUR3_128, 0x22, "murmur3-128", "multihash"),
    /// _multihash_, Murmur3 hash algorithm, 32-bit security
    (MURMUR3_32, 0x23, "murmur3-32", "multihash"),
    /// _multiaddr_, Internet Protocol version 6
    (IP6, 0x29, "ip6", "multiaddr"),
    /// _multiaddr_
    (IP6ZONE, 0x2a, "ip6zone", "multiaddr"),
    /// _namespace_
    (PATH, 0x2f, "path", "namespace"),
    /// _multiformat_, multicodec specification from [multiformats][http://multiformats.io]
    (MULTICODEC, 0x30, "multicodec", "multiformat"),
    /// _multiformat_, multihash specification from [multiformats][http://multiformats.io]
    (MULTIHASH, 0x31, "multihash", "multiformat"),
    /// _multiformat_, multiaddr specification from [multiformats][http://multiformats.io]
    (MULTIADDR, 0x32, "multiaddr", "multiformat"),
    /// _multiformat_, multibase specification from [multiformats][http://multiformats.io]
    (MULTIBASE, 0x33, "multibase", "multiformat"),
    /// _multiaddr_, Domain name system
    (DNS, 0x35, "dns", "multiaddr"),
    /// _multiaddr_
    (DNS4, 0x36, "dns4", "multiaddr"),
    /// _multiaddr_
    (DNS6, 0x37, "dns6", "multiaddr"),
    /// _multiaddr_
    (DNSADDR, 0x38, "dnsaddr", "multiaddr"),
    /// _serialization_, Protocol buffer
    (PROTOBUF, 0x50, "protobuf", "serialization"),
    /// _serialization_, Concise Binary Object Representation
    (CBOR, 0x51, "cbor", "serialization"),
    /// _ipld_
    (RAW, 0x55, "raw", "ipld"),
    /// _multihash_
    (DBL_SHA2_256, 0x56, "dbl-sha2-256", "multihash"),
    /// _serialization_
    (RLP, 0x60, "rlp", "serialization"),
    /// _serialization_
    (BENCODE, 0x63, "bencode", "serialization"),
    /// _ipld_
    (DAG_PB, 0x70, "dag-pb", "ipld"),
    /// _ipld_
    (DAG_CBOR, 0x71, "dag-cbor", "ipld"),
    /// _ipld_
    (LIBP2P_KEY, 0x72, "libp2p-key", "ipld"),
    /// _ipld_
    (GIT_RAW, 0x78, "git-raw", "ipld"),
    /// _ipld_
    (TORRENT_INFO, 0x7b, "torrent-info", "ipld"),
    /// _ipld_
    (TORRENT_FILE, 0x7c, "torrent-file", "ipld"),
    /// _ipld_
    (LEOFCOIN_BLOCK, 0x81, "leofcoin-block", "ipld"),
    /// _ipld_
    (LEOFCOIN_TX, 0x82, "leofcoin-tx", "ipld"),
    /// _ipld_
    (LEOFCOIN_PR, 0x83, "leofcoin-pr", "ipld"),
    /// _multiaddr_
    (SCTP, 0x84, "sctp", "multiaddr"),
    /// _ipld_
    (DAG_JOSE, 0x85, "dag-jose", "ipld"),
    /// _ipld_
    (DAG_COSE, 0x86, "dag-cose", "ipld"),
    /// _ipld_
    (ETH_BLOCK, 0x90, "eth-block", "ipld"),
    /// _ipld_
    (ETH_BLOCK_LIST, 0x91, "eth-block-list", "ipld"),
    /// _ipld_
    (ETH_TX_TRIE, 0x92, "eth-tx-trie", "ipld"),
    /// _ipld_
    (ETH_TX, 0x93, "eth-tx", "ipld"),
    /// _ipld_
    (ETH_TX_RECEIPT_TRIE, 0x94, "eth-tx-receipt-trie", "ipld"),
    /// _ipld_
    (ETH_TX_RECEIPT, 0x95, "eth-tx-receipt", "ipld"),
    /// _ipld_
    (ETH_STATE_TRIE, 0x96, "eth-state-trie", "ipld"),
    /// _ipld_
    (ETH_ACCOUNT_SNAPSHOT, 0x97, "eth-account-snapshot", "ipld"),
    /// _ipld_
    (ETH_STORAGE_TRIE, 0x98, "eth-storage-trie", "ipld"),
    /// _ipld_
    (BITCOIN_BLOCK, 0xb0, "bitcoin-block", "ipld"),
    /// _ipld_
    (BITCOIN_TX, 0xb1, "bitcoin-tx", "ipld"),
    /// _ipld_
    (
        BITCOIN_WITNESS_COMMITMENT,
        0xb2,
        "bitcoin-witness-commitment",
        "ipld"
    ),
    /// _ipld_
    (ZCASH_BLOCK, 0xc0, "zcash-block", "ipld"),
    /// _ipld_
    (ZCASH_TX, 0xc1, "zcash-tx", "ipld"),
    /// _ipld_
    (STELLAR_BLOCK, 0xd0, "stellar-block", "ipld"),
    /// _ipld_
    (STELLAR_TX, 0xd1, "stellar-tx", "ipld"),
    /// _multihash_
    (MD4, 0xd4, "md4", "multihash"),
    /// _multihash_
    (MD5, 0xd5, "md5", "multihash"),
    /// _multihash_
    (BMT, 0xd6, "bmt", "multihash"),
    /// _ipld_
    (DECRED_BLOCK, 0xe0, "decred-block", "ipld"),
    /// _ipld_
    (DECRED_TX, 0xe1, "decred-tx", "ipld"),
    /// _namespace_
    (IPLD_NS, 0xe2, "ipld-ns", "namespace"),
    /// _namespace_
    (IPFS_NS, 0xe3, "ipfs-ns", "namespace"),
    /// _namespace_
    (SWARM_NS, 0xe4, "swarm-ns", "namespace"),
    /// _namespace_
    (IPNS_NS, 0xe5, "ipns-ns", "namespace"),
    /// _namespace_
    (ZERONET, 0xe6, "zeronet", "namespace"),
    /// _key_
    (SECP256K1_PUB, 0xe7, "secp256k1-pub", "key"),
    /// _key_
    (BLS12_381_G1_PUB, 0xea, "bls12_381-g1-pub", "key"),
    /// _key_
    (BLS12_381_G2_PUB, 0xeb, "bls12_381-g2-pub", "key"),
    /// _key_
    (X25519_PUB, 0xec, "x25519-pub", "key"),
    /// _key_
    (ED25519_PUB, 0xed, "ed25519-pub", "key"),
    /// _ipld_
    (DASH_BLOCK, 0xf0, "dash-block", "ipld"),
    /// _ipld_
    (DASH_TX, 0xf1, "dash-tx", "ipld"),
    /// _ipld_
    (SWARM_MANIFEST, 0xfa, "swarm-manifest", "ipld"),
    /// _ipld_
    (SWARM_FEED, 0xfb, "swarm-feed", "ipld"),
    /// _multiaddr_
    (UDP, 0x0111, "udp", "multiaddr"),
    /// _multiaddr_
    (P2P_WEBRTC_STAR, 0x0113, "p2p-webrtc-star", "multiaddr"),
    /// _multiaddr_
    (P2P_WEBRTC_DIRECT, 0x0114, "p2p-webrtc-direct", "multiaddr"),
    /// _multiaddr_
    (P2P_STARDUST, 0x0115, "p2p-stardust", "multiaddr"),
    /// _multiaddr_
    (P2P_CIRCUIT, 0x0122, "p2p-circuit", "multiaddr"),
    /// _ipld_
    (DAG_JSON, 0x0129, "dag-json", "ipld"),
    /// _multiaddr_
    (UDT, 0x012d, "udt", "multiaddr"),
    /// _multiaddr_
    (UTP, 0x012e, "utp", "multiaddr"),
    /// _multiaddr_
    (UNIX, 0x0190, "unix", "multiaddr"),
    /// _multiaddr_
    (P2P, 0x01a5, "p2p", "multiaddr"),
    /// _multiaddr_
    (HTTPS, 0x01bb, "https", "multiaddr"),
    /// _multiaddr_
    (ONION, 0x01bc, "onion", "multiaddr"),
    /// _multiaddr_
    (ONION3, 0x01bd, "onion3", "multiaddr"),
    /// _multiaddr_
    (GARLIC64, 0x01be, "garlic64", "multiaddr"),
    /// _multiaddr_
    (GARLIC32, 0x01bf, "garlic32", "multiaddr"),
    /// _multiaddr_
    (TLS, 0x01c0, "tls", "multiaddr"),
    /// _multiaddr_
    (QUIC, 0x01cc, "quic", "multiaddr"),
    /// _multiaddr_
    (WS, 0x01dd, "ws", "multiaddr"),
    /// _multiaddr_
    (WSS, 0x01de, "wss", "multiaddr"),
    /// _multiaddr_
    (
        P2P_WEBSOCKET_STAR,
        0x01df,
        "p2p-websocket-star",
        "multiaddr"
    ),
    /// _multiaddr_
    (HTTP, 0x01e0, "http", "multiaddr"),
    /// _serialization_
    (JSON, 0x0200, "json", "serialization"),
    /// _serialization_
    (MESSAGEPACK, 0x0201, "messagepack", "serialization"),
    /// _libp2p_
    (LIBP2P_PEER_RECORD, 0x0301, "libp2p-peer-record", "libp2p"),
    /// _multihash_
    (
        SHA2_256_TRUNC254_PADDED,
        0x1012,
        "sha2-256-trunc254-padded",
        "multihash"
    ),
    /// _multihash_
    (RIPEMD_128, 0x1052, "ripemd-128", "multihash"),
    /// _multihash_
    (RIPEMD_160, 0x1053, "ripemd-160", "multihash"),
    /// _multihash_
    (RIPEMD_256, 0x1054, "ripemd-256", "multihash"),
    /// _multihash_
    (RIPEMD_320, 0x1055, "ripemd-320", "multihash"),
    /// _multihash_
    (X11, 0x1100, "x11", "multihash"),
    /// _key_
    (P256_PUB, 0x1200, "p256-pub", "key"),
    /// _key_
    (P384_PUB, 0x1201, "p384-pub", "key"),
    /// _key_
    (P521_PUB, 0x1202, "p521-pub", "key"),
    /// _key_
    (ED448_PUB, 0x1203, "ed448-pub", "key"),
    /// _key_
    (X448_PUB, 0x1204, "x448-pub", "key"),
    /// _multihash_
    (KANGAROOTWELVE, 0x1d01, "kangarootwelve", "multihash"),
    /// _multihash_
    (SM3_256, 0x534d, "sm3-256", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 8-bit digest.
    (BLAKE2B_8, 0xb201, "blake2b-8", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 16-bit digest.
    (BLAKE2B_16, 0xb202, "blake2b-16", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 24-bit digest.
    (BLAKE2B_24, 0xb203, "blake2b-24", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 32-bit digest.
    (BLAKE2B_32, 0xb204, "blake2b-32", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 40-bit digest.
    (BLAKE2B_40, 0xb205, "blake2b-40", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 48-bit digest.
    (BLAKE2B_48, 0xb206, "blake2b-48", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 56-bit digest.
    (BLAKE2B_56, 0xb207, "blake2b-56", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 64-bit digest.
    (BLAKE2B_64, 0xb208, "blake2b-64", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 72-bit digest.
    (BLAKE2B_72, 0xb209, "blake2b-72", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 80-bit digest.
    (BLAKE2B_80, 0xb20a, "blake2b-80", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 88-bit digest.
    (BLAKE2B_88, 0xb20b, "blake2b-88", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 96-bit digest.
    (BLAKE2B_96, 0xb20c, "blake2b-96", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 104-bit digest.
    (BLAKE2B_104, 0xb20d, "blake2b-104", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 112-bit digest.
    (BLAKE2B_112, 0xb20e, "blake2b-112", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 120-bit digest.
    (BLAKE2B_120, 0xb20f, "blake2b-120", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 128-bit digest.
    (BLAKE2B_128, 0xb210, "blake2b-128", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 136-bit digest.
    (BLAKE2B_136, 0xb211, "blake2b-136", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 144-bit digest.
    (BLAKE2B_144, 0xb212, "blake2b-144", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 152-bit digest.
    (BLAKE2B_152, 0xb213, "blake2b-152", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 160-bit digest.
    (BLAKE2B_160, 0xb214, "blake2b-160", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 168-bit digest.
    (BLAKE2B_168, 0xb215, "blake2b-168", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 176-bit digest.
    (BLAKE2B_176, 0xb216, "blake2b-176", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 184-bit digest.
    (BLAKE2B_184, 0xb217, "blake2b-184", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 192-bit digest.
    (BLAKE2B_192, 0xb218, "blake2b-192", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 200-bit digest.
    (BLAKE2B_200, 0xb219, "blake2b-200", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 208-bit digest.
    (BLAKE2B_208, 0xb21a, "blake2b-208", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 216-bit digest.
    (BLAKE2B_216, 0xb21b, "blake2b-216", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 224-bit digest.
    (BLAKE2B_224, 0xb21c, "blake2b-224", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 232-bit digest.
    (BLAKE2B_232, 0xb21d, "blake2b-232", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 240-bit digest.
    (BLAKE2B_240, 0xb21e, "blake2b-240", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 248-bit digest.
    (BLAKE2B_248, 0xb21f, "blake2b-248", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 256-bit digest.
    (BLAKE2B_256, 0xb220, "blake2b-256", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 264-bit digest.
    (BLAKE2B_264, 0xb221, "blake2b-264", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 272-bit digest.
    (BLAKE2B_272, 0xb222, "blake2b-272", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 280-bit digest.
    (BLAKE2B_280, 0xb223, "blake2b-280", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 288-bit digest.
    (BLAKE2B_288, 0xb224, "blake2b-288", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 296-bit digest.
    (BLAKE2B_296, 0xb225, "blake2b-296", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 304-bit digest.
    (BLAKE2B_304, 0xb226, "blake2b-304", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 312-bit digest.
    (BLAKE2B_312, 0xb227, "blake2b-312", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 320-bit digest.
    (BLAKE2B_320, 0xb228, "blake2b-320", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 328-bit digest.
    (BLAKE2B_328, 0xb229, "blake2b-328", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 336-bit digest.
    (BLAKE2B_336, 0xb22a, "blake2b-336", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 344-bit digest.
    (BLAKE2B_344, 0xb22b, "blake2b-344", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 352-bit digest.
    (BLAKE2B_352, 0xb22c, "blake2b-352", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 360-bit digest.
    (BLAKE2B_360, 0xb22d, "blake2b-360", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 368-bit digest.
    (BLAKE2B_368, 0xb22e, "blake2b-368", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 376-bit digest.
    (BLAKE2B_376, 0xb22f, "blake2b-376", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 384-bit digest.
    (BLAKE2B_384, 0xb230, "blake2b-384", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 392-bit digest.
    (BLAKE2B_392, 0xb231, "blake2b-392", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 400-bit digest.
    (BLAKE2B_400, 0xb232, "blake2b-400", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 408-bit digest.
    (BLAKE2B_408, 0xb233, "blake2b-408", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 416-bit digest.
    (BLAKE2B_416, 0xb234, "blake2b-416", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 424-bit digest.
    (BLAKE2B_424, 0xb235, "blake2b-424", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 432-bit digest.
    (BLAKE2B_432, 0xb236, "blake2b-432", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 440-bit digest.
    (BLAKE2B_440, 0xb237, "blake2b-440", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 448-bit digest.
    (BLAKE2B_448, 0xb238, "blake2b-448", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 456-bit digest.
    (BLAKE2B_456, 0xb239, "blake2b-456", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 464-bit digest.
    (BLAKE2B_464, 0xb23a, "blake2b-464", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 472-bit digest.
    (BLAKE2B_472, 0xb23b, "blake2b-472", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 480-bit digest.
    (BLAKE2B_480, 0xb23c, "blake2b-480", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 488-bit digest.
    (BLAKE2B_488, 0xb23d, "blake2b-488", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 496-bit digest.
    (BLAKE2B_496, 0xb23e, "blake2b-496", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 504-bit digest.
    (BLAKE2B_504, 0xb23f, "blake2b-504", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 512-bit digest.
    (BLAKE2B_512, 0xb240, "blake2b-512", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 8-bit digest.
    (BLAKE2S_8, 0xb241, "blake2s-8", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 16-bit digest.
    (BLAKE2S_16, 0xb242, "blake2s-16", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 24-bit digest.
    (BLAKE2S_24, 0xb243, "blake2s-24", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 32-bit digest.
    (BLAKE2S_32, 0xb244, "blake2s-32", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 40-bit digest.
    (BLAKE2S_40, 0xb245, "blake2s-40", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 48-bit digest.
    (BLAKE2S_48, 0xb246, "blake2s-48", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 56-bit digest.
    (BLAKE2S_56, 0xb247, "blake2s-56", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 64-bit digest.
    (BLAKE2S_64, 0xb248, "blake2s-64", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 72-bit digest.
    (BLAKE2S_72, 0xb249, "blake2s-72", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 80-bit digest.
    (BLAKE2S_80, 0xb24a, "blake2s-80", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 88-bit digest.
    (BLAKE2S_88, 0xb24b, "blake2s-88", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 96-bit digest.
    (BLAKE2S_96, 0xb24c, "blake2s-96", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 104-bit digest.
    (BLAKE2S_104, 0xb24d, "blake2s-104", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 112-bit digest.
    (BLAKE2S_112, 0xb24e, "blake2s-112", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 120-bit digest.
    (BLAKE2S_120, 0xb24f, "blake2s-120", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 128-bit digest.
    (BLAKE2S_128, 0xb250, "blake2s-128", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 136-bit digest.
    (BLAKE2S_136, 0xb251, "blake2s-136", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 144-bit digest.
    (BLAKE2S_144, 0xb252, "blake2s-144", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 152-bit digest.
    (BLAKE2S_152, 0xb253, "blake2s-152", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 160-bit digest.
    (BLAKE2S_160, 0xb254, "blake2s-160", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 168-bit digest.
    (BLAKE2S_168, 0xb255, "blake2s-168", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 176-bit digest.
    (BLAKE2S_176, 0xb256, "blake2s-176", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 184-bit digest.
    (BLAKE2S_184, 0xb257, "blake2s-184", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 192-bit digest.
    (BLAKE2S_192, 0xb258, "blake2s-192", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 200-bit digest.
    (BLAKE2S_200, 0xb259, "blake2s-200", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 208-bit digest.
    (BLAKE2S_208, 0xb25a, "blake2s-208", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 216-bit digest.
    (BLAKE2S_216, 0xb25b, "blake2s-216", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 224-bit digest.
    (BLAKE2S_224, 0xb25c, "blake2s-224", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 232-bit digest.
    (BLAKE2S_232, 0xb25d, "blake2s-232", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 240-bit digest.
    (BLAKE2S_240, 0xb25e, "blake2s-240", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 248-bit digest.
    (BLAKE2S_248, 0xb25f, "blake2s-248", "multihash"),
    /// _multihash_, Blake2b hashing algorithm for 256-bit digest.
    (BLAKE2S_256, 0xb260, "blake2s-256", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 8-bit digest.
    (SKEIN256_8, 0xb301, "skein256-8", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 16-bit digest.
    (SKEIN256_16, 0xb302, "skein256-16", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 24-bit digest.
    (SKEIN256_24, 0xb303, "skein256-24", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 32-bit digest.
    (SKEIN256_32, 0xb304, "skein256-32", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 40-bit digest.
    (SKEIN256_40, 0xb305, "skein256-40", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 48-bit digest.
    (SKEIN256_48, 0xb306, "skein256-48", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 56-bit digest.
    (SKEIN256_56, 0xb307, "skein256-56", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 64-bit digest.
    (SKEIN256_64, 0xb308, "skein256-64", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 72-bit digest.
    (SKEIN256_72, 0xb309, "skein256-72", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 80-bit digest.
    (SKEIN256_80, 0xb30a, "skein256-80", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 88-bit digest.
    (SKEIN256_88, 0xb30b, "skein256-88", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state, 96-bit digest.
    (SKEIN256_96, 0xb30c, "skein256-96", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 04-bit digest.
    (SKEIN256_104, 0xb30d, "skein256-104", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 12-bit digest.
    (SKEIN256_112, 0xb30e, "skein256-112", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 20-bit digest.
    (SKEIN256_120, 0xb30f, "skein256-120", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 28-bit digest.
    (SKEIN256_128, 0xb310, "skein256-128", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 36-bit digest.
    (SKEIN256_136, 0xb311, "skein256-136", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 44-bit digest.
    (SKEIN256_144, 0xb312, "skein256-144", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 52-bit digest.
    (SKEIN256_152, 0xb313, "skein256-152", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 60-bit digest.
    (SKEIN256_160, 0xb314, "skein256-160", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 68-bit digest.
    (SKEIN256_168, 0xb315, "skein256-168", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 76-bit digest.
    (SKEIN256_176, 0xb316, "skein256-176", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 84-bit digest.
    (SKEIN256_184, 0xb317, "skein256-184", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,1 92-bit digest.
    (SKEIN256_192, 0xb318, "skein256-192", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 00-bit digest.
    (SKEIN256_200, 0xb319, "skein256-200", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 08-bit digest.
    (SKEIN256_208, 0xb31a, "skein256-208", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 16-bit digest.
    (SKEIN256_216, 0xb31b, "skein256-216", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 24-bit digest.
    (SKEIN256_224, 0xb31c, "skein256-224", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 32-bit digest.
    (SKEIN256_232, 0xb31d, "skein256-232", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 40-bit digest.
    (SKEIN256_240, 0xb31e, "skein256-240", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 48-bit digest.
    (SKEIN256_248, 0xb31f, "skein256-248", "multihash"),
    /// _multihash_, Skein hashing algorithm 256-bit state,2 56-bit digest.
    (SKEIN256_256, 0xb320, "skein256-256", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 8-bit digest.
    (SKEIN512_8, 0xb321, "skein512-8", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 16-bit digest.
    (SKEIN512_16, 0xb322, "skein512-16", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 24-bit digest.
    (SKEIN512_24, 0xb323, "skein512-24", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 32-bit digest.
    (SKEIN512_32, 0xb324, "skein512-32", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 40-bit digest.
    (SKEIN512_40, 0xb325, "skein512-40", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 48-bit digest.
    (SKEIN512_48, 0xb326, "skein512-48", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 56-bit digest.
    (SKEIN512_56, 0xb327, "skein512-56", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 64-bit digest.
    (SKEIN512_64, 0xb328, "skein512-64", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 72-bit digest.
    (SKEIN512_72, 0xb329, "skein512-72", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 80-bit digest.
    (SKEIN512_80, 0xb32a, "skein512-80", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 88-bit digest.
    (SKEIN512_88, 0xb32b, "skein512-88", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 96-bit digest.
    (SKEIN512_96, 0xb32c, "skein512-96", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 104-bit digest.
    (SKEIN512_104, 0xb32d, "skein512-104", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 112-bit digest.
    (SKEIN512_112, 0xb32e, "skein512-112", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 120-bit digest.
    (SKEIN512_120, 0xb32f, "skein512-120", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 128-bit digest.
    (SKEIN512_128, 0xb330, "skein512-128", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 136-bit digest.
    (SKEIN512_136, 0xb331, "skein512-136", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 144-bit digest.
    (SKEIN512_144, 0xb332, "skein512-144", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 152-bit digest.
    (SKEIN512_152, 0xb333, "skein512-152", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 160-bit digest.
    (SKEIN512_160, 0xb334, "skein512-160", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 168-bit digest.
    (SKEIN512_168, 0xb335, "skein512-168", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 176-bit digest.
    (SKEIN512_176, 0xb336, "skein512-176", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 184-bit digest.
    (SKEIN512_184, 0xb337, "skein512-184", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 192-bit digest.
    (SKEIN512_192, 0xb338, "skein512-192", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 200-bit digest.
    (SKEIN512_200, 0xb339, "skein512-200", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 208-bit digest.
    (SKEIN512_208, 0xb33a, "skein512-208", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 216-bit digest.
    (SKEIN512_216, 0xb33b, "skein512-216", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 224-bit digest.
    (SKEIN512_224, 0xb33c, "skein512-224", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 232-bit digest.
    (SKEIN512_232, 0xb33d, "skein512-232", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 240-bit digest.
    (SKEIN512_240, 0xb33e, "skein512-240", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 248-bit digest.
    (SKEIN512_248, 0xb33f, "skein512-248", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 256-bit digest.
    (SKEIN512_256, 0xb340, "skein512-256", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 264-bit digest.
    (SKEIN512_264, 0xb341, "skein512-264", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 272-bit digest.
    (SKEIN512_272, 0xb342, "skein512-272", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 280-bit digest.
    (SKEIN512_280, 0xb343, "skein512-280", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 288-bit digest.
    (SKEIN512_288, 0xb344, "skein512-288", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 296-bit digest.
    (SKEIN512_296, 0xb345, "skein512-296", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 304-bit digest.
    (SKEIN512_304, 0xb346, "skein512-304", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 312-bit digest.
    (SKEIN512_312, 0xb347, "skein512-312", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 320-bit digest.
    (SKEIN512_320, 0xb348, "skein512-320", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 328-bit digest.
    (SKEIN512_328, 0xb349, "skein512-328", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 336-bit digest.
    (SKEIN512_336, 0xb34a, "skein512-336", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 344-bit digest.
    (SKEIN512_344, 0xb34b, "skein512-344", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 352-bit digest.
    (SKEIN512_352, 0xb34c, "skein512-352", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 360-bit digest.
    (SKEIN512_360, 0xb34d, "skein512-360", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 368-bit digest.
    (SKEIN512_368, 0xb34e, "skein512-368", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 376-bit digest.
    (SKEIN512_376, 0xb34f, "skein512-376", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 384-bit digest.
    (SKEIN512_384, 0xb350, "skein512-384", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 392-bit digest.
    (SKEIN512_392, 0xb351, "skein512-392", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 400-bit digest.
    (SKEIN512_400, 0xb352, "skein512-400", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 408-bit digest.
    (SKEIN512_408, 0xb353, "skein512-408", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 416-bit digest.
    (SKEIN512_416, 0xb354, "skein512-416", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 424-bit digest.
    (SKEIN512_424, 0xb355, "skein512-424", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 432-bit digest.
    (SKEIN512_432, 0xb356, "skein512-432", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 440-bit digest.
    (SKEIN512_440, 0xb357, "skein512-440", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 448-bit digest.
    (SKEIN512_448, 0xb358, "skein512-448", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 456-bit digest.
    (SKEIN512_456, 0xb359, "skein512-456", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 464-bit digest.
    (SKEIN512_464, 0xb35a, "skein512-464", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 472-bit digest.
    (SKEIN512_472, 0xb35b, "skein512-472", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 480-bit digest.
    (SKEIN512_480, 0xb35c, "skein512-480", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 488-bit digest.
    (SKEIN512_488, 0xb35d, "skein512-488", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 496-bit digest.
    (SKEIN512_496, 0xb35e, "skein512-496", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 504-bit digest.
    (SKEIN512_504, 0xb35f, "skein512-504", "multihash"),
    /// _multihash_, Skein hashing algorithm 512-bit state, 512-bit digest.
    (SKEIN512_512, 0xb360, "skein512-512", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 8-bit digest.
    (SKEIN1024_8, 0xb361, "skein1024-8", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 16-bit digest.
    (SKEIN1024_16, 0xb362, "skein1024-16", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 24-bit digest.
    (SKEIN1024_24, 0xb363, "skein1024-24", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 32-bit digest.
    (SKEIN1024_32, 0xb364, "skein1024-32", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 40-bit digest.
    (SKEIN1024_40, 0xb365, "skein1024-40", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 48-bit digest.
    (SKEIN1024_48, 0xb366, "skein1024-48", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 56-bit digest.
    (SKEIN1024_56, 0xb367, "skein1024-56", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 64-bit digest.
    (SKEIN1024_64, 0xb368, "skein1024-64", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 72-bit digest.
    (SKEIN1024_72, 0xb369, "skein1024-72", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 80-bit digest.
    (SKEIN1024_80, 0xb36a, "skein1024-80", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 88-bit digest.
    (SKEIN1024_88, 0xb36b, "skein1024-88", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 96-bit digest.
    (SKEIN1024_96, 0xb36c, "skein1024-96", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 104-bit digest.
    (SKEIN1024_104, 0xb36d, "skein1024-104", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 112-bit digest.
    (SKEIN1024_112, 0xb36e, "skein1024-112", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 120-bit digest.
    (SKEIN1024_120, 0xb36f, "skein1024-120", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 128-bit digest.
    (SKEIN1024_128, 0xb370, "skein1024-128", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 136-bit digest.
    (SKEIN1024_136, 0xb371, "skein1024-136", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 144-bit digest.
    (SKEIN1024_144, 0xb372, "skein1024-144", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 152-bit digest.
    (SKEIN1024_152, 0xb373, "skein1024-152", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 160-bit digest.
    (SKEIN1024_160, 0xb374, "skein1024-160", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 168-bit digest.
    (SKEIN1024_168, 0xb375, "skein1024-168", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 176-bit digest.
    (SKEIN1024_176, 0xb376, "skein1024-176", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 184-bit digest.
    (SKEIN1024_184, 0xb377, "skein1024-184", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 192-bit digest.
    (SKEIN1024_192, 0xb378, "skein1024-192", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 200-bit digest.
    (SKEIN1024_200, 0xb379, "skein1024-200", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 208-bit digest.
    (SKEIN1024_208, 0xb37a, "skein1024-208", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 216-bit digest.
    (SKEIN1024_216, 0xb37b, "skein1024-216", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 224-bit digest.
    (SKEIN1024_224, 0xb37c, "skein1024-224", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 232-bit digest.
    (SKEIN1024_232, 0xb37d, "skein1024-232", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 240-bit digest.
    (SKEIN1024_240, 0xb37e, "skein1024-240", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 248-bit digest.
    (SKEIN1024_248, 0xb37f, "skein1024-248", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 256-bit digest.
    (SKEIN1024_256, 0xb380, "skein1024-256", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 264-bit digest.
    (SKEIN1024_264, 0xb381, "skein1024-264", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 272-bit digest.
    (SKEIN1024_272, 0xb382, "skein1024-272", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 280-bit digest.
    (SKEIN1024_280, 0xb383, "skein1024-280", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 288-bit digest.
    (SKEIN1024_288, 0xb384, "skein1024-288", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 296-bit digest.
    (SKEIN1024_296, 0xb385, "skein1024-296", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 304-bit digest.
    (SKEIN1024_304, 0xb386, "skein1024-304", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 312-bit digest.
    (SKEIN1024_312, 0xb387, "skein1024-312", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 320-bit digest.
    (SKEIN1024_320, 0xb388, "skein1024-320", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 328-bit digest.
    (SKEIN1024_328, 0xb389, "skein1024-328", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 336-bit digest.
    (SKEIN1024_336, 0xb38a, "skein1024-336", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 344-bit digest.
    (SKEIN1024_344, 0xb38b, "skein1024-344", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 352-bit digest.
    (SKEIN1024_352, 0xb38c, "skein1024-352", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 360-bit digest.
    (SKEIN1024_360, 0xb38d, "skein1024-360", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 368-bit digest.
    (SKEIN1024_368, 0xb38e, "skein1024-368", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 376-bit digest.
    (SKEIN1024_376, 0xb38f, "skein1024-376", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 384-bit digest.
    (SKEIN1024_384, 0xb390, "skein1024-384", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 392-bit digest.
    (SKEIN1024_392, 0xb391, "skein1024-392", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 400-bit digest.
    (SKEIN1024_400, 0xb392, "skein1024-400", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 408-bit digest.
    (SKEIN1024_408, 0xb393, "skein1024-408", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 416-bit digest.
    (SKEIN1024_416, 0xb394, "skein1024-416", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 424-bit digest.
    (SKEIN1024_424, 0xb395, "skein1024-424", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 432-bit digest.
    (SKEIN1024_432, 0xb396, "skein1024-432", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 440-bit digest.
    (SKEIN1024_440, 0xb397, "skein1024-440", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 448-bit digest.
    (SKEIN1024_448, 0xb398, "skein1024-448", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 456-bit digest.
    (SKEIN1024_456, 0xb399, "skein1024-456", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 464-bit digest.
    (SKEIN1024_464, 0xb39a, "skein1024-464", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 472-bit digest.
    (SKEIN1024_472, 0xb39b, "skein1024-472", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 480-bit digest.
    (SKEIN1024_480, 0xb39c, "skein1024-480", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 488-bit digest.
    (SKEIN1024_488, 0xb39d, "skein1024-488", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 496-bit digest.
    (SKEIN1024_496, 0xb39e, "skein1024-496", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 504-bit digest.
    (SKEIN1024_504, 0xb39f, "skein1024-504", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 512-bit digest.
    (SKEIN1024_512, 0xb3a0, "skein1024-512", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 520-bit digest.
    (SKEIN1024_520, 0xb3a1, "skein1024-520", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 528-bit digest.
    (SKEIN1024_528, 0xb3a2, "skein1024-528", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 536-bit digest.
    (SKEIN1024_536, 0xb3a3, "skein1024-536", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 544-bit digest.
    (SKEIN1024_544, 0xb3a4, "skein1024-544", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 552-bit digest.
    (SKEIN1024_552, 0xb3a5, "skein1024-552", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 560-bit digest.
    (SKEIN1024_560, 0xb3a6, "skein1024-560", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 568-bit digest.
    (SKEIN1024_568, 0xb3a7, "skein1024-568", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 576-bit digest.
    (SKEIN1024_576, 0xb3a8, "skein1024-576", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 584-bit digest.
    (SKEIN1024_584, 0xb3a9, "skein1024-584", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 592-bit digest.
    (SKEIN1024_592, 0xb3aa, "skein1024-592", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 600-bit digest.
    (SKEIN1024_600, 0xb3ab, "skein1024-600", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 608-bit digest.
    (SKEIN1024_608, 0xb3ac, "skein1024-608", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 616-bit digest.
    (SKEIN1024_616, 0xb3ad, "skein1024-616", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 624-bit digest.
    (SKEIN1024_624, 0xb3ae, "skein1024-624", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 632-bit digest.
    (SKEIN1024_632, 0xb3af, "skein1024-632", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 640-bit digest.
    (SKEIN1024_640, 0xb3b0, "skein1024-640", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 648-bit digest.
    (SKEIN1024_648, 0xb3b1, "skein1024-648", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 656-bit digest.
    (SKEIN1024_656, 0xb3b2, "skein1024-656", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 664-bit digest.
    (SKEIN1024_664, 0xb3b3, "skein1024-664", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 672-bit digest.
    (SKEIN1024_672, 0xb3b4, "skein1024-672", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 680-bit digest.
    (SKEIN1024_680, 0xb3b5, "skein1024-680", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 688-bit digest.
    (SKEIN1024_688, 0xb3b6, "skein1024-688", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 696-bit digest.
    (SKEIN1024_696, 0xb3b7, "skein1024-696", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 704-bit digest.
    (SKEIN1024_704, 0xb3b8, "skein1024-704", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 712-bit digest.
    (SKEIN1024_712, 0xb3b9, "skein1024-712", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 720-bit digest.
    (SKEIN1024_720, 0xb3ba, "skein1024-720", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 728-bit digest.
    (SKEIN1024_728, 0xb3bb, "skein1024-728", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 736-bit digest.
    (SKEIN1024_736, 0xb3bc, "skein1024-736", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 744-bit digest.
    (SKEIN1024_744, 0xb3bd, "skein1024-744", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 752-bit digest.
    (SKEIN1024_752, 0xb3be, "skein1024-752", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 760-bit digest.
    (SKEIN1024_760, 0xb3bf, "skein1024-760", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 768-bit digest.
    (SKEIN1024_768, 0xb3c0, "skein1024-768", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 776-bit digest.
    (SKEIN1024_776, 0xb3c1, "skein1024-776", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 784-bit digest.
    (SKEIN1024_784, 0xb3c2, "skein1024-784", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 792-bit digest.
    (SKEIN1024_792, 0xb3c3, "skein1024-792", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 800-bit digest.
    (SKEIN1024_800, 0xb3c4, "skein1024-800", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 808-bit digest.
    (SKEIN1024_808, 0xb3c5, "skein1024-808", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 816-bit digest.
    (SKEIN1024_816, 0xb3c6, "skein1024-816", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 824-bit digest.
    (SKEIN1024_824, 0xb3c7, "skein1024-824", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 832-bit digest.
    (SKEIN1024_832, 0xb3c8, "skein1024-832", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 840-bit digest.
    (SKEIN1024_840, 0xb3c9, "skein1024-840", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 848-bit digest.
    (SKEIN1024_848, 0xb3ca, "skein1024-848", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 856-bit digest.
    (SKEIN1024_856, 0xb3cb, "skein1024-856", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 864-bit digest.
    (SKEIN1024_864, 0xb3cc, "skein1024-864", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 872-bit digest.
    (SKEIN1024_872, 0xb3cd, "skein1024-872", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 880-bit digest.
    (SKEIN1024_880, 0xb3ce, "skein1024-880", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 888-bit digest.
    (SKEIN1024_888, 0xb3cf, "skein1024-888", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 896-bit digest.
    (SKEIN1024_896, 0xb3d0, "skein1024-896", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 904-bit digest.
    (SKEIN1024_904, 0xb3d1, "skein1024-904", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 912-bit digest.
    (SKEIN1024_912, 0xb3d2, "skein1024-912", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 920-bit digest.
    (SKEIN1024_920, 0xb3d3, "skein1024-920", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 928-bit digest.
    (SKEIN1024_928, 0xb3d4, "skein1024-928", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 936-bit digest.
    (SKEIN1024_936, 0xb3d5, "skein1024-936", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 944-bit digest.
    (SKEIN1024_944, 0xb3d6, "skein1024-944", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 952-bit digest.
    (SKEIN1024_952, 0xb3d7, "skein1024-952", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 960-bit digest.
    (SKEIN1024_960, 0xb3d8, "skein1024-960", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 968-bit digest.
    (SKEIN1024_968, 0xb3d9, "skein1024-968", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 976-bit digest.
    (SKEIN1024_976, 0xb3da, "skein1024-976", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 984-bit digest.
    (SKEIN1024_984, 0xb3db, "skein1024-984", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 992-bit digest.
    (SKEIN1024_992, 0xb3dc, "skein1024-992", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 1000-bit digest.
    (SKEIN1024_1000, 0xb3dd, "skein1024-1000", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 1008-bit digest.
    (SKEIN1024_1008, 0xb3de, "skein1024-1008", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 1016-bit digest.
    (SKEIN1024_1016, 0xb3df, "skein1024-1016", "multihash"),
    /// _multihash_, Skein hashing algorithm 1024-bit state, 1024-bit digest.
    (SKEIN1024_1024, 0xb3e0, "skein1024-1024", "multihash"),
    /// _multihash_
    (
        POSEIDON_BLS12_381_A2_FC1,
        0xb401,
        "poseidon-bls12_381-a2-fc1",
        "multihash"
    ),
    /// _multihash_
    (
        POSEIDON_BLS12_381_A2_FC1_SC,
        0xb402,
        "poseidon-bls12_381-a2-fc1-sc",
        "multihash"
    ),
    /// _multihash_
    (
        ZEROXCERT_IMPRINT_256,
        0xce11,
        "zeroxcert-imprint-256",
        "zeroxcert"
    ),
    /// _multihash_
    (
        FIL_COMMITMENT_UNSEALED,
        0xf101,
        "fil-commitment-unsealed",
        "filecoin"
    ),
    /// _multihash_
    (
        FIL_COMMITMENT_SEALED,
        0xf102,
        "fil-commitment-sealed",
        "filecoin"
    ),
    /// _holochain_
    (HOLOCHAIN_ADR_V0, 0x807124, "holochain-adr-v0", "holochain"),
    /// _holochain_
    (HOLOCHAIN_ADR_V1, 0x817124, "holochain-adr-v1", "holochain"),
    /// _holochain_
    (HOLOCHAIN_KEY_V0, 0x947124, "holochain-key-v0", "holochain"),
    /// _holochain_
    (HOLOCHAIN_KEY_V1, 0x957124, "holochain-key-v1", "holochain"),
    /// _holochain_
    (HOLOCHAIN_SIG_V0, 0xa27124, "holochain-sig-v0", "holochain"),
    /// _holochain_
    (HOLOCHAIN_SIG_V1, 0xa37124, "holochain-sig-v1", "holochain"),
];

/// Return a list of code-points tagged as "multihash".
pub fn multihash_codes() -> Vec<Codepoint> {
    TABLE_MULTIHASH.clone()
}

/// Return a list of code-points tagged as "multibase".
pub fn multibase_codes() -> Vec<Codepoint> {
    TABLE_MULTIBASE.clone()
}

#[cfg(test)]
#[path = "multicodec_test.rs"]
mod multicodec_test;
