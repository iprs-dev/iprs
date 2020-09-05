use lazy_static::lazy_static;

use std::{convert::TryFrom, fmt, io, result};

use crate::{Error, Result};

/// Multicodec carries a code that confirms to
/// [multicode][multicodec] and [unsigned_varint][unsigned-varint] specs.
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
    pub fn from_slice(buf: &[u8]) -> Result<(Multicodec, &[u8])> {
        let (code, rem) = err_at!(Invalid, unsigned_varint::decode::u128(buf))?;
        Ok((Multicodec { code }, rem))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut buf);
        Ok(slice.to_vec())
    }

    pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize>
    where
        W: io::Write,
    {
        let mut scratch: [u8; 19] = Default::default();
        let slice = unsigned_varint::encode::u128(self.code, &mut scratch);
        err_at!(IOError, buf.write(&slice))?;
        Ok(slice.len())
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

lazy_static! {
    /// Default codec table.
    ///
    /// Refer [multicodec][multicodec] for details.
    ///
    /// multicodec: https://github.com/multiformats/multicodec
    pub static ref TABLE: [Codepoint; 455] = [
        Codepoint {
            code: 0x00,
            name: "identity".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x01,
            name: "cidv1".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x02,
            name: "cidv2".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x03,
            name: "cidv3".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x04,
            name: "ip4".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x06,
            name: "tcp".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x11,
            name: "sha1".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x12,
            name: "sha2-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x13,
            name: "sha2-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x14,
            name: "sha3-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x15,
            name: "sha3-384".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x16,
            name: "sha3-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x17,
            name: "sha3-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x18,
            name: "shake-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x19,
            name: "shake-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1a,
            name: "keccak-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1b,
            name: "keccak-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1c,
            name: "keccak-384".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1d,
            name: "keccak-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1e,
            name: "blake3".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x21,
            name: "dccp".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x22,
            name: "murmur3-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x23,
            name: "murmur3-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x29,
            name: "ip6".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x2a,
            name: "ip6zone".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x2f,
            name: "path".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0x30,
            name: "multicodec".to_string(),
            tag: "multiformat".to_string(),
        },
        Codepoint {
            code: 0x31,
            name: "multihash".to_string(),
            tag: "multiformat".to_string(),
        },
        Codepoint {
            code: 0x32,
            name: "multiaddr".to_string(),
            tag: "multiformat".to_string(),
        },
        Codepoint {
            code: 0x33,
            name: "multibase".to_string(),
            tag: "multiformat".to_string(),
        },
        Codepoint {
            code: 0x35,
            name: "dns".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x36,
            name: "dns4".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x37,
            name: "dns6".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x38,
            name: "dnsaddr".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x50,
            name: "protobuf".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x51,
            name: "cbor".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x55,
            name: "raw".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x56,
            name: "dbl-sha2-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x60,
            name: "rlp".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x63,
            name: "bencode".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x70,
            name: "dag-pb".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x71,
            name: "dag-cbor".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x72,
            name: "libp2p-key".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x78,
            name: "git-raw".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x7b,
            name: "torrent-info".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x7c,
            name: "torrent-file".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x81,
            name: "leofcoin-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x82,
            name: "leofcoin-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x83,
            name: "leofcoin-pr".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x84,
            name: "sctp".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x85,
            name: "dag-jose".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x86,
            name: "dag-cose".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x90,
            name: "eth-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x91,
            name: "eth-block-list".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x92,
            name: "eth-tx-trie".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x93,
            name: "eth-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x94,
            name: "eth-tx-receipt-trie".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x95,
            name: "eth-tx-receipt".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x96,
            name: "eth-state-trie".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x97,
            name: "eth-account-snapshot".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x98,
            name: "eth-storage-trie".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xb0,
            name: "bitcoin-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xb1,
            name: "bitcoin-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xb2,
            name: "bitcoin-witness-commitment".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xc0,
            name: "zcash-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xc1,
            name: "zcash-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xd0,
            name: "stellar-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xd1,
            name: "stellar-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xd4,
            name: "md4".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xd5,
            name: "md5".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xd6,
            name: "bmt".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xe0,
            name: "decred-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xe1,
            name: "decred-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xe2,
            name: "ipld-ns".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0xe3,
            name: "ipfs-ns".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0xe4,
            name: "swarm-ns".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0xe5,
            name: "ipns-ns".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0xe6,
            name: "zeronet".to_string(),
            tag: "namespace".to_string(),
        },
        Codepoint {
            code: 0xe7,
            name: "secp256k1-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0xea,
            name: "bls12_381-g1-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0xeb,
            name: "bls12_381-g2-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0xec,
            name: "x25519-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0xed,
            name: "ed25519-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0xf0,
            name: "dash-block".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xf1,
            name: "dash-tx".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xfa,
            name: "swarm-manifest".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0xfb,
            name: "swarm-feed".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x0111,
            name: "udp".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0113,
            name: "p2p-webrtc-star".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0114,
            name: "p2p-webrtc-direct".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0115,
            name: "p2p-stardust".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0122,
            name: "p2p-circuit".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0129,
            name: "dag-json".to_string(),
            tag: "ipld".to_string(),
        },
        Codepoint {
            code: 0x012d,
            name: "udt".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x012e,
            name: "utp".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0190,
            name: "unix".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01a5,
            name: "p2p".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01bb,
            name: "https".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01bc,
            name: "onion".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01bd,
            name: "onion3".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01be,
            name: "garlic64".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01bf,
            name: "garlic32".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01c0,
            name: "tls".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01cc,
            name: "quic".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01dd,
            name: "ws".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01de,
            name: "wss".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01df,
            name: "p2p-websocket-star".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x01e0,
            name: "http".to_string(),
            tag: "multiaddr".to_string(),
        },
        Codepoint {
            code: 0x0200,
            name: "json".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x0201,
            name: "messagepack".to_string(),
            tag: "serialization".to_string(),
        },
        Codepoint {
            code: 0x0301,
            name: "libp2p-peer-record".to_string(),
            tag: "libp2p".to_string(),
        },
        Codepoint {
            code: 0x1012,
            name: "sha2-256-trunc254-padded".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1052,
            name: "ripemd-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1053,
            name: "ripemd-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1054,
            name: "ripemd-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1055,
            name: "ripemd-320".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1100,
            name: "x11".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x1200,
            name: "p256-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0x1201,
            name: "p384-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0x1202,
            name: "p521-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0x1203,
            name: "ed448-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0x1204,
            name: "x448-pub".to_string(),
            tag: "key".to_string(),
        },
        Codepoint {
            code: 0x1d01,
            name: "kangarootwelve".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0x534d,
            name: "sm3-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb201,
            name: "blake2b-8".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb202,
            name: "blake2b-16".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb203,
            name: "blake2b-24".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb204,
            name: "blake2b-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb205,
            name: "blake2b-40".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb206,
            name: "blake2b-48".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb207,
            name: "blake2b-56".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb208,
            name: "blake2b-64".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb209,
            name: "blake2b-72".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20a,
            name: "blake2b-80".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20b,
            name: "blake2b-88".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20c,
            name: "blake2b-96".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20d,
            name: "blake2b-104".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20e,
            name: "blake2b-112".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb20f,
            name: "blake2b-120".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb210,
            name: "blake2b-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb211,
            name: "blake2b-136".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb212,
            name: "blake2b-144".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb213,
            name: "blake2b-152".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb214,
            name: "blake2b-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb215,
            name: "blake2b-168".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb216,
            name: "blake2b-176".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb217,
            name: "blake2b-184".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb218,
            name: "blake2b-192".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb219,
            name: "blake2b-200".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21a,
            name: "blake2b-208".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21b,
            name: "blake2b-216".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21c,
            name: "blake2b-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21d,
            name: "blake2b-232".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21e,
            name: "blake2b-240".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb21f,
            name: "blake2b-248".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb220,
            name: "blake2b-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb221,
            name: "blake2b-264".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb222,
            name: "blake2b-272".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb223,
            name: "blake2b-280".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb224,
            name: "blake2b-288".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb225,
            name: "blake2b-296".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb226,
            name: "blake2b-304".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb227,
            name: "blake2b-312".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb228,
            name: "blake2b-320".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb229,
            name: "blake2b-328".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22a,
            name: "blake2b-336".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22b,
            name: "blake2b-344".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22c,
            name: "blake2b-352".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22d,
            name: "blake2b-360".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22e,
            name: "blake2b-368".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb22f,
            name: "blake2b-376".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb230,
            name: "blake2b-384".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb231,
            name: "blake2b-392".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb232,
            name: "blake2b-400".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb233,
            name: "blake2b-408".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb234,
            name: "blake2b-416".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb235,
            name: "blake2b-424".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb236,
            name: "blake2b-432".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb237,
            name: "blake2b-440".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb238,
            name: "blake2b-448".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb239,
            name: "blake2b-456".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23a,
            name: "blake2b-464".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23b,
            name: "blake2b-472".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23c,
            name: "blake2b-480".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23d,
            name: "blake2b-488".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23e,
            name: "blake2b-496".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb23f,
            name: "blake2b-504".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb240,
            name: "blake2b-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb241,
            name: "blake2s-8".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb242,
            name: "blake2s-16".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb243,
            name: "blake2s-24".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb244,
            name: "blake2s-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb245,
            name: "blake2s-40".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb246,
            name: "blake2s-48".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb247,
            name: "blake2s-56".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb248,
            name: "blake2s-64".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb249,
            name: "blake2s-72".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24a,
            name: "blake2s-80".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24b,
            name: "blake2s-88".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24c,
            name: "blake2s-96".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24d,
            name: "blake2s-104".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24e,
            name: "blake2s-112".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb24f,
            name: "blake2s-120".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb250,
            name: "blake2s-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb251,
            name: "blake2s-136".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb252,
            name: "blake2s-144".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb253,
            name: "blake2s-152".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb254,
            name: "blake2s-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb255,
            name: "blake2s-168".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb256,
            name: "blake2s-176".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb257,
            name: "blake2s-184".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb258,
            name: "blake2s-192".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb259,
            name: "blake2s-200".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25a,
            name: "blake2s-208".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25b,
            name: "blake2s-216".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25c,
            name: "blake2s-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25d,
            name: "blake2s-232".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25e,
            name: "blake2s-240".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb25f,
            name: "blake2s-248".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb260,
            name: "blake2s-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb301,
            name: "skein256-8".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb302,
            name: "skein256-16".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb303,
            name: "skein256-24".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb304,
            name: "skein256-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb305,
            name: "skein256-40".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb306,
            name: "skein256-48".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb307,
            name: "skein256-56".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb308,
            name: "skein256-64".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb309,
            name: "skein256-72".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30a,
            name: "skein256-80".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30b,
            name: "skein256-88".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30c,
            name: "skein256-96".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30d,
            name: "skein256-104".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30e,
            name: "skein256-112".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb30f,
            name: "skein256-120".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb310,
            name: "skein256-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb311,
            name: "skein256-136".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb312,
            name: "skein256-144".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb313,
            name: "skein256-152".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb314,
            name: "skein256-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb315,
            name: "skein256-168".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb316,
            name: "skein256-176".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb317,
            name: "skein256-184".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb318,
            name: "skein256-192".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb319,
            name: "skein256-200".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31a,
            name: "skein256-208".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31b,
            name: "skein256-216".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31c,
            name: "skein256-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31d,
            name: "skein256-232".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31e,
            name: "skein256-240".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb31f,
            name: "skein256-248".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb320,
            name: "skein256-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb321,
            name: "skein512-8".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb322,
            name: "skein512-16".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb323,
            name: "skein512-24".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb324,
            name: "skein512-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb325,
            name: "skein512-40".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb326,
            name: "skein512-48".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb327,
            name: "skein512-56".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb328,
            name: "skein512-64".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb329,
            name: "skein512-72".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32a,
            name: "skein512-80".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32b,
            name: "skein512-88".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32c,
            name: "skein512-96".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32d,
            name: "skein512-104".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32e,
            name: "skein512-112".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb32f,
            name: "skein512-120".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb330,
            name: "skein512-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb331,
            name: "skein512-136".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb332,
            name: "skein512-144".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb333,
            name: "skein512-152".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb334,
            name: "skein512-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb335,
            name: "skein512-168".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb336,
            name: "skein512-176".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb337,
            name: "skein512-184".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb338,
            name: "skein512-192".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb339,
            name: "skein512-200".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33a,
            name: "skein512-208".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33b,
            name: "skein512-216".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33c,
            name: "skein512-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33d,
            name: "skein512-232".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33e,
            name: "skein512-240".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb33f,
            name: "skein512-248".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb340,
            name: "skein512-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb341,
            name: "skein512-264".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb342,
            name: "skein512-272".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb343,
            name: "skein512-280".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb344,
            name: "skein512-288".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb345,
            name: "skein512-296".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb346,
            name: "skein512-304".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb347,
            name: "skein512-312".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb348,
            name: "skein512-320".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb349,
            name: "skein512-328".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34a,
            name: "skein512-336".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34b,
            name: "skein512-344".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34c,
            name: "skein512-352".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34d,
            name: "skein512-360".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34e,
            name: "skein512-368".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb34f,
            name: "skein512-376".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb350,
            name: "skein512-384".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb351,
            name: "skein512-392".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb352,
            name: "skein512-400".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb353,
            name: "skein512-408".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb354,
            name: "skein512-416".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb355,
            name: "skein512-424".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb356,
            name: "skein512-432".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb357,
            name: "skein512-440".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb358,
            name: "skein512-448".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb359,
            name: "skein512-456".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35a,
            name: "skein512-464".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35b,
            name: "skein512-472".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35c,
            name: "skein512-480".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35d,
            name: "skein512-488".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35e,
            name: "skein512-496".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb35f,
            name: "skein512-504".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb360,
            name: "skein512-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb361,
            name: "skein1024-8".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb362,
            name: "skein1024-16".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb363,
            name: "skein1024-24".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb364,
            name: "skein1024-32".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb365,
            name: "skein1024-40".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb366,
            name: "skein1024-48".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb367,
            name: "skein1024-56".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb368,
            name: "skein1024-64".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb369,
            name: "skein1024-72".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36a,
            name: "skein1024-80".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36b,
            name: "skein1024-88".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36c,
            name: "skein1024-96".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36d,
            name: "skein1024-104".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36e,
            name: "skein1024-112".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb36f,
            name: "skein1024-120".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb370,
            name: "skein1024-128".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb371,
            name: "skein1024-136".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb372,
            name: "skein1024-144".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb373,
            name: "skein1024-152".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb374,
            name: "skein1024-160".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb375,
            name: "skein1024-168".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb376,
            name: "skein1024-176".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb377,
            name: "skein1024-184".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb378,
            name: "skein1024-192".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb379,
            name: "skein1024-200".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37a,
            name: "skein1024-208".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37b,
            name: "skein1024-216".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37c,
            name: "skein1024-224".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37d,
            name: "skein1024-232".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37e,
            name: "skein1024-240".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb37f,
            name: "skein1024-248".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb380,
            name: "skein1024-256".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb381,
            name: "skein1024-264".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb382,
            name: "skein1024-272".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb383,
            name: "skein1024-280".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb384,
            name: "skein1024-288".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb385,
            name: "skein1024-296".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb386,
            name: "skein1024-304".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb387,
            name: "skein1024-312".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb388,
            name: "skein1024-320".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb389,
            name: "skein1024-328".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38a,
            name: "skein1024-336".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38b,
            name: "skein1024-344".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38c,
            name: "skein1024-352".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38d,
            name: "skein1024-360".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38e,
            name: "skein1024-368".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb38f,
            name: "skein1024-376".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb390,
            name: "skein1024-384".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb391,
            name: "skein1024-392".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb392,
            name: "skein1024-400".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb393,
            name: "skein1024-408".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb394,
            name: "skein1024-416".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb395,
            name: "skein1024-424".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb396,
            name: "skein1024-432".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb397,
            name: "skein1024-440".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb398,
            name: "skein1024-448".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb399,
            name: "skein1024-456".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39a,
            name: "skein1024-464".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39b,
            name: "skein1024-472".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39c,
            name: "skein1024-480".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39d,
            name: "skein1024-488".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39e,
            name: "skein1024-496".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb39f,
            name: "skein1024-504".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a0,
            name: "skein1024-512".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a1,
            name: "skein1024-520".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a2,
            name: "skein1024-528".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a3,
            name: "skein1024-536".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a4,
            name: "skein1024-544".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a5,
            name: "skein1024-552".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a6,
            name: "skein1024-560".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a7,
            name: "skein1024-568".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a8,
            name: "skein1024-576".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3a9,
            name: "skein1024-584".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3aa,
            name: "skein1024-592".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ab,
            name: "skein1024-600".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ac,
            name: "skein1024-608".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ad,
            name: "skein1024-616".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ae,
            name: "skein1024-624".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3af,
            name: "skein1024-632".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b0,
            name: "skein1024-640".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b1,
            name: "skein1024-648".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b2,
            name: "skein1024-656".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b3,
            name: "skein1024-664".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b4,
            name: "skein1024-672".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b5,
            name: "skein1024-680".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b6,
            name: "skein1024-688".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b7,
            name: "skein1024-696".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b8,
            name: "skein1024-704".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3b9,
            name: "skein1024-712".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ba,
            name: "skein1024-720".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3bb,
            name: "skein1024-728".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3bc,
            name: "skein1024-736".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3bd,
            name: "skein1024-744".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3be,
            name: "skein1024-752".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3bf,
            name: "skein1024-760".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c0,
            name: "skein1024-768".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c1,
            name: "skein1024-776".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c2,
            name: "skein1024-784".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c3,
            name: "skein1024-792".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c4,
            name: "skein1024-800".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c5,
            name: "skein1024-808".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c6,
            name: "skein1024-816".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c7,
            name: "skein1024-824".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c8,
            name: "skein1024-832".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3c9,
            name: "skein1024-840".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ca,
            name: "skein1024-848".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3cb,
            name: "skein1024-856".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3cc,
            name: "skein1024-864".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3cd,
            name: "skein1024-872".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3ce,
            name: "skein1024-880".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3cf,
            name: "skein1024-888".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d0,
            name: "skein1024-896".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d1,
            name: "skein1024-904".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d2,
            name: "skein1024-912".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d3,
            name: "skein1024-920".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d4,
            name: "skein1024-928".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d5,
            name: "skein1024-936".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d6,
            name: "skein1024-944".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d7,
            name: "skein1024-952".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d8,
            name: "skein1024-960".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3d9,
            name: "skein1024-968".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3da,
            name: "skein1024-976".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3db,
            name: "skein1024-984".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3dc,
            name: "skein1024-992".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3dd,
            name: "skein1024-1000".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3de,
            name: "skein1024-1008".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3df,
            name: "skein1024-1016".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb3e0,
            name: "skein1024-1024".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb401,
            name: "poseidon-bls12_381-a2-fc1".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xb402,
            name: "poseidon-bls12_381-a2-fc1-sc".to_string(),
            tag: "multihash".to_string(),
        },
        Codepoint {
            code: 0xce11,
            name: "zeroxcert-imprint-256".to_string(),
            tag: "zeroxcert".to_string(),
        },
        Codepoint {
            code: 0xf101,
            name: "fil-commitment-unsealed".to_string(),
            tag: "filecoin".to_string(),
        },
        Codepoint {
            code: 0xf102,
            name: "fil-commitment-sealed".to_string(),
            tag: "filecoin".to_string(),
        },
        Codepoint {
            code: 0x807124,
            name: "holochain-adr-v0".to_string(),
            tag: "holochain".to_string(),
        },
        Codepoint {
            code: 0x817124,
            name: "holochain-adr-v1".to_string(),
            tag: "holochain".to_string(),
        },
        Codepoint {
            code: 0x947124,
            name: "holochain-key-v0".to_string(),
            tag: "holochain".to_string(),
        },
        Codepoint {
            code: 0x957124,
            name: "holochain-key-v1".to_string(),
            tag: "holochain".to_string(),
        },
        Codepoint {
            code: 0xa27124,
            name: "holochain-sig-v0".to_string(),
            tag: "holochain".to_string(),
        },
        Codepoint {
            code: 0xa37124,
            name: "holochain-sig-v1".to_string(),
            tag: "holochain".to_string(),
        },
    ];
}

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
