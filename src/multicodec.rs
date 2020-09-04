use std::{convert::TryFrom, io};

use crate::{Error, Result};

macro_rules! codec {
    ($(
        #[$doc:meta]
        ($label:ident, $name:expr, $dval:expr, $tag:expr),
    )*) => {
        /// Enumerated values for default codec table.
        ///
        /// Refer [multicodec][multicodec] for details.
        ///
        /// multicodec: https://github.com/multiformats/multicodec
        #[derive(Clone)]
        pub enum Multicodec {
            $(
                #[$doc]
                $label = $dval,
            )*
        }

        impl TryFrom<u64> for Multicodec {
            type Error = Error;

            fn try_from(val: u64) -> Result<Self> {
                match val {
                    $($dval => Ok(Multicodec::$label),)*
                    _ => err_at!(Invalid, msg: format!("invalid code")),
                }
            }
        }

        impl Multicodec {
            pub fn from_slice(buf: &[u8]) -> Result<(Multicodec, &[u8])> {
                let (code, rem) = err_at!(Invalid, unsigned_varint::decode::u64(buf))?;
                Ok((TryFrom::try_from(code)?, rem))
            }

            pub fn encode(&self) -> Result<Vec<u8>> {
                let val = self.clone();

                let mut buf: [u8; 10] = Default::default();
                let slice = unsigned_varint::encode::u64(val as u32 as u64, &mut buf);
                Ok(slice.to_vec())
            }

            pub fn encode_with<W>(&self, buf: &mut W) -> Result<usize> where W: io::Write {
                let val = self.clone();

                let mut scratch: [u8; 10] = Default::default();
                let slice = unsigned_varint::encode::u64(val as u32 as u64, &mut scratch);
                err_at!(IOError, buf.write(&slice))?;
                Ok(slice.len())
            }
        }

        #[cfg(test)]
        fn details() -> Vec<Vec<String>> {
            vec![
                $(vec![$name.to_string(), format!("0x{:x}", $dval), $tag.to_string()],)*
            ]
        }
    };
}

codec![
    /// Raw binary
    (Identity, "identity", 0x00, "multihash"),
    /// CID version-1
    (Cidv1, "cidv1", 0x01, "ipld"),
    /// CID version-2
    (Cidv2, "cidv2", 0x02, "ipld"),
    /// CID version-3
    (Cidv3, "cidv3", 0x03, "ipld"),
    ///
    (Ip4, "ip4", 0x04, "multiaddr"),
    ///
    (Tcp, "tcp", 0x06, "multiaddr"),
    ///
    (Sha1, "sha1", 0x11, "multihash"),
    ///
    (Sha2_256, "sha2-256", 0x12, "multihash"),
    ///
    (Sha2_512, "sha2-512", 0x13, "multihash"),
    ///
    (Sha3_512, "sha3-512", 0x14, "multihash"),
    ///
    (Sha3_384, "sha3-384", 0x15, "multihash"),
    ///
    (Sha3_256, "sha3-256", 0x16, "multihash"),
    ///
    (Sha3_224, "sha3-224", 0x17, "multihash"),
    ///
    (Shake128, "shake-128", 0x18, "multihash"),
    ///
    (Shake256, "shake-256", 0x19, "multihash"),
    /// keccak has variable output length. The number specifies the core length
    (Keccak224, "keccak-224", 0x1a, "multihash"),
    ///
    (Keccak256, "keccak-256", 0x1b, "multihash"),
    ///
    (Keccak384, "keccak-384", 0x1c, "multihash"),
    ///
    (Keccak512, "keccak-512", 0x1d, "multihash"),
    /// BLAKE3 has a default 32 byte output length. The maximum length is (2^64)-1 "2^"64)-1 bytes
    (Blake3, "blake3", 0x1e, "multihash"),
    ///
    (Dccp, "dccp", 0x21, "multiaddr"),
    ///
    (Murmur3_128, "murmur3-128", 0x22, "multihash"),
    ///
    (Murmur3_32, "murmur3-32", 0x23, "multihash"),
    ///
    (Ip6, "ip6", 0x29, "multiaddr"),
    ///
    (Ip6zone, "ip6zone", 0x2a, "multiaddr"),
    /// Namespace for string paths. Corresponds to `/` in ASCII
    (Path, "path", 0x2f, "namespace"),
    ///
    (Multicodec, "multicodec", 0x30, "multiformat"),
    ///
    (Multihash, "multihash", 0x31, "multiformat"),
    ///
    (Multiaddr, "multiaddr", 0x32, "multiformat"),
    ///
    (Multibase, "multibase", 0x33, "multiformat"),
    ///
    (Dns, "dns", 0x35, "multiaddr"),
    ///
    (Dns4, "dns4", 0x36, "multiaddr"),
    ///
    (Dns6, "dns6", 0x37, "multiaddr"),
    ///
    (Dnsaddr, "dnsaddr", 0x38, "multiaddr"),
    /// Protocol Buffers
    (Protobuf, "protobuf", 0x50, "serialization"),
    /// CBOR
    (Cbor, "cbor", 0x51, "serialization"),
    /// Raw binary
    (Raw, "raw", 0x55, "ipld"),
    ///
    (DblSha2_256, "dbl-sha2-256", 0x56, "multihash"),
    /// recursive length prefix
    (Rlp, "rlp", 0x60, "serialization"),
    /// bencode
    (Bencode, "bencode", 0x63, "serialization"),
    /// MerkleDAG protobuf
    (DagPb, "dag-pb", 0x70, "ipld"),
    /// MerkleDAG cbor
    (DagCbor, "dag-cbor", 0x71, "ipld"),
    /// Libp2p Public Key"
    (Libp2pKey, "libp2p-key", 0x72, "ipld"),
    /// Raw Git object"
    (GitRaw, "git-raw", 0x78, "ipld"),
    /// Torrent file info field (bencoded)
    (TorrentInfo, "torrent-info", 0x7b, "ipld"),
    /// Torrent file (bencoded)
    (TorrentFile, "torrent-file", 0x7c, "ipld"),
    /// Leofcoin Block,
    (LeofcoinBlock, "leofcoin-block", 0x81, "ipld"),
    /// Leofcoin Transaction
    (LeofcoinTx, "leofcoin-tx", 0x82, "ipld"),
    /// Leofcoin Peer Reputation
    (LeofcoinPr, "leofcoin-pr", 0x83, "ipld"),
    ///
    (Sctp, "sctp", 0x84, "multiaddr"),
    /// MerkleDAG JOSE
    (DagJose, "dag-jose", 0x85, "ipld"),
    /// MerkleDAG COSE
    (DagCose, "dag-cose", 0x86, "ipld"),
    /// Ethereum Block (RLP)
    (EthBlock, "eth-block", 0x90, "ipld"),
    /// Ethereum Block List (RLP)
    (EthBlockList, "eth-block-list", 0x91, "ipld"),
    /// Ethereum Transaction Trie (Ethtrie)
    (EthTxTrie, "eth-tx-trie", 0x92, "ipld"),
    /// Ethereum Transaction (RLP)
    (EthTx, "eth-tx", 0x93, "ipld"),
    /// Ethereum Transaction Receipt Trie (Eth-Trie)
    (EthTxReceiptTrie, "eth-tx-receipt-trie", 0x94, "ipld"),
    /// Ethereum Transaction Receipt (RLP)
    (EthTxReceipt, "eth-tx-receipt", 0x95, "ipld"),
    /// Ethereum State Trie (Eth-Secure-Trie)
    (EthStateTrie, "eth-state-trie", 0x96, "ipld"),
    /// Ethereum Account Snapshot (RLP)
    (EthAccountSnapshot, "eth-account-snapshot", 0x97, "ipld"),
    /// Ethereum Contract Storage Trie (Eth-Secure-Trie)
    (EthStorageTrie, "eth-storage-trie", 0x98, "ipld"),
    /// Bitcoin Block
    (BitcoinBlock, "bitcoin-block", 0xb0, "ipld"),
    /// Bitcoin Tx
    (BitcoinTx, "bitcoin-tx", 0xb1, "ipld"),
    /// Bitcoin Witness Commitment
    (
        BitcoinWitnessCommitment,
        "bitcoin-witness-commitment",
        0xb2,
        "ipld"
    ),
    /// Zcash Block
    (ZcashBlock, "zcash-block", 0xc0, "ipld"),
    /// Zcash Tx
    (ZcashTx, "zcash-tx", 0xc1, "ipld"),
    /// Stellar Block
    (StellarBlock, "stellar-block", 0xd0, "ipld"),
    /// Stellar Tx
    (StellarTx, "stellar-tx", 0xd1, "ipld"),
    ///
    (Md4, "md4", 0xd4, "multihash"),
    ///
    (Md5, "md5", 0xd5, "multihash"),
    /// Binary Merkle Tree Hash
    (Bmt, "bmt", 0xd6, "multihash"),
    /// Decred Block
    (DecredBlock, "decred-block", 0xe0, "ipld"),
    /// Decred Tx
    (DecredTx, "decred-tx", 0xe1, "ipld"),
    /// IPLD path
    (IpldNs, "ipld-ns", 0xe2, "namespace"),
    /// IPFS path
    (IpfsNs, "ipfs-ns", 0xe3, "namespace"),
    /// Swarm path
    (SwarmNs, "swarm-ns", 0xe4, "namespace"),
    /// IPNS path
    (IpnsNs, "ipns-ns", 0xe5, "namespace"),
    /// ZeroNet site address
    (Zeronet, "zeronet", 0xe6, "namespace"),
    /// Secp256k1 public key
    (Secp256k1Pub, "secp256k1-pub", 0xe7, "key"),
    /// BLS12-381 public key in the G1 field
    (Bls12_381G1Pub, "bls12_381-g1-pub", 0xea, "key"),
    /// BLS12-381 public key in the G2 field
    (Bls12_381G2Pub, "bls12_381-g2-pub", 0xeb, "key"),
    /// Curve25519 public key
    (X25519Pub, "x25519-pub", 0xec, "key"),
    /// Ed25519 public key
    (Ed25519Pub, "ed25519-pub", 0xed, "key"),
    /// Dash Block
    (DashBlock, "dash-block", 0xf0, "ipld"),
    /// Dash Tx
    (DashTx, "dash-tx", 0xf1, "ipld"),
    /// Swarm Manifest
    (SwarmManifest, "swarm-manifest", 0xfa, "ipld"),
    /// Swarm Feed
    (SwarmFeed, "swarm-feed", 0xfb, "ipld"),
    ///
    (Udp, "udp", 0x0111, "multiaddr"),
    ///
    (P2pWebrtcStar, "p2p-webrtc-star", 0x0113, "multiaddr"),
    ///
    (P2pWebrtcDirect, "p2p-webrtc-direct", 0x0114, "multiaddr"),
    ///
    (P2pStardust, "p2p-stardust", 0x0115, "multiaddr"),
    ///
    (P2pCircuit, "p2p-circuit", 0x0122, "multiaddr"),
    /// "MerkleDAG json"
    (DagJson, "dag-json", 0x0129, "ipld"),
    ///
    (Udt, "udt", 0x012d, "multiaddr"),
    ///
    (Utp, "utp", 0x012e, "multiaddr"),
    ///
    (Unix, "unix", 0x0190, "multiaddr"),
    /// libp2p
    (P2p, "p2p", 0x01a5, "multiaddr"),
    ///
    (Https, "https", 0x01bb, "multiaddr"),
    ///
    (Onion, "onion", 0x01bc, "multiaddr"),
    ///
    (Onion3, "onion3", 0x01bd, "multiaddr"),
    /// I2P base64 (raw "raw" public key)
    (Garlic64, "garlic64", 0x01be, "multiaddr"),
    /// I2P base32, hashed public key or encoded public key/checksum+optional secret
    (Garlic32, "garlic32", 0x01bf, "multiaddr"),
    ///
    (Tls, "tls", 0x01c0, "multiaddr"),
    ///
    (Quic, "quic", 0x01cc, "multiaddr"),
    ///
    (Ws, "ws", 0x01dd, "multiaddr"),
    ///
    (Wss, "wss", 0x01de, "multiaddr"),
    ///
    (P2pWebsocketStar, "p2p-websocket-star", 0x01df, "multiaddr"),
    ///
    (Http, "http", 0x01e0, "multiaddr"),
    /// JSON (UTF-8-encoded)
    (Json, "json", 0x0200, "serialization"),
    /// MessagePack
    (Messagepack, "messagepack", 0x0201, "serialization"),
    /// libp2p peer record type
    (Libp2pPeerRecord, "libp2p-peer-record", 0x0301, "libp2p"),
    /// SHA2-256 with the two most significant bits from the last byte zeroed (as "as" via a mask with 0b00111111) - used for proving trees as in Filecoin
    (
        Sha2_256Trunc254Padded,
        "sha2-256-trunc254-padded",
        0x1012,
        "multihash"
    ),
    ///
    (Ripemd128, "ripemd-128", 0x1052, "multihash"),
    ///
    (Ripemd160, "ripemd-160", 0x1053, "multihash"),
    ///
    (Ripemd256, "ripemd-256", 0x1054, "multihash"),
    ///
    (Ripemd320, "ripemd-320", 0x1055, "multihash"),
    ///
    (X11, "x11", 0x1100, "multihash"),
    /// P-256 public Key
    (P256Pub, "p256-pub", 0x1200, "key"),
    /// P-384 public Key
    (P384Pub, "p384-pub", 0x1201, "key"),
    /// P-521 public Key
    (P521Pub, "p521-pub", 0x1202, "key"),
    /// Ed448 public Key
    (Ed448Pub, "ed448-pub", 0x1203, "key"),
    /// X448 public Key
    (X448Pub, "x448-pub", 0x1204, "key"),
    /// KangarooTwelve is an extendable-output hash function based on Keccak-p
    (Kangarootwelve, "kangarootwelve", 0x1d01, "multihash"),
    ///
    (Sm3_256, "sm3-256", 0x534d, "multihash"),
    /// Blake2b consists of 64 output lengths that give different hashes
    (Blake2b8, "blake2b-8", 0xb201, "multihash"),
    ///
    (Blake2b16, "blake2b-16", 0xb202, "multihash"),
    ///
    (Blake2b24, "blake2b-24", 0xb203, "multihash"),
    ///
    (Blake2b32, "blake2b-32", 0xb204, "multihash"),
    ///
    (Blake2b40, "blake2b-40", 0xb205, "multihash"),
    ///
    (Blake2b48, "blake2b-48", 0xb206, "multihash"),
    ///
    (Blake2b56, "blake2b-56", 0xb207, "multihash"),
    ///
    (Blake2b64, "blake2b-64", 0xb208, "multihash"),
    ///
    (Blake2b72, "blake2b-72", 0xb209, "multihash"),
    ///
    (Blake2b80, "blake2b-80", 0xb20a, "multihash"),
    ///
    (Blake2b88, "blake2b-88", 0xb20b, "multihash"),
    ///
    (Blake2b96, "blake2b-96", 0xb20c, "multihash"),
    ///
    (Blake2b104, "blake2b-104", 0xb20d, "multihash"),
    ///
    (Blake2b112, "blake2b-112", 0xb20e, "multihash"),
    ///
    (Blake2b120, "blake2b-120", 0xb20f, "multihash"),
    ///
    (Blake2b128, "blake2b-128", 0xb210, "multihash"),
    ///
    (Blake2b136, "blake2b-136", 0xb211, "multihash"),
    ///
    (Blake2b144, "blake2b-144", 0xb212, "multihash"),
    ///
    (Blake2b152, "blake2b-152", 0xb213, "multihash"),
    ///
    (Blake2b160, "blake2b-160", 0xb214, "multihash"),
    ///
    (Blake2b168, "blake2b-168", 0xb215, "multihash"),
    ///
    (Blake2b176, "blake2b-176", 0xb216, "multihash"),
    ///
    (Blake2b184, "blake2b-184", 0xb217, "multihash"),
    ///
    (Blake2b192, "blake2b-192", 0xb218, "multihash"),
    ///
    (Blake2b200, "blake2b-200", 0xb219, "multihash"),
    ///
    (Blake2b208, "blake2b-208", 0xb21a, "multihash"),
    ///
    (Blake2b216, "blake2b-216", 0xb21b, "multihash"),
    ///
    (Blake2b224, "blake2b-224", 0xb21c, "multihash"),
    ///
    (Blake2b232, "blake2b-232", 0xb21d, "multihash"),
    ///
    (Blake2b240, "blake2b-240", 0xb21e, "multihash"),
    ///
    (Blake2b248, "blake2b-248", 0xb21f, "multihash"),
    ///
    (Blake2b256, "blake2b-256", 0xb220, "multihash"),
    ///
    (Blake2b264, "blake2b-264", 0xb221, "multihash"),
    ///
    (Blake2b272, "blake2b-272", 0xb222, "multihash"),
    ///
    (Blake2b280, "blake2b-280", 0xb223, "multihash"),
    ///
    (Blake2b288, "blake2b-288", 0xb224, "multihash"),
    ///
    (Blake2b296, "blake2b-296", 0xb225, "multihash"),
    ///
    (Blake2b304, "blake2b-304", 0xb226, "multihash"),
    ///
    (Blake2b312, "blake2b-312", 0xb227, "multihash"),
    ///
    (Blake2b320, "blake2b-320", 0xb228, "multihash"),
    ///
    (Blake2b328, "blake2b-328", 0xb229, "multihash"),
    ///
    (Blake2b336, "blake2b-336", 0xb22a, "multihash"),
    ///
    (Blake2b344, "blake2b-344", 0xb22b, "multihash"),
    ///
    (Blake2b352, "blake2b-352", 0xb22c, "multihash"),
    ///
    (Blake2b360, "blake2b-360", 0xb22d, "multihash"),
    ///
    (Blake2b368, "blake2b-368", 0xb22e, "multihash"),
    ///
    (Blake2b376, "blake2b-376", 0xb22f, "multihash"),
    ///
    (Blake2b384, "blake2b-384", 0xb230, "multihash"),
    ///
    (Blake2b392, "blake2b-392", 0xb231, "multihash"),
    ///
    (Blake2b400, "blake2b-400", 0xb232, "multihash"),
    ///
    (Blake2b408, "blake2b-408", 0xb233, "multihash"),
    ///
    (Blake2b416, "blake2b-416", 0xb234, "multihash"),
    ///
    (Blake2b424, "blake2b-424", 0xb235, "multihash"),
    ///
    (Blake2b432, "blake2b-432", 0xb236, "multihash"),
    ///
    (Blake2b440, "blake2b-440", 0xb237, "multihash"),
    ///
    (Blake2b448, "blake2b-448", 0xb238, "multihash"),
    ///
    (Blake2b456, "blake2b-456", 0xb239, "multihash"),
    ///
    (Blake2b464, "blake2b-464", 0xb23a, "multihash"),
    ///
    (Blake2b472, "blake2b-472", 0xb23b, "multihash"),
    ///
    (Blake2b480, "blake2b-480", 0xb23c, "multihash"),
    ///
    (Blake2b488, "blake2b-488", 0xb23d, "multihash"),
    ///
    (Blake2b496, "blake2b-496", 0xb23e, "multihash"),
    ///
    (Blake2b504, "blake2b-504", 0xb23f, "multihash"),
    ///
    (Blake2b512, "blake2b-512", 0xb240, "multihash"),
    /// Blake2s consists of 32 output lengths that give different hashes
    (Blake2s8, "blake2s-8", 0xb241, "multihash"),
    ///
    (Blake2s16, "blake2s-16", 0xb242, "multihash"),
    ///
    (Blake2s24, "blake2s-24", 0xb243, "multihash"),
    ///
    (Blake2s32, "blake2s-32", 0xb244, "multihash"),
    ///
    (Blake2s40, "blake2s-40", 0xb245, "multihash"),
    ///
    (Blake2s48, "blake2s-48", 0xb246, "multihash"),
    ///
    (Blake2s56, "blake2s-56", 0xb247, "multihash"),
    ///
    (Blake2s64, "blake2s-64", 0xb248, "multihash"),
    ///
    (Blake2s72, "blake2s-72", 0xb249, "multihash"),
    ///
    (Blake2s80, "blake2s-80", 0xb24a, "multihash"),
    ///
    (Blake2s88, "blake2s-88", 0xb24b, "multihash"),
    ///
    (Blake2s96, "blake2s-96", 0xb24c, "multihash"),
    ///
    (Blake2s104, "blake2s-104", 0xb24d, "multihash"),
    ///
    (Blake2s112, "blake2s-112", 0xb24e, "multihash"),
    ///
    (Blake2s120, "blake2s-120", 0xb24f, "multihash"),
    ///
    (Blake2s128, "blake2s-128", 0xb250, "multihash"),
    ///
    (Blake2s136, "blake2s-136", 0xb251, "multihash"),
    ///
    (Blake2s144, "blake2s-144", 0xb252, "multihash"),
    ///
    (Blake2s152, "blake2s-152", 0xb253, "multihash"),
    ///
    (Blake2s160, "blake2s-160", 0xb254, "multihash"),
    ///
    (Blake2s168, "blake2s-168", 0xb255, "multihash"),
    ///
    (Blake2s176, "blake2s-176", 0xb256, "multihash"),
    ///
    (Blake2s184, "blake2s-184", 0xb257, "multihash"),
    ///
    (Blake2s192, "blake2s-192", 0xb258, "multihash"),
    ///
    (Blake2s200, "blake2s-200", 0xb259, "multihash"),
    ///
    (Blake2s208, "blake2s-208", 0xb25a, "multihash"),
    ///
    (Blake2s216, "blake2s-216", 0xb25b, "multihash"),
    ///
    (Blake2s224, "blake2s-224", 0xb25c, "multihash"),
    ///
    (Blake2s232, "blake2s-232", 0xb25d, "multihash"),
    ///
    (Blake2s240, "blake2s-240", 0xb25e, "multihash"),
    ///
    (Blake2s248, "blake2s-248", 0xb25f, "multihash"),
    ///
    (Blake2s256, "blake2s-256", 0xb260, "multihash"),
    /// Skein256 consists of 32 output lengths that give different hashes
    (Skein256_8, "skein256-8", 0xb301, "multihash"),
    ///
    (Skein256_16, "skein256-16", 0xb302, "multihash"),
    ///
    (Skein256_24, "skein256-24", 0xb303, "multihash"),
    ///
    (Skein256_32, "skein256-32", 0xb304, "multihash"),
    ///
    (Skein256_40, "skein256-40", 0xb305, "multihash"),
    ///
    (Skein256_48, "skein256-48", 0xb306, "multihash"),
    ///
    (Skein256_56, "skein256-56", 0xb307, "multihash"),
    ///
    (Skein256_64, "skein256-64", 0xb308, "multihash"),
    ///
    (Skein256_72, "skein256-72", 0xb309, "multihash"),
    ///
    (Skein256_80, "skein256-80", 0xb30a, "multihash"),
    ///
    (Skein256_88, "skein256-88", 0xb30b, "multihash"),
    ///
    (Skein256_96, "skein256-96", 0xb30c, "multihash"),
    ///
    (Skein256_104, "skein256-104", 0xb30d, "multihash"),
    ///
    (Skein256_112, "skein256-112", 0xb30e, "multihash"),
    ///
    (Skein256_120, "skein256-120", 0xb30f, "multihash"),
    ///
    (Skein256_128, "skein256-128", 0xb310, "multihash"),
    ///
    (Skein256_136, "skein256-136", 0xb311, "multihash"),
    ///
    (Skein256_144, "skein256-144", 0xb312, "multihash"),
    ///
    (Skein256_152, "skein256-152", 0xb313, "multihash"),
    ///
    (Skein256_160, "skein256-160", 0xb314, "multihash"),
    ///
    (Skein256_168, "skein256-168", 0xb315, "multihash"),
    ///
    (Skein256_176, "skein256-176", 0xb316, "multihash"),
    ///
    (Skein256_184, "skein256-184", 0xb317, "multihash"),
    ///
    (Skein256_192, "skein256-192", 0xb318, "multihash"),
    ///
    (Skein256_200, "skein256-200", 0xb319, "multihash"),
    ///
    (Skein256_208, "skein256-208", 0xb31a, "multihash"),
    ///
    (Skein256_216, "skein256-216", 0xb31b, "multihash"),
    ///
    (Skein256_224, "skein256-224", 0xb31c, "multihash"),
    ///
    (Skein256_232, "skein256-232", 0xb31d, "multihash"),
    ///
    (Skein256_240, "skein256-240", 0xb31e, "multihash"),
    ///
    (Skein256_248, "skein256-248", 0xb31f, "multihash"),
    ///
    (Skein256_256, "skein256-256", 0xb320, "multihash"),
    /// Skein512 consists of 64 output lengths that give different hashes
    (Skein512_8, "skein512-8", 0xb321, "multihash"),
    ///
    (Skein512_16, "skein512-16", 0xb322, "multihash"),
    ///
    (Skein512_24, "skein512-24", 0xb323, "multihash"),
    ///
    (Skein512_32, "skein512-32", 0xb324, "multihash"),
    ///
    (Skein512_40, "skein512-40", 0xb325, "multihash"),
    ///
    (Skein512_48, "skein512-48", 0xb326, "multihash"),
    ///
    (Skein512_56, "skein512-56", 0xb327, "multihash"),
    ///
    (Skein512_64, "skein512-64", 0xb328, "multihash"),
    ///
    (Skein512_72, "skein512-72", 0xb329, "multihash"),
    ///
    (Skein512_80, "skein512-80", 0xb32a, "multihash"),
    ///
    (Skein512_88, "skein512-88", 0xb32b, "multihash"),
    ///
    (Skein512_96, "skein512-96", 0xb32c, "multihash"),
    ///
    (Skein512_104, "skein512-104", 0xb32d, "multihash"),
    ///
    (Skein512_112, "skein512-112", 0xb32e, "multihash"),
    ///
    (Skein512_120, "skein512-120", 0xb32f, "multihash"),
    ///
    (Skein512_128, "skein512-128", 0xb330, "multihash"),
    ///
    (Skein512_136, "skein512-136", 0xb331, "multihash"),
    ///
    (Skein512_144, "skein512-144", 0xb332, "multihash"),
    ///
    (Skein512_152, "skein512-152", 0xb333, "multihash"),
    ///
    (Skein512_160, "skein512-160", 0xb334, "multihash"),
    ///
    (Skein512_168, "skein512-168", 0xb335, "multihash"),
    ///
    (Skein512_176, "skein512-176", 0xb336, "multihash"),
    ///
    (Skein512_184, "skein512-184", 0xb337, "multihash"),
    ///
    (Skein512_192, "skein512-192", 0xb338, "multihash"),
    ///
    (Skein512_200, "skein512-200", 0xb339, "multihash"),
    ///
    (Skein512_208, "skein512-208", 0xb33a, "multihash"),
    ///
    (Skein512_216, "skein512-216", 0xb33b, "multihash"),
    ///
    (Skein512_224, "skein512-224", 0xb33c, "multihash"),
    ///
    (Skein512_232, "skein512-232", 0xb33d, "multihash"),
    ///
    (Skein512_240, "skein512-240", 0xb33e, "multihash"),
    ///
    (Skein512_248, "skein512-248", 0xb33f, "multihash"),
    ///
    (Skein512_256, "skein512-256", 0xb340, "multihash"),
    ///
    (Skein512_264, "skein512-264", 0xb341, "multihash"),
    ///
    (Skein512_272, "skein512-272", 0xb342, "multihash"),
    ///
    (Skein512_280, "skein512-280", 0xb343, "multihash"),
    ///
    (Skein512_288, "skein512-288", 0xb344, "multihash"),
    ///
    (Skein512_296, "skein512-296", 0xb345, "multihash"),
    ///
    (Skein512_304, "skein512-304", 0xb346, "multihash"),
    ///
    (Skein512_312, "skein512-312", 0xb347, "multihash"),
    ///
    (Skein512_320, "skein512-320", 0xb348, "multihash"),
    ///
    (Skein512_328, "skein512-328", 0xb349, "multihash"),
    ///
    (Skein512_336, "skein512-336", 0xb34a, "multihash"),
    ///
    (Skein512_344, "skein512-344", 0xb34b, "multihash"),
    ///
    (Skein512_352, "skein512-352", 0xb34c, "multihash"),
    ///
    (Skein512_360, "skein512-360", 0xb34d, "multihash"),
    ///
    (Skein512_368, "skein512-368", 0xb34e, "multihash"),
    ///
    (Skein512_376, "skein512-376", 0xb34f, "multihash"),
    ///
    (Skein512_384, "skein512-384", 0xb350, "multihash"),
    ///
    (Skein512_392, "skein512-392", 0xb351, "multihash"),
    ///
    (Skein512_400, "skein512-400", 0xb352, "multihash"),
    ///
    (Skein512_408, "skein512-408", 0xb353, "multihash"),
    ///
    (Skein512_416, "skein512-416", 0xb354, "multihash"),
    ///
    (Skein512_424, "skein512-424", 0xb355, "multihash"),
    ///
    (Skein512_432, "skein512-432", 0xb356, "multihash"),
    ///
    (Skein512_440, "skein512-440", 0xb357, "multihash"),
    ///
    (Skein512_448, "skein512-448", 0xb358, "multihash"),
    ///
    (Skein512_456, "skein512-456", 0xb359, "multihash"),
    ///
    (Skein512_464, "skein512-464", 0xb35a, "multihash"),
    ///
    (Skein512_472, "skein512-472", 0xb35b, "multihash"),
    ///
    (Skein512_480, "skein512-480", 0xb35c, "multihash"),
    ///
    (Skein512_488, "skein512-488", 0xb35d, "multihash"),
    ///
    (Skein512_496, "skein512-496", 0xb35e, "multihash"),
    ///
    (Skein512_504, "skein512-504", 0xb35f, "multihash"),
    ///
    (Skein512_512, "skein512-512", 0xb360, "multihash"),
    /// Skein1024 consists of 128 output lengths that give different hashes
    (Skein1024_8, "skein1024-8", 0xb361, "multihash"),
    ///
    (Skein1024_16, "skein1024-16", 0xb362, "multihash"),
    ///
    (Skein1024_24, "skein1024-24", 0xb363, "multihash"),
    ///
    (Skein1024_32, "skein1024-32", 0xb364, "multihash"),
    ///
    (Skein1024_40, "skein1024-40", 0xb365, "multihash"),
    ///
    (Skein1024_48, "skein1024-48", 0xb366, "multihash"),
    ///
    (Skein1024_56, "skein1024-56", 0xb367, "multihash"),
    ///
    (Skein1024_64, "skein1024-64", 0xb368, "multihash"),
    ///
    (Skein1024_72, "skein1024-72", 0xb369, "multihash"),
    ///
    (Skein1024_80, "skein1024-80", 0xb36a, "multihash"),
    ///
    (Skein1024_88, "skein1024-88", 0xb36b, "multihash"),
    ///
    (Skein1024_96, "skein1024-96", 0xb36c, "multihash"),
    ///
    (Skein1024_104, "skein1024-104", 0xb36d, "multihash"),
    ///
    (Skein1024_112, "skein1024-112", 0xb36e, "multihash"),
    ///
    (Skein1024_120, "skein1024-120", 0xb36f, "multihash"),
    ///
    (Skein1024_128, "skein1024-128", 0xb370, "multihash"),
    ///
    (Skein1024_136, "skein1024-136", 0xb371, "multihash"),
    ///
    (Skein1024_144, "skein1024-144", 0xb372, "multihash"),
    ///
    (Skein1024_152, "skein1024-152", 0xb373, "multihash"),
    ///
    (Skein1024_160, "skein1024-160", 0xb374, "multihash"),
    ///
    (Skein1024_168, "skein1024-168", 0xb375, "multihash"),
    ///
    (Skein1024_176, "skein1024-176", 0xb376, "multihash"),
    ///
    (Skein1024_184, "skein1024-184", 0xb377, "multihash"),
    ///
    (Skein1024_192, "skein1024-192", 0xb378, "multihash"),
    ///
    (Skein1024_200, "skein1024-200", 0xb379, "multihash"),
    ///
    (Skein1024_208, "skein1024-208", 0xb37a, "multihash"),
    ///
    (Skein1024_216, "skein1024-216", 0xb37b, "multihash"),
    ///
    (Skein1024_224, "skein1024-224", 0xb37c, "multihash"),
    ///
    (Skein1024_232, "skein1024-232", 0xb37d, "multihash"),
    ///
    (Skein1024_240, "skein1024-240", 0xb37e, "multihash"),
    ///
    (Skein1024_248, "skein1024-248", 0xb37f, "multihash"),
    ///
    (Skein1024_256, "skein1024-256", 0xb380, "multihash"),
    ///
    (Skein1024_264, "skein1024-264", 0xb381, "multihash"),
    ///
    (Skein1024_272, "skein1024-272", 0xb382, "multihash"),
    ///
    (Skein1024_280, "skein1024-280", 0xb383, "multihash"),
    ///
    (Skein1024_288, "skein1024-288", 0xb384, "multihash"),
    ///
    (Skein1024_296, "skein1024-296", 0xb385, "multihash"),
    ///
    (Skein1024_304, "skein1024-304", 0xb386, "multihash"),
    ///
    (Skein1024_312, "skein1024-312", 0xb387, "multihash"),
    ///
    (Skein1024_320, "skein1024-320", 0xb388, "multihash"),
    ///
    (Skein1024_328, "skein1024-328", 0xb389, "multihash"),
    ///
    (Skein1024_336, "skein1024-336", 0xb38a, "multihash"),
    ///
    (Skein1024_344, "skein1024-344", 0xb38b, "multihash"),
    ///
    (Skein1024_352, "skein1024-352", 0xb38c, "multihash"),
    ///
    (Skein1024_360, "skein1024-360", 0xb38d, "multihash"),
    ///
    (Skein1024_368, "skein1024-368", 0xb38e, "multihash"),
    ///
    (Skein1024_376, "skein1024-376", 0xb38f, "multihash"),
    ///
    (Skein1024_384, "skein1024-384", 0xb390, "multihash"),
    ///
    (Skein1024_392, "skein1024-392", 0xb391, "multihash"),
    ///
    (Skein1024_400, "skein1024-400", 0xb392, "multihash"),
    ///
    (Skein1024_408, "skein1024-408", 0xb393, "multihash"),
    ///
    (Skein1024_416, "skein1024-416", 0xb394, "multihash"),
    ///
    (Skein1024_424, "skein1024-424", 0xb395, "multihash"),
    ///
    (Skein1024_432, "skein1024-432", 0xb396, "multihash"),
    ///
    (Skein1024_440, "skein1024-440", 0xb397, "multihash"),
    ///
    (Skein1024_448, "skein1024-448", 0xb398, "multihash"),
    ///
    (Skein1024_456, "skein1024-456", 0xb399, "multihash"),
    ///
    (Skein1024_464, "skein1024-464", 0xb39a, "multihash"),
    ///
    (Skein1024_472, "skein1024-472", 0xb39b, "multihash"),
    ///
    (Skein1024_480, "skein1024-480", 0xb39c, "multihash"),
    ///
    (Skein1024_488, "skein1024-488", 0xb39d, "multihash"),
    ///
    (Skein1024_496, "skein1024-496", 0xb39e, "multihash"),
    ///
    (Skein1024_504, "skein1024-504", 0xb39f, "multihash"),
    ///
    (Skein1024_512, "skein1024-512", 0xb3a0, "multihash"),
    ///
    (Skein1024_520, "skein1024-520", 0xb3a1, "multihash"),
    ///
    (Skein1024_528, "skein1024-528", 0xb3a2, "multihash"),
    ///
    (Skein1024_536, "skein1024-536", 0xb3a3, "multihash"),
    ///
    (Skein1024_544, "skein1024-544", 0xb3a4, "multihash"),
    ///
    (Skein1024_552, "skein1024-552", 0xb3a5, "multihash"),
    ///
    (Skein1024_560, "skein1024-560", 0xb3a6, "multihash"),
    ///
    (Skein1024_568, "skein1024-568", 0xb3a7, "multihash"),
    ///
    (Skein1024_576, "skein1024-576", 0xb3a8, "multihash"),
    ///
    (Skein1024_584, "skein1024-584", 0xb3a9, "multihash"),
    ///
    (Skein1024_592, "skein1024-592", 0xb3aa, "multihash"),
    ///
    (Skein1024_600, "skein1024-600", 0xb3ab, "multihash"),
    ///
    (Skein1024_608, "skein1024-608", 0xb3ac, "multihash"),
    ///
    (Skein1024_616, "skein1024-616", 0xb3ad, "multihash"),
    ///
    (Skein1024_624, "skein1024-624", 0xb3ae, "multihash"),
    ///
    (Skein1024_632, "skein1024-632", 0xb3af, "multihash"),
    ///
    (Skein1024_640, "skein1024-640", 0xb3b0, "multihash"),
    ///
    (Skein1024_648, "skein1024-648", 0xb3b1, "multihash"),
    ///
    (Skein1024_656, "skein1024-656", 0xb3b2, "multihash"),
    ///
    (Skein1024_664, "skein1024-664", 0xb3b3, "multihash"),
    ///
    (Skein1024_672, "skein1024-672", 0xb3b4, "multihash"),
    ///
    (Skein1024_680, "skein1024-680", 0xb3b5, "multihash"),
    ///
    (Skein1024_688, "skein1024-688", 0xb3b6, "multihash"),
    ///
    (Skein1024_696, "skein1024-696", 0xb3b7, "multihash"),
    ///
    (Skein1024_704, "skein1024-704", 0xb3b8, "multihash"),
    ///
    (Skein1024_712, "skein1024-712", 0xb3b9, "multihash"),
    ///
    (Skein1024_720, "skein1024-720", 0xb3ba, "multihash"),
    ///
    (Skein1024_728, "skein1024-728", 0xb3bb, "multihash"),
    ///
    (Skein1024_736, "skein1024-736", 0xb3bc, "multihash"),
    ///
    (Skein1024_744, "skein1024-744", 0xb3bd, "multihash"),
    ///
    (Skein1024_752, "skein1024-752", 0xb3be, "multihash"),
    ///
    (Skein1024_760, "skein1024-760", 0xb3bf, "multihash"),
    ///
    (Skein1024_768, "skein1024-768", 0xb3c0, "multihash"),
    ///
    (Skein1024_776, "skein1024-776", 0xb3c1, "multihash"),
    ///
    (Skein1024_784, "skein1024-784", 0xb3c2, "multihash"),
    ///
    (Skein1024_792, "skein1024-792", 0xb3c3, "multihash"),
    ///
    (Skein1024_800, "skein1024-800", 0xb3c4, "multihash"),
    ///
    (Skein1024_808, "skein1024-808", 0xb3c5, "multihash"),
    ///
    (Skein1024_816, "skein1024-816", 0xb3c6, "multihash"),
    ///
    (Skein1024_824, "skein1024-824", 0xb3c7, "multihash"),
    ///
    (Skein1024_832, "skein1024-832", 0xb3c8, "multihash"),
    ///
    (Skein1024_840, "skein1024-840", 0xb3c9, "multihash"),
    ///
    (Skein1024_848, "skein1024-848", 0xb3ca, "multihash"),
    ///
    (Skein1024_856, "skein1024-856", 0xb3cb, "multihash"),
    ///
    (Skein1024_864, "skein1024-864", 0xb3cc, "multihash"),
    ///
    (Skein1024_872, "skein1024-872", 0xb3cd, "multihash"),
    ///
    (Skein1024_880, "skein1024-880", 0xb3ce, "multihash"),
    ///
    (Skein1024_888, "skein1024-888", 0xb3cf, "multihash"),
    ///
    (Skein1024_896, "skein1024-896", 0xb3d0, "multihash"),
    ///
    (Skein1024_904, "skein1024-904", 0xb3d1, "multihash"),
    ///
    (Skein1024_912, "skein1024-912", 0xb3d2, "multihash"),
    ///
    (Skein1024_920, "skein1024-920", 0xb3d3, "multihash"),
    ///
    (Skein1024_928, "skein1024-928", 0xb3d4, "multihash"),
    ///
    (Skein1024_936, "skein1024-936", 0xb3d5, "multihash"),
    ///
    (Skein1024_944, "skein1024-944", 0xb3d6, "multihash"),
    ///
    (Skein1024_952, "skein1024-952", 0xb3d7, "multihash"),
    ///
    (Skein1024_960, "skein1024-960", 0xb3d8, "multihash"),
    ///
    (Skein1024_968, "skein1024-968", 0xb3d9, "multihash"),
    ///
    (Skein1024_976, "skein1024-976", 0xb3da, "multihash"),
    ///
    (Skein1024_984, "skein1024-984", 0xb3db, "multihash"),
    ///
    (Skein1024_992, "skein1024-992", 0xb3dc, "multihash"),
    ///
    (Skein1024_1000, "skein1024-1000", 0xb3dd, "multihash"),
    ///
    (Skein1024_1008, "skein1024-1008", 0xb3de, "multihash"),
    ///
    (Skein1024_1016, "skein1024-1016", 0xb3df, "multihash"),
    ///
    (Skein1024_1024, "skein1024-1024", 0xb3e0, "multihash"),
    /// Poseidon using BLS12-381 and arity of 2 with Filecoin parameters
    (
        PoseidonBls12_381A2Fc1,
        "poseidon-bls12_381-a2-fc1",
        0xb401,
        "multihash"
    ),
    /// Poseidon using BLS12-381 and arity of 2 with Filecoin parameters - high-security variant
    (
        PoseidonBls12_381A2Fc1Sc,
        "poseidon-bls12_381-a2-fc1-sc",
        0xb402,
        "multihash"
    ),
    /// 0xcert Asset Imprint (root "root" hash)
    (
        ZeroxcertImprint256,
        "zeroxcert-imprint-256",
        0xce11,
        "zeroxcert"
    ),
    /// Filecoin piece or sector data commitment merkle node/root (CommP "commp" & CommD)
    (
        FilCommitmentUnsealed,
        "fil-commitment-unsealed",
        0xf101,
        "filecoin"
    ),
    /// Filecoin sector data commitment merkle node/root - sealed and replicated (CommR)
    (
        FilCommitmentSealed,
        "fil-commitment-sealed",
        0xf102,
        "filecoin"
    ),
    /// Holochain v0 address    + 8 R-S (63 "63" x Base-32)
    (HolochainAdrV0, "holochain-adr-v0", 0x807124, "holochain"),
    /// Holochain v1 address    + 8 R-S (63 "63" x Base-32)
    (HolochainAdrV1, "holochain-adr-v1", 0x817124, "holochain"),
    /// Holochain v0 public key + 8 R-S (63 "63" x Base-32)
    (HolochainKeyV0, "holochain-key-v0", 0x947124, "holochain"),
    /// Holochain v1 public key + 8 R-S (63 "63" x Base-32)
    (HolochainKeyV1, "holochain-key-v1", 0x957124, "holochain"),
    /// Holochain v0 signature  + 8 R-S (63 "63" x Base-32)
    (HolochainSigV0, "holochain-sig-v0", 0xa27124, "holochain"),
    /// Holochain v1 signature  + 8 R-S (63 "63" x Base-32)
    (HolochainSigV1, "holochain-sig-v1", 0xa37124, "holochain"),
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
        let pkg_lines = details();
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
}
