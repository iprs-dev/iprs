//! Module implement [multiaddr](https://multiformats.io/multiaddr/)
//! specification.

// Copyright (c) 2020 R Pratap Chakravarthy

#[macro_export]
macro_rules! read_slice {
    ($data:expr, $n:expr, $prefix:expr) => {
        if $data.len() < $n {
            let msg = format!("{} insufficient bytes {}", $prefix, $n);
            err_at!(DecodeError, msg: msg)
        } else {
            Ok((&$data[..$n], &$data[$n..]))
        }
    };
}

mod dccp;
mod dns;
mod dns4;
mod dns6;
mod dnsaddr;
mod garlic32;
mod garlic64;
mod http;
mod https;
mod ip4;
mod ip6;
mod ip6zone;
mod onion;
mod onion3;
mod p2p;
mod p2p_circuit;
mod p2p_webrtc_direct;
mod quic;
mod sctp;
mod tcp;
mod udp;
mod udt;
mod unix;
mod utp;
mod ws;
mod wss;

use crate::{
    multiaddr::{
        dccp::Dccp, dns::Dns, dns4::Dns4, dns6::Dns6, dnsaddr::Dnsaddr, garlic32::Garlic32,
        garlic64::Garlic64, http::Http, https::Https, ip4::Ip4, ip6::Ip6, ip6zone::Ip6zone,
        onion::Onion, onion3::Onion3, p2p::P2p, p2p_circuit::P2pCircuit,
        p2p_webrtc_direct::P2pWebRtcDirect, quic::Quic, sctp::Sctp, tcp::Tcp, udp::Udp, udt::Udt,
        unix::Unix, utp::Utp, ws::Ws, wss::Wss,
    },
    multicodec::{self, Multicodec},
    Error, Result,
};

macro_rules! impl_multiaddr {
    ($(
        #[$doc:meta]
        ($var:ident, $type:ident, $name:expr, $code:path),
    )*) => (
        /// Type implement a multiaddress.
        ///
        /// As an enumerated type it can hold multiaddress,
        ///
        /// * Address encoded in binary format.
        /// * Address encoded in text format.
        /// * Or parsed from binary/text format and held as Ip4, Tcp, Udp,
        ///   Quic etc..
        #[derive(Clone, Eq, PartialEq)]
        pub enum Multiaddr {
            Text(String),    // unparsed multi-addr in text format.
            Binary(Vec<u8>), // unparsed multi-addr in binary format.
            $(
                #[$doc]
                $var($type),
            )*
            Ipfs(P2p),
            None,
        }

        impl Multiaddr {
            /// Parse text formated multi-address. Refer to
            /// [spec](https://multiformats.io/multiaddr/) for details.
            pub fn from_text(text: &str) -> Result<Multiaddr> {
                let parts: Vec<&str> = text.split('/').collect();

                if parts.len() == 0 {
                    err_at!(BadAddr, msg: format!("empty multiaddr {}", text))
                } else if parts[0].is_empty() {
                    err_at!(BadAddr, msg: format!("multiaddr must start with '/'"))
                } else if parts[1..].len() == 0 {
                    err_at!(BadAddr, msg: format!("empty multiaddr {}", text))
                } else {
                    Self::parse_text_parts(&parts[1..])
                }
            }

            pub(crate) fn parse_text_parts(parts: &[&str]) -> Result<Multiaddr> {
                let maddr = match parts {
                    $(
                        [$name, ..] => {
                            let val = $type::from_text(&parts[1..])?;
                            Multiaddr::$var(val)
                        }
                    )*
                    ["ipfs", ..] => {
                        let val = P2p::from_text(&parts[1..])?;
                        Multiaddr::P2p(val)
                    }
                    parts => {
                        let msg = format!("invalid multiaddr components {:?}", parts);
                        err_at!(BadAddr, msg: msg)?
                    }
                };

                Ok(maddr)
            }

            /// Convert this multi-address into text format.
            pub fn to_text(&self) -> Result<String> {
                let text = match self {
                    Multiaddr::Text ( text ) => text.clone(),
                    Multiaddr::Binary(data) => {
                        let (maddr, _) = Self::decode(&data)?;
                        maddr.to_text()?
                    }
                    $(
                        Multiaddr::$var(val) => val.to_text()?,
                    )*
                    Multiaddr::Ipfs(val) => val.to_text()?,
                    Multiaddr::None => {
                        let msg = format!("empty multiaddr");
                        err_at!(Invalid, msg: msg)?
                    }
                };

                Ok(text)
            }

            /// Parse binary formated multi-address. Refer to
            /// [spec](https://multiformats.io/multiaddr/) for details.
            pub fn decode(data: &[u8]) -> Result<(Multiaddr, &[u8])> {
                let (codec, data) = Multicodec::decode(data)?;

                let (ma, data) = match codec.to_code() {
                    $(
                        $code => {
                            let (val, data) = $type::decode(data)?;
                            (Multiaddr::$var(val), data)
                        }
                    )*
                    code => {
                        let msg = format!("invalid code {}", code);
                        err_at!(DecodeError, msg: msg)?
                    }
                };

                Ok((ma, data))
            }

            /// Encode this multi-address into binary format.
            pub fn encode(&self) -> Result<Vec<u8>> {
                let data = match self {
                    Multiaddr::Text ( text ) => Self::from_text(text)?.encode()?,
                    Multiaddr::Binary ( data ) => data.clone(),
                    $(
                        Multiaddr::$var(val) => val.encode()?,
                    )*
                    Multiaddr::Ipfs(val) => val.encode()?,
                    Multiaddr::None => {
                        let msg = format!("empty multiaddr");
                        err_at!(Invalid, msg: msg)?
                    }
                };

                Ok(data)
            }

            /// Return the multiaddress as multi-codec.
            pub fn to_multicodec(&self) -> Option<Multicodec> {
                match self {
                    Multiaddr::Text ( _ ) => None,
                    Multiaddr::Binary ( _ ) => None,
                    $(
                        Multiaddr::$var{ .. } => Some($code.into()),
                    )*
                    Multiaddr::Ipfs{ .. } => Some(multicodec::P2P.into()),
                    Multiaddr::None => None,
                }
            }
        }
    );
}

impl_multiaddr![
    /// Internet-protocol version 4
    (Ip4, Ip4, "ip4", multicodec::IP4),
    /// Internet-protocol version 6
    (Ip6, Ip6, "ip6", multicodec::IP6),
    /// Transport control protocol
    (Tcp, Tcp, "tcp", multicodec::TCP),
    /// Domain name service
    (Dns, Dns, "dns", multicodec::DNS),
    /// Domain name service, for IP4
    (Dns4, Dns4, "dns4", multicodec::DNS4),
    /// Domain name service, for IP6
    (Dns6, Dns6, "dns6", multicodec::DNS6),
    /// Domain name service, automatic
    (Dnsaddr, Dnsaddr, "dnsaddr", multicodec::DNSADDR),
    /// User datagram protocol
    (Udp, Udp, "udp", multicodec::UDP),
    /// Datagram congestion control protocol
    (Dccp, Dccp, "dccp", multicodec::DCCP),
    /// Ip-6-zone
    (Ip6zone, Ip6zone, "ip6zone", multicodec::IP6ZONE),
    /// Stream control transmission protocol
    (Sctp, Sctp, "sctp", multicodec::SCTP),
    /// Onion routing for Tor network.
    (Onion, Onion, "onion", multicodec::ONION),
    /// Onion routing for Tor network.
    (Onion3, Onion3, "onion3", multicodec::ONION3),
    /// Garlic routing for invisible internet protocol
    (Garlic32, Garlic32, "garlic32", multicodec::GARLIC32),
    /// Garlic routine for invisible internet protocol
    (Garlic64, Garlic64, "garlic64", multicodec::GARLIC64),
    /// Peer-2-peer addressing for ipfs and affiliated network
    (P2p, P2p, "p2p", multicodec::P2P),
    /// Unix socket addressing
    (Unix, Unix, "unix", multicodec::UNIX),
    /// Utp addressing
    (Utp, Utp, "utp", multicodec::UTP),
    /// Udt addressing
    (Udt, Udt, "udt", multicodec::UDT),
    /// Quic addressing
    (Quic, Quic, "quic", multicodec::QUIC),
    /// Addressing for HTTP protocol
    (Http, Http, "http", multicodec::HTTP),
    /// Https addressing
    (Https, Https, "https", multicodec::HTTPS),
    /// p2p-circuit addressing
    (
        P2pCircuit,
        P2pCircuit,
        "p2p-circuit",
        multicodec::P2P_CIRCUIT
    ),
    /// p2p-webrtc-direct addressing
    (
        P2pWebRtcDirect,
        P2pWebRtcDirect,
        "p2p-webrtc-direct",
        multicodec::P2P_WEBRTC_DIRECT
    ),
    /// ws addressing
    (Ws, Ws, "ws", multicodec::WS),
    /// wss addressing
    (Wss, Wss, "wss", multicodec::WSS),
];
