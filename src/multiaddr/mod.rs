macro_rules! read_slice {
    ($data:expr, $n:expr, $prefix:expr) => {
        if $data.len() < $n {
            err_at!(DecodeError, msg: "{} insufficient bytes {}", $prefix, $n)
        } else {
            Ok((&$data[..$n], &$data[$n..]))
        }
    };
}

pub(crate) mod dccp;
pub(crate) mod dns;
pub(crate) mod dns4;
pub(crate) mod dns6;
pub(crate) mod dnsaddr;
pub(crate) mod garlic32;
pub(crate) mod garlic64;
pub(crate) mod http;
pub(crate) mod https;
pub(crate) mod ip4;
pub(crate) mod ip6;
pub(crate) mod ip6zone;
pub(crate) mod onion;
pub(crate) mod onion3;
pub(crate) mod p2p;
pub(crate) mod p2p_circuit;
pub(crate) mod p2p_webrtc_direct;
pub(crate) mod quic;
pub(crate) mod sctp;
pub(crate) mod tcp;
pub(crate) mod udp;
pub(crate) mod udt;
pub(crate) mod unix;
pub(crate) mod utp;
pub(crate) mod ws;
pub(crate) mod wss;

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
        #[derive(Clone, Eq, PartialEq, Debug)]
        pub enum Multiaddr {
            Text(String),    // unparsed multi-addr in text format.
            Binary(Vec<u8>), // unparsed multi-addr in binary format.
            $(
                #[$doc]
                $var($type, Box<Self>),
            )*
            Ipfs(P2p, Box<Self>),
            None,
        }

        impl Multiaddr {
            /// Parse text formated multi-address. Refer to
            /// [spec](https://multiformats.io/multiaddr/) for details.
            pub fn from_text(text: &str) -> Result<Multiaddr> {
                let parts: Vec<&str> = text.split('/').collect();

                if parts.len() == 0 {
                    err_at!(BadAddr, msg: "empty multiaddr {}", text)
                } else if parts[0].is_empty() {
                    err_at!(BadAddr, msg: "multiaddr must start with '/'")
                } else if parts[1..].len() == 0 {
                    err_at!(BadAddr, msg: "empty multiaddr {}", text)
                } else {
                    match Self::parse_text_parts(&parts[1..])? {
                        (ma, []) => Ok(ma),
                        (_, _) => err_at!(BadAddr, msg: "invalid multiaddr {:?}", text),
                    }
                }
            }

            pub(crate) fn parse_text_parts<'a, 'b>(parts: &'a [&'b str]) -> Result<(Multiaddr, &'a [&'b str])> {
                let (maddr, tail) = match parts {
                    [] => (Multiaddr::None, parts),
                    $(
                        [$name, ..] => {
                            let (val, tail) = $type::from_text(&parts[1..])?;
                            let (ma, tail) = Self::parse_text_parts(tail)?;
                            (Multiaddr::$var(val, Box::new(ma)), tail)
                        }
                    )*
                    ["ip", ..] => {
                        // first try parsing it for ip4
                        match Ip4::from_text(&parts[1..]) {
                            Ok((val, tail)) => {
                                let (ma, tail) = Self::parse_text_parts(tail)?;
                                (Multiaddr::Ip4(val, Box::new(ma)), tail)
                            }
                            Err(_) => {
                                // then try parsing it for ip6
                                let (val, tail) = Ip6::from_text(&parts[1..])?;
                                let (ma, tail) = Self::parse_text_parts(tail)?;
                                (Multiaddr::Ip6(val, Box::new(ma)), tail)
                            }
                        }
                    }
                    ["ipfs", ..] => {
                        let (val, tail) = P2p::from_text(&parts[1..])?;
                        let (ma, tail) = Self::parse_text_parts(tail)?;
                        (Multiaddr::P2p(val, Box::new(ma)), tail)
                    }
                    parts => err_at!(BadAddr, msg: "invalid multiaddr {:?}", parts)?,
                };

                Ok((maddr, tail))
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
                        Multiaddr::$var(val, tail) => {
                            val.to_text()? + &tail.to_text()?
                        }
                    )*
                    Multiaddr::Ipfs(val, tail) => {
                        val.to_text()? + &tail.to_text()?
                    }
                    Multiaddr::None => "".to_string(),
                };

                Ok(text)
            }

            /// Parse binary formated multi-address. Refer to
            /// [spec](https://multiformats.io/multiaddr/) for details.
            pub fn decode(data: &[u8]) -> Result<(Multiaddr, &[u8])> {
                if data.len() == 0 {
                    return Ok((Multiaddr::None, data))
                }

                let (codec, data) = Multicodec::decode(data)?;

                let (ma, data) = match codec.to_code() {
                    $(
                        $code => {
                            let (val, data) = $type::decode(data)?;
                            let (ma, data) = Self::decode(data)?;
                            (Multiaddr::$var(val, Box::new(ma)), data)
                        }
                    )*
                    code => err_at!(DecodeError, msg: "invalid code {}", code)?,
                };

                Ok((ma, data))
            }

            /// Encode this multi-address into binary format.
            pub fn encode(&self) -> Result<Vec<u8>> {
                let data = match self {
                    Multiaddr::Text ( text ) => Self::from_text(text)?.encode()?,
                    Multiaddr::Binary ( data ) => data.clone(),
                    $(
                        Multiaddr::$var(val, tail) => {
                            let mut data = val.encode()?;
                            data.extend_from_slice(&tail.encode()?);
                            data
                        }
                    )*
                    Multiaddr::Ipfs(val, tail) => {
                        let mut data = val.encode()?;
                        data.extend_from_slice(&tail.encode()?);
                        data
                    }
                    Multiaddr::None => vec![],
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

            /// Return multiaddr as array of components.
            pub fn split(self) -> Result<Vec<Self>> {
                let mut ma = match self {
                    Multiaddr::Text ( text ) => Self::from_text(&text)?,
                    Multiaddr::Binary ( data ) => Self::decode(&data)?.0,
                    ma => ma
                };

                let mut components = vec![];
                let nn = Box::new(Multiaddr::None);
                loop {
                    ma = match ma {
                        $(
                            Multiaddr::$var(val, ma) => {
                                components.push(Multiaddr::$var(val, nn.clone()));
                                *ma
                            }
                        )*
                        Multiaddr::Ipfs(val, ma) => {
                            components.push(Multiaddr::Ipfs(val, nn.clone()));
                            *ma
                        }
                        Multiaddr::Text(_) => break,
                        Multiaddr::Binary(_) => break,
                        Multiaddr::None => break,
                    };
                }

                Ok(components)
            }

            /// Join the components into single multiaddr.
            pub fn join(mut components: Vec<Multiaddr>) -> Result<Multiaddr> {
                let mut ma = Box::new(Multiaddr::None);
                components.reverse();
                for comp in components.into_iter() {
                    ma = match comp {
                        $(
                            Multiaddr::$var(val, box Multiaddr::None) => {
                                Box::new(Multiaddr::$var(val, ma))
                            }
                        )*
                        Multiaddr::Ipfs(val, box Multiaddr::None) => {
                            Box::new(Multiaddr::Ipfs(val, ma))
                        }
                        _ => err_at!(Invalid, msg: "can't joint")?
                    }
                }

                Ok(*ma)
            }
        }
    );
}

impl Multiaddr {
    /// IsThinWaist returns whether a Multiaddr starts with "Thin Waist"
    /// Protocols. This means: /{IP4, IP6}[/{TCP, UDP}]
    pub fn is_thin_wait(&self) -> bool {
        use Multiaddr::*;

        let ma = match self {
            Ip4(_, box tail) => tail.clone(),
            Ip6(_, box tail) => tail.clone(),
            _ => return false,
        };
        match ma {
            Tcp(_, _) => true,
            Udp(_, _) => true,
            Multiaddr::None => true,
            _ => false,
        }
    }

    pub fn parse(self) -> Result<Self> {
        use Multiaddr::*;

        let val = match self {
            Text(text) => Multiaddr::from_text(&text)?,
            Binary(data) => Multiaddr::decode(&data)?.0,
            _ => self,
        };

        Ok(val)
    }
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
