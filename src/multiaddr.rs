// Copyright (c) 2020 R Pratap Chakravarthy

use std::{convert::TryInto, net};

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

/// Multiaddr type, either as binary encoded data or as one of
/// many multiaddr values, like Ip4, Tcp, Udp, Quic etc..
#[derive(Clone, Eq, PartialEq)]
pub enum Multiaddr {
    Binary {
        data: Vec<u8>,
    },
    Ip4 {
        addr: net::Ipv4Addr,
        mddr: Option<Box<Multiaddr>>,
    },
    Tcp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns {
        addr: String,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns4 {
        addr: String,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns6 {
        addr: String,
        mddr: Option<Box<Multiaddr>>,
    },
    Dnsaddr {
        addr: String,
        mddr: Option<Box<Multiaddr>>,
    },
    Udp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Quic {
        mddr: Option<Box<Multiaddr>>,
    },
    Dccp {
        mddr: Option<Box<Multiaddr>>,
    },
    Ip6 {
        mddr: Option<Box<Multiaddr>>,
    },
    Ip6zone {
        mddr: Option<Box<Multiaddr>>,
    },
    Sctp {
        mddr: Option<Box<Multiaddr>>,
    },
    Circuit {
        mddr: Option<Box<Multiaddr>>,
    },
    Udt {
        mddr: Option<Box<Multiaddr>>,
    },
    Utp {
        mddr: Option<Box<Multiaddr>>,
    },
    Unix {
        mddr: Option<Box<Multiaddr>>,
    },
    P2p {
        mddr: Option<Box<Multiaddr>>,
    },
    Ipfs {
        mddr: Option<Box<Multiaddr>>,
    },
    Http {
        mddr: Option<Box<Multiaddr>>,
    },
    Https {
        mddr: Option<Box<Multiaddr>>,
    },
    Onion {
        mddr: Option<Box<Multiaddr>>,
    },
    Onion3 {
        mddr: Option<Box<Multiaddr>>,
    },
    Garlic64 {
        mddr: Option<Box<Multiaddr>>,
    },
    Garlic32 {
        mddr: Option<Box<Multiaddr>>,
    },
    P2pWebRtcDirect {
        mddr: Option<Box<Multiaddr>>,
    },
    Ws {
        mddr: Option<Box<Multiaddr>>,
    },
    Wss {
        mddr: Option<Box<Multiaddr>>,
    },
}

impl Multiaddr {
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

    fn parse_text_parts(parts: &[&str]) -> Result<Multiaddr> {
        let maddr = match parts {
            ["ipv4", addr, ..] => {
                let addr: net::Ipv4Addr = err_at!(BadAddr, addr.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(&parts[2..])?));
                Multiaddr::Ip4 { addr, mddr }
            }
            ["tcp", port] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = None;
                Multiaddr::Tcp { port, mddr }
            }
            ["dns", addr] => todo!(),
            ["dns4", addr] => todo!(),
            ["dns6", addr] => todo!(),
            ["dnsaddr", addr] => todo!(),
            ["udp", port] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = None;
                Multiaddr::Udp { port, mddr }
            }
            ["udp", port, ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(&parts[3..])?));
                Multiaddr::Udp { port, mddr }
            }
            ["quic"] => todo!(),
            parts => {
                let msg = format!("invalid multiaddr components {:?}", parts);
                err_at!(BadAddr, msg: msg)?
            }
        };

        Ok(maddr)
    }

    pub fn to_text(&self) -> Result<String> {
        use Multiaddr::*;

        match self {
            Binary { data } => {
                let (maddr, _) = Self::decode(&data)?;
                maddr.to_text()
            }
            Ip4 { addr, mddr } => todo!(),
            Tcp { port, mddr } => todo!(),
            Dns { addr, mddr } => todo!(),
            Dns4 { addr, mddr } => todo!(),
            Dns6 { addr, mddr } => todo!(),
            Dnsaddr { addr, mddr } => todo!(),
            Udp { port, mddr } => todo!(),
            Quic { mddr } => todo!(),
            Dccp { mddr } => todo!(),
            Ip6 { mddr } => todo!(),
            Ip6zone { mddr } => todo!(),
            Sctp { mddr } => todo!(),
            Circuit { mddr } => todo!(),
            Udt { mddr } => todo!(),
            Utp { mddr } => todo!(),
            Unix { mddr } => todo!(),
            P2p { mddr } => todo!(),
            Ipfs { mddr } => todo!(),
            Http { mddr } => todo!(),
            Https { mddr } => todo!(),
            Onion { mddr } => todo!(),
            Onion3 { mddr } => todo!(),
            Garlic64 { mddr } => todo!(),
            Garlic32 { mddr } => todo!(),
            P2pWebRtcDirect { mddr } => todo!(),
            Ws { mddr } => todo!(),
            Wss { mddr } => todo!(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<(Multiaddr, &[u8])> {
        todo!()
        //let (addr, byts) = Self::do_decode(bytes)?;
        //Some((*addr, byts))
    }

    //fn do_decode(bytes: &[u8]) -> Option<(Box<Multiaddr>, &[u8])> {
    //    if bytes.len() == 0 {
    //        return None;
    //    }

    //    let (mcode, bs) = Multicodec::decode(bytes).ok()?;
    //    match mcode.to_code() {
    //        multicodec::IP4 if bs.len() >= 4 => {
    //            let addr = net::Ipv4Addr::new(bs[0], bs[1], bs[2], bs[3]);
    //            let byts = &bs[4..];
    //            let (mddr, byts) = match Self::do_decode(byts) {
    //                Some((mddr, byts)) => (Some(mddr), byts),
    //                None => (None, byts),
    //            };
    //            Some((Box::new(Multiaddr::Ip4 { addr, mddr }), byts))
    //        }
    //        multicodec::TCP if bs.len() >= 2 => {
    //            let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
    //            Some((Box::new(Multiaddr::Tcp { port }), &bs[2..]))
    //        }
    //        multicodec::UDP if bs.len() >= 2 => {
    //            let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
    //            let (mddr, bytes) = match Self::do_decode(&bs[2..]) {
    //                Some((mddr, bytes)) => (Some(mddr), bytes),
    //                None => (None, &bs[2..]),
    //            };
    //            Some((Box::new(Multiaddr::Udp { port, mddr }), bytes))
    //        }
    //        multicodec::QUIC => Some((Box::new(Multiaddr::Quic), bs)),
    //        _ => None,
    //    }
    //}
}
impl Multiaddr {
    fn to_multicodec(&self) -> Option<Multicodec> {
        use Multiaddr::*;

        let code = match self {
            Binary { .. } => return None,
            Ip4 { .. } => 0x0004,
            Tcp { .. } => 0x0006,
            Dns { .. } => 0x0035, // 4 or 6
            Dns4 { .. } => 0x0036,
            Dns6 { .. } => 0x0037,
            Dnsaddr { .. } => 0x0038,
            Udp { .. } => 0x0111,
            Dccp { .. } => 0x0021,
            Ip6 { .. } => 0x0029,
            Ip6zone { .. } => 0x002A,
            Quic { .. } => 0x01CC,
            Sctp { .. } => 0x0084,
            Circuit { .. } => 0x0122,
            Udt { .. } => 0x012D,
            Utp { .. } => 0x012E,
            Unix { .. } => 0x0190,
            P2p { .. } => 0x01A5,
            Ipfs { .. } => 0x01A5, // alias for backwards compatability
            Http { .. } => 0x01E0,
            Https { .. } => 0x01BB,
            Onion { .. } => 0x01BC, // also for backwards compatibility
            Onion3 { .. } => 0x01BD,
            Garlic64 { .. } => 0x01BE,
            Garlic32 { .. } => 0x01BF,
            P2pWebRtcDirect { .. } => 0x0114,
            Ws { .. } => 0x01DD,
            Wss { .. } => 0x01DE,
        };
        Some(code.into())
    }
}
