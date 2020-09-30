// Copyright (c) 2020 R Pratap Chakravarthy

use std::{convert::TryInto, net};

use crate::{
    multicodec::{self, Multicodec},
    peer_id::PeerId,
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
    Ip6 {
        addr: net::Ipv6Addr,
        mddr: Option<Box<Multiaddr>>,
    },
    Tcp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns4 {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Dns6 {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Dnsaddr {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Udp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Dccp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Ip6zone {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Sctp {
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    P2pCircuit {
        mddr: Option<Box<Multiaddr>>,
    },
    Onion {
        hash: Vec<u8>,
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Onion3 {
        hash: Vec<u8>,
        port: u16,
        mddr: Option<Box<Multiaddr>>,
    },
    Garlic64 {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    Garlic32 {
        addr: Vec<u8>,
        mddr: Option<Box<Multiaddr>>,
    },
    P2p {
        addr: PeerId,
        mddr: Option<Box<Multiaddr>>,
    },
    Ipfs {
        mddr: Option<Box<Multiaddr>>,
    },
    Unix {
        path: String,
    },
    Utp {
        mddr: Option<Box<Multiaddr>>,
    },
    Udt {
        mddr: Option<Box<Multiaddr>>,
    },
    Quic {
        mddr: Option<Box<Multiaddr>>,
    },
    Http {
        mddr: Option<Box<Multiaddr>>,
    },
    Https {
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
            ["ip4", addr, tail @ ..] => {
                let addr: net::Ipv4Addr = err_at!(BadAddr, addr.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Ip4 { addr, mddr }
            }
            ["ip6", addr, tail @ ..] => {
                let addr: net::Ipv6Addr = err_at!(BadAddr, addr.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Ip6 { addr, mddr }
            }
            ["tcp", port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Tcp { port, mddr }
            }
            ["dns", addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Dns { addr, mddr }
            }
            ["dns4", addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Dns4 { addr, mddr }
            }
            ["dns6", addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Dns6 { addr, mddr }
            }
            ["dnsaddr", addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Dnsaddr { addr, mddr }
            }
            ["udp", port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Udp { port, mddr }
            }
            ["dccp", port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Dccp { port, mddr }
            }
            ["ip6zone", addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Ip6zone { addr, mddr }
            }
            ["sctp", port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Sctp { port, mddr }
            }
            ["p2p-circuit", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2pCircuit { mddr }
            }
            ["onion", addr, tail @ ..] => {
                let (hash, port) = parse_onion_addr(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Onion { hash, port, mddr }
            }
            ["onion3", addr, tail @ ..] => {
                let (hash, port) = parse_onion3_addr(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Onion3 { hash, port, mddr }
            }
            ["garlic64", addr, tail @ ..] => {
                let addr = parse_garlic64(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Garlic64 { addr, mddr }
            }
            ["garlic32", addr, tail @ ..] => {
                let addr = parse_garlic32(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Garlic32 { addr, mddr }
            }
            ["p2p", addr, tail @ ..] => {
                let addr = PeerId::from_text(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2p { addr, mddr }
            }
            ["ipfs", addr, tail @ ..] => {
                let addr = PeerId::from_text(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2p { addr, mddr }
            }
            ["unix", tail @ ..] => {
                // it's a path protocol (terminal).
                let path = "/".to_string() + &tail.join("/");
                Multiaddr::Unix { path }
            }
            ["utp", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Utp { mddr }
            }
            ["udt", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Udt { mddr }
            }
            ["quic", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Quic { mddr }
            }
            ["http", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Http { mddr }
            }
            ["https", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Https { mddr }
            }
            ["p2p-webrtc-direct", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2pWebRtcDirect { mddr }
            }
            ["ws", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Ws { mddr }
            }
            ["wss", tail @ ..] => {
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::Wss { mddr }
            }
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
            Ip6 { addr, mddr } => todo!(),
            Tcp { port, mddr } => todo!(),
            Dns { addr, mddr } => todo!(),
            Dns4 { addr, mddr } => todo!(),
            Dns6 { addr, mddr } => todo!(),
            Dnsaddr { addr, mddr } => todo!(),
            Udp { port, mddr } => todo!(),
            Dccp { port, mddr } => todo!(),
            Ip6zone { addr, mddr } => todo!(),
            Sctp { port, mddr } => todo!(),
            P2pCircuit { mddr } => todo!(),
            Onion { hash, port, mddr } => todo!(),
            Onion3 { hash, port, mddr } => todo!(),
            Garlic64 { addr, mddr } => todo!(),
            Garlic32 { addr, mddr } => todo!(),
            Unix { path } => todo!(),
            P2p { addr, mddr } => todo!(),
            Ipfs { mddr } => todo!(),
            Udt { mddr } => todo!(),
            Utp { mddr } => todo!(),
            Http { mddr } => todo!(),
            Https { mddr } => todo!(),
            P2pWebRtcDirect { mddr } => todo!(),
            Ws { mddr } => todo!(),
            Wss { mddr } => todo!(),
            Quic { mddr } => todo!(),
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
            Ip6 { .. } => 0x0029,
            Tcp { .. } => 0x0006,
            Dns { .. } => 0x0035, // 4 or 6
            Dns4 { .. } => 0x0036,
            Dns6 { .. } => 0x0037,
            Dnsaddr { .. } => 0x0038,
            Udp { .. } => 0x0111,
            Dccp { .. } => 0x0021,
            Ip6zone { .. } => 0x002A,
            Sctp { .. } => 0x0084,
            P2pCircuit { .. } => 0x0122,
            Onion { .. } => 0x01BC, // also for backwards compatibility
            Onion3 { .. } => 0x01BD,
            Garlic64 { .. } => 0x01BE,
            Garlic32 { .. } => 0x01BF,
            Udt { .. } => 0x012D,
            Utp { .. } => 0x012E,
            Unix { .. } => 0x0190,
            P2p { .. } => 0x01A5,
            Ipfs { .. } => 0x01A5, // alias for backwards compatability
            Http { .. } => 0x01E0,
            Https { .. } => 0x01BB,
            P2pWebRtcDirect { .. } => 0x0114,
            Ws { .. } => 0x01DD,
            Wss { .. } => 0x01DE,
            Quic { .. } => 0x01CC,
        };
        Some(code.into())
    }
}

fn parse_onion_addr(addr: &str) -> Result<(Vec<u8>, u16)> {
    use data_encoding::BASE32;

    let mut parts = addr.split(':');
    let (hash, port) = match (parts.next(), parts.next()) {
        (Some(base_hash), Some(_)) if base_hash.len() != 16 => {
            err_at!(BadAddr, msg: format!("{}", addr))?
        }
        (Some(base_hash), Some(port)) => {
            let base_hash = base_hash.to_uppercase();
            let hash = err_at!(BadAddr, BASE32.decode(base_hash.as_bytes()))?;
            if hash.len() != 10 {
                err_at!(BadAddr, msg: format!("base_hash: {}", base_hash))?
            }
            let port: u16 = err_at!(BadAddr, port.parse())?;
            (hash, port)
        }
        (_, _) => err_at!(BadAddr, msg: format!("{}", addr))?,
    };

    if port < 1 {
        err_at!(BadAddr, msg: format!("port {}", port))?
    }

    Ok((hash, port))
}

fn parse_onion3_addr(addr: &str) -> Result<(Vec<u8>, u16)> {
    use data_encoding::BASE32;

    let mut parts = addr.split(':');
    let (hash, port) = match (parts.next(), parts.next()) {
        (Some(base_hash), Some(_)) if base_hash.len() != 56 => {
            err_at!(BadAddr, msg: format!("{}", addr))?
        }
        (Some(base_hash), Some(port)) => {
            let base_hash = base_hash.to_uppercase();
            let hash = err_at!(BadAddr, BASE32.decode(base_hash.as_bytes()))?;
            if hash.len() != 32 {
                err_at!(BadAddr, msg: format!("base_hash: {}", base_hash))?
            }
            let port: u16 = err_at!(BadAddr, port.parse())?;
            (hash, port)
        }
        (_, _) => err_at!(BadAddr, msg: format!("{}", addr))?,
    };

    if port < 1 {
        err_at!(BadAddr, msg: format!("port {}", port))?
    }
    Ok((hash, port))
}

const GARLIC64: data_encoding::Encoding = new_encoding! {
    symbols: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~",
    padding: '=',
};

fn parse_garlic64(addr: &str) -> Result<Vec<u8>> {
    // i2p base64 address will be between 516 and 616 characters long,
    // depending on certificate type
    if addr.len() < 516 || addr.len() > 616 {
        err_at!(BadAddr, msg: format!("invalid i2p addr base64 {}", addr))
    } else {
        Ok(err_at!(BadAddr, GARLIC64.decode(addr.as_bytes()))?)
    }
}

const GARLIC32: data_encoding::Encoding = new_encoding! {
    symbols: "abcdefghijklmnopqrstuvwxyz234567",
    padding: '=',
};

fn parse_garlic32(addr: &str) -> Result<Vec<u8>> {
    use std::iter::{repeat, FromIterator};

    // an i2p base32 address with a length of greater than 55
    // characters is using an Encrypted Leaseset v2. all other
    // base32 addresses will always be exactly 52 characters
    if addr.len() < 55 && addr.len() != 52 {
        err_at!(BadAddr, msg: format!("invalid i2p addr base32"))?
    } else {
        let addr = {
            let iter = repeat('=').take(8 - (addr.len() % 8));
            addr.to_string() + &String::from_iter(iter)
        };
        Ok(err_at!(BadAddr, GARLIC32.decode(addr.as_bytes()))?)
    }
}
