// Copyright (c) 2020 R Pratap Chakravarthy

use std::{convert::TryInto, net};

use crate::{
    multicodec::{self, Multicodec},
    peer_id::PeerId,
    Error, Result,
};

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

/// Multiaddr type, either as binary encoded data or as one of
/// many multiaddr values, like Ip4, Tcp, Udp, Quic etc..
#[derive(Clone, Eq, PartialEq)]
pub enum Multiaddr {
    Text {
        text: String,
    },
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
        peer_id: PeerId,
        mddr: Option<Box<Multiaddr>>,
    },
    Ipfs {
        peer_id: PeerId,
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
                let peer_id = PeerId::from_text(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2p { peer_id, mddr }
            }
            ["ipfs", addr, tail @ ..] => {
                let peer_id = PeerId::from_text(addr)?;
                let mddr = Some(Box::new(Self::parse_text_parts(tail)?));
                Multiaddr::P2p { peer_id, mddr }
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
        use std::str::from_utf8;
        use Multiaddr::*;

        let tail_text = |ma: Option<&Box<Multiaddr>>| -> Result<String> {
            let val = match ma {
                Some(ma) => ma.to_text()?,
                None => "".to_string(),
            };

            Ok(val)
        };

        let text = match self {
            Text { text } => text.clone(),
            Binary { data } => {
                let (maddr, _) = Self::decode(&data)?;
                maddr.to_text()?
            }
            Ip4 { addr, mddr } => {
                let s = "/ip4".to_string() + &addr.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Ip6 { addr, mddr } => {
                let s = "/ip6".to_string() + &addr.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Tcp { port, mddr } => {
                let s = "/tcp".to_string() + &port.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Dns { addr, mddr } => {
                let s = "/dns".to_string();
                let s = s + &err_at!(DecodeError, from_utf8(addr))?;
                s + &tail_text(mddr.as_ref())?
            }
            Dns4 { addr, mddr } => {
                let s = "/dns4".to_string();
                let s = s + &err_at!(DecodeError, from_utf8(addr))?;
                s + &tail_text(mddr.as_ref())?
            }
            Dns6 { addr, mddr } => {
                let s = "/dns6".to_string();
                let s = s + &err_at!(DecodeError, from_utf8(addr))?;
                s + &tail_text(mddr.as_ref())?
            }
            Dnsaddr { addr, mddr } => {
                let s = "/dnsaddr".to_string();
                let s = s + &err_at!(DecodeError, from_utf8(addr))?;
                s + &tail_text(mddr.as_ref())?
            }
            Udp { port, mddr } => {
                let s = "/udp".to_string() + &port.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Dccp { port, mddr } => {
                let s = "/dccp".to_string() + &port.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Ip6zone { addr, mddr } => {
                let s = "/ip6zone".to_string();
                let s = s + &err_at!(DecodeError, from_utf8(addr))?;
                s + &tail_text(mddr.as_ref())?
            }
            Sctp { port, mddr } => {
                let s = "/sctp".to_string() + &port.to_string();
                s + &tail_text(mddr.as_ref())?
            }
            P2pCircuit { mddr } => {
                let s = "/p2p-circuit".to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Onion { hash, port, mddr } => {
                let s = "/onion".to_string() + &to_onion_text(hash, *port)?;
                s + &tail_text(mddr.as_ref())?
            }
            Onion3 { hash, port, mddr } => {
                let s = "/onion".to_string() + &to_onion3_text(hash, *port)?;
                s + &tail_text(mddr.as_ref())?
            }
            Garlic64 { addr, mddr } => {
                let s = "/garlic64".to_string() + &to_garlic64(addr)?;
                s + &tail_text(mddr.as_ref())?
            }
            Garlic32 { addr, mddr } => {
                let s = "/garlic32".to_string() + &to_garlic32(addr)?;
                s + &tail_text(mddr.as_ref())?
            }
            P2p { peer_id, mddr } => {
                let s = "/p2p".to_string() + &peer_id.to_base58btc()?;
                s + &tail_text(mddr.as_ref())?
            }
            Ipfs { peer_id, mddr } => {
                let s = "/p2p".to_string() + &peer_id.to_base58btc()?;
                s + &tail_text(mddr.as_ref())?
            }
            Unix { path } => "/unix".to_string() + &path,
            Udt { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            Utp { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            Http { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            Https { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            P2pWebRtcDirect { mddr } => {
                let s = "/udt".to_string();
                s + &tail_text(mddr.as_ref())?
            }
            Ws { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            Wss { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
            Quic { mddr } => "/udt".to_string() + &tail_text(mddr.as_ref())?,
        };

        Ok(text)
    }

    pub fn decode(data: &[u8]) -> Result<(Multiaddr, &[u8])> {
        use std::str::from_utf8;
        use unsigned_varint::decode as uv_decode;

        let (codec, data) = Multicodec::decode(data)?;

        let (ma, data) = match codec.to_code() {
            multicodec::IP4 if data.len() >= 4 => {
                let (bs, data) = read_slice!(data, 4, "ip4")?;
                let addr = net::Ipv4Addr::new(bs[0], bs[1], bs[2], bs[3]);
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Ip4 {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::IP6 => {
                let (bs, data) = read_slice!(data, 16, "ip6")?;
                let addr: net::Ipv6Addr = {
                    let mut addr = [0_u8; 16];
                    addr.copy_from_slice(bs);
                    addr.into()
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Ip6 {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::TCP => {
                let (bs, data) = read_slice!(data, 2, "tcp")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Tcp {
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::DNS => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "dns")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Dns {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::DNS4 => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "dns4")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Dns {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::DNS6 => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "dns6")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Dns {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::DNSADDR => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "dnsaddr")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Dns {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::UDP => {
                let (bs, data) = read_slice!(data, 2, "udp")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Udp {
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::DCCP => {
                let (bs, data) = read_slice!(data, 2, "dccp")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Udp {
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::IP6ZONE => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "ip6zone")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Ip6zone {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::SCTP => {
                let (bs, data) = read_slice!(data, 2, "sctp")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Sctp {
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::P2P_CIRCUIT => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::P2pCircuit {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::ONION => {
                let (hash, data) = read_slice!(data, 10, "onion-addr")?;
                let (port, data) = {
                    let (bs, data) = read_slice!(data, 2, "onion-port")?;
                    let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                    (port, data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Onion {
                        hash: hash.to_vec(),
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::ONION3 => {
                let (hash, data) = read_slice!(data, 35, "onion3-addr")?;
                let (port, data) = {
                    let (bs, data) = read_slice!(data, 2, "onion3-port")?;
                    let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                    (port, data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Onion {
                        hash: hash.to_vec(),
                        port,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::GARLIC64 => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "garlic64")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Garlic64 {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::GARLIC32 => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    let (name, data) = read_slice!(data, (n as usize), "garlic32")?;
                    (name.to_vec(), data)
                };
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Garlic64 {
                        addr,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::P2P => {
                let (addr, data) = {
                    let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                    read_slice!(data, (n as usize), "p2p")?
                };
                let (peer_id, _) = PeerId::decode(addr)?;
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::P2p {
                        peer_id,
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::UNIX => {
                let (n, data) = err_at!(DecodeError, uv_decode::u128(data))?;
                let (path, data) = read_slice!(data, (n as usize), "unix")?;
                let path = err_at!(DecodeError, from_utf8(path))?.to_string();
                (Multiaddr::Unix { path }, data)
            }
            multicodec::UTP => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Utp {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::UDT => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Udt {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::QUIC => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Quic {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::HTTP => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Http {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::HTTPS => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Https {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::P2P_WEBRTC_DIRECT => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::P2pWebRtcDirect {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::WS => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Ws {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            multicodec::WSS => {
                let (mddr, data) = Self::decode(data)?;
                (
                    Multiaddr::Wss {
                        mddr: Some(Box::new(mddr)),
                    },
                    data,
                )
            }
            code => err_at!(DecodeError, msg: format!("invalid code {}", code))?,
        };

        Ok((ma, data))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        use unsigned_varint::encode::u128 as uv_encode;
        use Multiaddr::*;

        let mut buf = [0_u8; 19];

        let tail_bytes = |ma: Option<&Box<Multiaddr>>| -> Result<Vec<u8>> {
            let val = match ma {
                Some(ma) => ma.encode()?,
                None => vec![],
            };

            Ok(val)
        };

        let data = match self {
            Text { text } => Self::from_text(text)?.encode()?,
            Binary { data } => data.clone(),
            Ip4 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::IP4)?.encode()?;
                data.extend_from_slice(&addr.octets());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Ip6 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::IP6)?.encode()?;
                data.extend_from_slice(&addr.octets());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Tcp { port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::TCP)?.encode()?;
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Dns { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::DNS)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Dns4 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::DNS4)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Dns6 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::DNS6)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Dnsaddr { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::DNSADDR)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Udp { port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::UDP)?.encode()?;
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Dccp { port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::DCCP)?.encode()?;
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Ip6zone { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::IP6ZONE)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Sctp { port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::SCTP)?.encode()?;
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            P2pCircuit { mddr } => {
                let mut data = Multicodec::from_code(multicodec::P2P_CIRCUIT)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Onion { hash, port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::ONION)?.encode()?;
                data.extend_from_slice(&hash);
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Onion3 { hash, port, mddr } => {
                let mut data = Multicodec::from_code(multicodec::ONION3)?.encode()?;
                data.extend_from_slice(&hash);
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Garlic64 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::GARLIC64)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Garlic32 { addr, mddr } => {
                let mut data = Multicodec::from_code(multicodec::GARLIC32)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            P2p { peer_id, mddr } => {
                let addr = peer_id.encode()?;

                let mut data = Multicodec::from_code(multicodec::P2P)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Ipfs { peer_id, mddr } => {
                let addr = peer_id.encode()?;

                let mut data = Multicodec::from_code(multicodec::P2P)?.encode()?;
                data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
                data.extend_from_slice(&addr);
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Unix { path } => {
                let mut data = Multicodec::from_code(multicodec::UNIX)?.encode()?;
                data.extend_from_slice(uv_encode(path.len() as u128, &mut buf));
                data.extend_from_slice(path.as_bytes());
                data
            }
            Udt { mddr } => {
                let mut data = Multicodec::from_code(multicodec::UDT)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Utp { mddr } => {
                let mut data = Multicodec::from_code(multicodec::UTP)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Http { mddr } => {
                let mut data = Multicodec::from_code(multicodec::HTTP)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Https { mddr } => {
                let mut data = Multicodec::from_code(multicodec::HTTPS)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Quic { mddr } => {
                let mut data = Multicodec::from_code(multicodec::QUIC)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            P2pWebRtcDirect { mddr } => {
                let mut data = Multicodec::from_code(multicodec::P2P_WEBRTC_DIRECT)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Ws { mddr } => {
                let mut data = Multicodec::from_code(multicodec::WS)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
            Wss { mddr } => {
                let mut data = Multicodec::from_code(multicodec::WSS)?.encode()?;
                data.extend_from_slice(&tail_bytes(mddr.as_ref())?);
                data
            }
        };

        Ok(data)
    }
}

impl Multiaddr {
    pub fn to_multicodec(&self) -> Option<Multicodec> {
        use Multiaddr::*;

        let code = match self {
            Text { .. } => return None,
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

fn to_onion_text(hash: &[u8], port: u16) -> Result<String> {
    use data_encoding::BASE32;

    let s = BASE32.encode(&hash) + ":" + &port.to_string();
    Ok(s)
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
            if hash.len() != 35 {
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

fn to_onion3_text(hash: &[u8], port: u16) -> Result<String> {
    use data_encoding::BASE32;

    let s = BASE32.encode(&hash) + ":" + &port.to_string();
    Ok(s)
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

fn to_garlic64(addr: &[u8]) -> Result<String> {
    Ok(GARLIC64.encode(addr))
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

fn to_garlic32(addr: &[u8]) -> Result<String> {
    Ok(GARLIC32.encode(addr))
}
