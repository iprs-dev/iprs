// Copyright (c) 2020 R Pratap Chakravarthy

use std::{convert::TryInto, net};

use crate::multicodec::{self, Multicodec};

pub enum Multiaddr {
    IP4 {
        addr: net::Ipv4Addr,
        prot: Option<Box<Multiaddr>>,
    },
    Tcp {
        port: u16,
    },
    Udp {
        port: u16,
        prot: Option<Box<Multiaddr>>,
    },
    Quic,
}

impl Multiaddr {
    pub fn from_text(text: &str) -> Option<Multiaddr> {
        let parts: Vec<&str> = text.split('/').collect();
        Self::parse_text_parts(&parts).map(|x| *x)
    }

    fn parse_text_parts(parts: &[&str]) -> Option<Box<Multiaddr>> {
        match parts {
            ["ipv4", addr, ..] => {
                let prot = Self::parse_text_parts(&parts[2..]);
                Some(Box::new(Multiaddr::IP4 {
                    addr: addr.parse().ok()?,
                    prot,
                }))
            }
            ["tcp", port] => {
                let port = port.parse().ok()?;
                Some(Box::new(Multiaddr::Tcp { port }))
            }
            ["udp", port] => {
                let port = port.parse().ok()?;
                let prot = None;
                Some(Box::new(Multiaddr::Udp { port, prot }))
            }
            ["udp", port, ..] => {
                let port = port.parse().ok()?;
                let prot = Self::parse_text_parts(&parts[3..]);
                Some(Box::new(Multiaddr::Udp { port, prot }))
            }
            ["quic"] => Some(Box::new(Multiaddr::Quic)),
            _ => None,
        }
    }

    pub fn decode(bytes: &[u8]) -> Option<(Multiaddr, &[u8])> {
        let (addr, byts) = Self::do_decode(bytes)?;
        Some((*addr, byts))
    }

    fn do_decode(bytes: &[u8]) -> Option<(Box<Multiaddr>, &[u8])> {
        if bytes.len() == 0 {
            return None;
        }

        let (mcode, bs) = Multicodec::decode(bytes).ok()?;
        match mcode.to_code() {
            multicodec::IP4 if bs.len() >= 4 => {
                let addr = net::Ipv4Addr::new(bs[0], bs[1], bs[2], bs[3]);
                let byts = &bs[4..];
                let (prot, byts) = match Self::do_decode(byts) {
                    Some((prot, byts)) => (Some(prot), byts),
                    None => (None, byts),
                };
                Some((Box::new(Multiaddr::IP4 { addr, prot }), byts))
            }
            multicodec::TCP if bs.len() >= 2 => {
                let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
                Some((Box::new(Multiaddr::Tcp { port }), &bs[2..]))
            }
            multicodec::UDP if bs.len() >= 2 => {
                let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
                let (prot, bytes) = match Self::do_decode(&bs[2..]) {
                    Some((prot, bytes)) => (Some(prot), bytes),
                    None => (None, &bs[2..]),
                };
                Some((Box::new(Multiaddr::Udp { port, prot }), bytes))
            }
            multicodec::QUIC => Some((Box::new(Multiaddr::Quic), bs)),
            _ => None,
        }
    }
}
