// Copyright (c) 2020 R Pratap Chakravarthy

use std::{convert::TryInto, net};

use crate::multicodec::{self, Multicodec};

pub enum Multiaddr {
    IP4 {
        addr: net::Ipv4Addr,
        port: Option<Box<Multiaddr>>,
    },
    Tcp {
        port: u16,
    },
    Udp {
        port: u16,
    },
}

impl Multiaddr {
    pub fn from_text(text: &str) -> Option<Multiaddr> {
        let parts: Vec<&str> = text.split('/').collect();
        Self::parse_text_parts(&parts).map(|x| *x)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<(Multiaddr, &[u8])> {
        let (addr, byts) = Self::parse_bytes(bytes)?;
        Some((*addr, byts))
    }

    fn parse_text_parts(parts: &[&str]) -> Option<Box<Multiaddr>> {
        match parts {
            ["ipv4", addr, ..] => {
                let port = Self::parse_text_parts(&parts[2..]);
                Some(Box::new(Multiaddr::IP4 {
                    addr: addr.parse().ok()?,
                    port,
                }))
            }
            ["tcp", port] => {
                let port = port.parse().ok()?;
                Some(Box::new(Multiaddr::Tcp { port }))
            }
            ["udp", port] => {
                let port = port.parse().ok()?;
                Some(Box::new(Multiaddr::Udp { port }))
            }
            _ => None,
        }
    }

    fn parse_bytes(bytes: &[u8]) -> Option<(Box<Multiaddr>, &[u8])> {
        if bytes.len() == 0 {
            return None;
        }

        let (mcode, bs) = Multicodec::from_slice(bytes).ok()?;
        match mcode.to_code() {
            multicodec::IP4 if bs.len() >= 4 => {
                let addr = net::Ipv4Addr::new(bs[0], bs[1], bs[2], bs[3]);
                let byts = &bs[4..];
                let (port, byts) = match Self::parse_bytes(byts) {
                    Some((port, byts)) => (Some(port), byts),
                    None => (None, byts),
                };
                Some((Box::new(Multiaddr::IP4 { addr, port }), byts))
            }
            multicodec::TCP if bs.len() >= 2 => {
                let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
                Some((Box::new(Multiaddr::Tcp { port }), &bs[2..]))
            }
            multicodec::UDP if bs.len() >= 2 => {
                let port = u16::from_be_bytes(bs[..2].try_into().unwrap());
                Some((Box::new(Multiaddr::Udp { port }), &bs[2..]))
            }
            _ => None,
        }
    }
}
