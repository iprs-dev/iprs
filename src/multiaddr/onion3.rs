use std::convert::TryInto;

use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Onion3 {
    hash: Vec<u8>,
    port: u16,
    tail: Box<Multiaddr>,
}

impl Onion3 {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts {
            [addr, tail @ ..] => {
                let (hash, port) = parse_onion3_addr(addr)?;
                let tail = Box::new(Multiaddr::parse_text_parts(tail)?);
                Onion3 { hash, port, tail }
            }
            _ => err_at!(BadAddr, msg: format!("onion3 {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        let s = "/onion3".to_string() + &to_onion3_text(&self.hash, self.port)?;
        Ok(s + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (hash, data) = read_slice!(data, 35, "onion3-addr")?;
            let (port, data) = {
                let (bs, data) = read_slice!(data, 2, "onion3-port")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                (port, data)
            };

            let (tail, data) = Multiaddr::decode(data)?;

            let val = Onion3 {
                hash: hash.to_vec(),
                port,
                tail: Box::new(tail),
            };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::ONION3)?.encode()?;
        data.extend_from_slice(&self.hash);
        data.extend_from_slice(&self.port.to_be_bytes());
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
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
