use std::convert::TryInto;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Onion {
    hash: Vec<u8>,
    port: u16,
}

impl Onion {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [addr, tail @ ..] => {
                let (hash, port) = parse_onion_addr(addr)?;
                (Onion { hash, port }, tail)
            }
            _ => err_at!(BadAddr, msg: "onion {:?}", parts)?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/onion".to_string() + &to_onion_text(&self.hash, self.port)?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (hash, data) = read_slice!(data, 10, "onion-addr")?;
            let (port, data) = {
                let (bs, data) = read_slice!(data, 2, "onion-port")?;
                let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());
                (port, data)
            };

            let val = Onion {
                hash: hash.to_vec(),
                port,
            };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::ONION)?.encode()?;
        data.extend_from_slice(&self.hash);
        data.extend_from_slice(&self.port.to_be_bytes());
        Ok(data)
    }
}

fn parse_onion_addr(addr: &str) -> Result<(Vec<u8>, u16)> {
    use data_encoding::BASE32;

    let mut parts = addr.split(':');
    let (hash, port) = match (parts.next(), parts.next()) {
        (Some(base_hash), Some(_)) if base_hash.len() != 16 => err_at!(BadAddr, msg: "{}", addr)?,
        (Some(base_hash), Some(port)) => {
            let base_hash = base_hash.to_uppercase();
            let hash = err_at!(BadAddr, BASE32.decode(base_hash.as_bytes()))?;
            if hash.len() != 10 {
                err_at!(BadAddr, msg: "base_hash: {}", base_hash)?
            }
            let port: u16 = err_at!(BadAddr, port.parse())?;
            (hash, port)
        }
        (_, _) => err_at!(BadAddr, msg: "{}", addr)?,
    };

    if port < 1 {
        err_at!(BadAddr, msg: "port {}", port)?
    }

    Ok((hash, port))
}

fn to_onion_text(hash: &[u8], port: u16) -> Result<String> {
    use data_encoding::BASE32;

    let s = BASE32.encode(&hash) + ":" + &port.to_string();
    Ok(s)
}
