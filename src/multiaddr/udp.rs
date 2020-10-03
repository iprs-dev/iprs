use std::convert::TryInto;

use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Udp {
    port: u16,
    tail: Box<Multiaddr>,
}

impl Udp {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts {
            [port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                let tail = Box::new(Multiaddr::parse_text_parts(tail)?);
                Udp { port, tail }
            }
            _ => err_at!(BadAddr, msg: format!("udp {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/udp".to_string() + &self.port.to_string() + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (bs, data) = read_slice!(data, 2, "udp")?;
            let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());

            let (tail, data) = Multiaddr::decode(data)?;

            let val = Udp {
                port,
                tail: Box::new(tail),
            };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::UDP)?.encode()?;
        data.extend_from_slice(&self.port.to_be_bytes());
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
}
