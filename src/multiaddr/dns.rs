use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Dns {
    addr: Vec<u8>,
    tail: Box<Multiaddr>,
}

impl Dns {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts {
            [addr, tail @ ..] => {
                let addr = addr.as_bytes().to_vec();
                let tail = Box::new(Multiaddr::parse_text_parts(tail)?);
                Dns { addr, tail }
            }
            _ => err_at!(BadAddr, msg: format!("dns {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        use std::str::from_utf8;

        let s = "/dns".to_string();
        let s = s + &err_at!(DecodeError, from_utf8(&self.addr))?;
        Ok(s + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (addr, data) = {
                let (n, data) = err_at!(DecodeError, uv_decode(data))?;
                let (name, data) = read_slice!(data, (n as usize), "dns")?;
                (name.to_vec(), data)
            };
            let (tail, data) = Multiaddr::decode(data)?;

            let val = Dns {
                addr,
                tail: Box::new(tail),
            };
            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        use unsigned_varint::encode::u128 as uv_encode;

        let mut buf = [0_u8; 19];

        let mut data = Multicodec::from_code(multicodec::DNS)?.encode()?;
        data.extend_from_slice(uv_encode(self.addr.len() as u128, &mut buf));
        data.extend_from_slice(&self.addr);
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
}
