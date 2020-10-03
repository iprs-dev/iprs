use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Garlic64 {
    addr: Vec<u8>,
    tail: Box<Multiaddr>,
}

impl Garlic64 {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts {
            [addr, tail @ ..] => {
                let addr = parse_garlic64(addr)?;
                let tail = Box::new(Multiaddr::parse_text_parts(tail)?);
                Garlic64 { addr, tail }
            }
            _ => err_at!(BadAddr, msg: format!("garlic64 {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        let s = "/garlic64".to_string() + &to_garlic64(&self.addr)?;
        Ok(s + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (addr, data) = {
                let (n, data) = err_at!(DecodeError, uv_decode(data))?;
                let (name, data) = read_slice!(data, (n as usize), "garlic64")?;
                (name.to_vec(), data)
            };

            let (tail, data) = Multiaddr::decode(data)?;

            let val = Garlic64 {
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

        let mut data = Multicodec::from_code(multicodec::GARLIC64)?.encode()?;
        data.extend_from_slice(uv_encode(self.addr.len() as u128, &mut buf));
        data.extend_from_slice(&self.addr);
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
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
