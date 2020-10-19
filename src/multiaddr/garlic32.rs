use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Garlic32 {
    addr: Vec<u8>,
}

impl Garlic32 {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [addr, tail @ ..] => {
                let addr = parse_garlic32(addr)?;
                (Garlic32 { addr }, tail)
            }
            _ => err_at!(BadAddr, msg: "garlic32 {:?}", parts)?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/garlic32".to_string() + &to_garlic32(&self.addr)?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (addr, data) = {
                let (n, data) = err_at!(DecodeError, uv_decode(data))?;
                let (name, data) = read_slice!(data, (n as usize), "garlic32")?;
                (name.to_vec(), data)
            };

            let val = Garlic32 { addr };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        use unsigned_varint::encode::u128 as uv_encode;

        let mut buf = [0_u8; 19];

        let mut data = Multicodec::from_code(multicodec::GARLIC32)?.encode()?;
        data.extend_from_slice(uv_encode(self.addr.len() as u128, &mut buf));
        data.extend_from_slice(&self.addr);
        Ok(data)
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
        err_at!(BadAddr, msg: "invalid i2p addr base32")?
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
