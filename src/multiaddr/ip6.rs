use std::net;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Ip6 {
    addr: net::Ipv6Addr,
}

impl Ip6 {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [addr, tail @ ..] => {
                let addr: net::Ipv6Addr = err_at!(BadAddr, addr.parse())?;
                (Ip6 { addr }, tail)
            }
            _ => err_at!(BadAddr, msg: format!("ip6 {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/ip6".to_string() + &self.addr.to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (bs, data) = read_slice!(data, 16, "ip6")?;
            let addr: net::Ipv6Addr = {
                let mut addr = [0_u8; 16];
                addr.copy_from_slice(bs);
                addr.into()
            };

            let val = Ip6 { addr };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::IP6)?.encode()?;
        data.extend_from_slice(&self.addr.octets());
        Ok(data)
    }
}
