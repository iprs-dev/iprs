use std::net;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Ip4 {
    addr: net::Ipv4Addr,
}

impl From<net::Ipv4Addr> for Ip4 {
    fn from(addr: net::Ipv4Addr) -> Self {
        Ip4 { addr }
    }
}

impl Ip4 {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [addr, tail @ ..] => {
                let addr: net::Ipv4Addr = err_at!(BadAddr, addr.parse())?;
                (Ip4 { addr }, tail)
            }
            _ => err_at!(BadAddr, msg: format!("ip4 {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/ip4".to_string() + &self.addr.to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (bs, data) = read_slice!(data, 4, "ip4")?;
            let addr = net::Ipv4Addr::new(bs[0], bs[1], bs[2], bs[3]);

            let val = Ip4 { addr };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::IP4)?.encode()?;
        data.extend_from_slice(&self.addr.octets());
        Ok(data)
    }

    pub(crate) fn to_addr(&self) -> net::Ipv4Addr {
        self.addr.clone()
    }
}
