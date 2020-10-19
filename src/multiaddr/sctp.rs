use std::convert::TryInto;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Sctp {
    port: u16,
}

impl Sctp {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                (Sctp { port }, tail)
            }
            _ => err_at!(BadAddr, msg: "sctp {:?}", parts)?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/sctp".to_string() + &self.port.to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (bs, data) = read_slice!(data, 2, "sctp")?;
            let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());

            let val = Sctp { port };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::SCTP)?.encode()?;
        data.extend_from_slice(&self.port.to_be_bytes());
        Ok(data)
    }
}
