use std::convert::TryInto;

use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Tcp {
    port: u16,
}

impl From<u16> for Tcp {
    fn from(port: u16) -> Self {
        Tcp { port }
    }
}

impl Tcp {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [port, tail @ ..] => {
                let port: u16 = err_at!(BadAddr, port.parse())?;
                (Tcp { port }, tail)
            }
            _ => err_at!(BadAddr, msg: "tcp {:?}", parts)?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/tcp".to_string() + &self.port.to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (bs, data) = read_slice!(data, 2, "tcp")?;
            let port: u16 = u16::from_be_bytes(bs.try_into().unwrap());

            let val = Tcp { port };

            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = Multicodec::from_code(multicodec::TCP)?.encode()?;
        data.extend_from_slice(&self.port.to_be_bytes());
        Ok(data)
    }

    pub(crate) fn to_port(&self) -> u16 {
        self.port
    }
}
