use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Ws {
    tail: Box<Multiaddr>,
}

impl Ws {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts.len() {
            n if n > 0 => {
                let tail = Box::new(Multiaddr::parse_text_parts(parts)?);
                Ws { tail }
            }
            _ => Ws {
                tail: Box::new(Multiaddr::None),
            },
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/ws".to_string() + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (tail, data) = Multiaddr::decode(data)?;
            let val = Ws {
                tail: Box::new(tail),
            };
            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = {
            let codec = Multicodec::from_code(multicodec::WS)?;
            codec.encode()?
        };
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
}
