use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    peer_id::PeerId,
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct P2p {
    peer_id: PeerId,
    tail: Box<Multiaddr>,
}

impl P2p {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts {
            [addr, tail @ ..] => {
                let peer_id = PeerId::from_text(addr)?;
                let tail = Box::new(Multiaddr::parse_text_parts(tail)?);
                P2p { peer_id, tail }
            }
            _ => err_at!(BadAddr, msg: format!("p2p {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        let s = "/p2p".to_string() + &self.peer_id.to_base58btc()?;
        Ok(s + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (addr, data) = {
                let (n, data) = err_at!(DecodeError, uv_decode(data))?;
                read_slice!(data, (n as usize), "p2p")?
            };
            let (peer_id, _) = PeerId::decode(addr)?;

            let (tail, data) = Multiaddr::decode(data)?;

            let val = P2p {
                peer_id,
                tail: Box::new(tail),
            };
            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        use unsigned_varint::encode::u128 as uv_encode;

        let mut buf = [0_u8; 19];

        let addr = self.peer_id.encode()?;

        let mut data = Multicodec::from_code(multicodec::P2P)?.encode()?;
        data.extend_from_slice(uv_encode(addr.len() as u128, &mut buf));
        data.extend_from_slice(&addr);
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
}
