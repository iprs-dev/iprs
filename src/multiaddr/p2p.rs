use crate::{
    multicodec::{self, Multicodec},
    peer_id::PeerId,
    Error, Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct P2p {
    peer_id: PeerId,
}

impl P2p {
    pub(crate) fn new(peer_id: PeerId) -> Self {
        P2p { peer_id }
    }

    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = match parts {
            [addr, tail @ ..] => {
                let peer_id = PeerId::from_text(addr)?;
                (P2p { peer_id }, tail)
            }
            _ => err_at!(BadAddr, msg: format!("p2p {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/p2p".to_string() + &self.peer_id.to_base58btc()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (addr, data) = {
                let (n, data) = err_at!(DecodeError, uv_decode(data))?;
                read_slice!(data, (n as usize), "p2p")?
            };
            let (peer_id, _) = PeerId::decode(addr)?;

            let val = P2p { peer_id };
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
        Ok(data)
    }

    pub(crate) fn to_peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }
}
