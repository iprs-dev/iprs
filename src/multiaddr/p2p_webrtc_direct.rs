use crate::{
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct P2pWebRtcDirect {
    tail: Box<Multiaddr>,
}

impl P2pWebRtcDirect {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts.len() {
            n if n > 0 => {
                let tail = Box::new(Multiaddr::parse_text_parts(parts)?);
                P2pWebRtcDirect { tail }
            }
            _ => P2pWebRtcDirect {
                tail: Box::new(Multiaddr::None),
            },
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/p2p-webrtc-direct".to_string() + &self.tail.to_text()?)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = {
            let (tail, data) = Multiaddr::decode(data)?;
            let val = P2pWebRtcDirect {
                tail: Box::new(tail),
            };
            (val, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut data = {
            let codec = Multicodec::from_code(multicodec::P2P_WEBRTC_DIRECT)?;
            codec.encode()?
        };
        data.extend_from_slice(&self.tail.encode()?);
        Ok(data)
    }
}
