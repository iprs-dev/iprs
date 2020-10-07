use crate::{
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct P2pWebRtcDirect;

impl P2pWebRtcDirect {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = (P2pWebRtcDirect, parts);
        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/p2p-webrtc-direct".to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = (P2pWebRtcDirect, data);
        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let data = {
            let codec = Multicodec::from_code(multicodec::P2P_WEBRTC_DIRECT)?;
            codec.encode()?
        };
        Ok(data)
    }
}
