use crate::{
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Wss;

impl Wss {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = (Wss, parts);
        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/wss".to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = (Wss, data);
        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let data = Multicodec::from_code(multicodec::WSS)?.encode()?;
        Ok(data)
    }
}
