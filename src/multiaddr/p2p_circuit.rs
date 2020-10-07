use crate::{
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct P2pCircuit;

impl P2pCircuit {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = (P2pCircuit, parts);
        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/p2p-circuit".to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = (P2pCircuit, data);
        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let data = Multicodec::from_code(multicodec::P2P_CIRCUIT)?.encode()?;
        Ok(data)
    }
}
