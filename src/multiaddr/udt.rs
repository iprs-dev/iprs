use crate::{
    multicodec::{self, Multicodec},
    Result,
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Udt;

impl Udt {
    pub(crate) fn from_text<'a, 'b>(parts: &'a [&'b str]) -> Result<(Self, &'a [&'b str])> {
        let val = (Udt, parts);
        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/udt".to_string())
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        let val = (Udt, data);
        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let data = Multicodec::from_code(multicodec::UDT)?.encode()?;
        Ok(data)
    }
}
