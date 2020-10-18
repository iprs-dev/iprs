//! Module implement the data-model for IPLD.

use std::collections::HashMap;

use crate::{cid::Cid};

pub enum Kind {
    Null,
    Bool(bool),
    Integer(i128),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Link(Cid),
    List(Vec<Kind>),
    Dict(HashMap<String, Kind>),
}

impl TryFrom<Cbor> for Kind {
    type Error = Error;

    fn try_from(val: Cbor) -> Result<Kind> {
        use crate::ipld::cbor::Cbor::*;
        use Kind::*;

        let kind = match val {
            Major0(info, num) => Integer(num.into()),
            Major1(info, num) => Integer(-(i128::from(num) + 1)),
            Major2(info, byts) => Bytes(bytes)
            Major3(info, text) => Text(text)
            Major4(info, list) => {
                let iter = list.into_iter().map(Kind::from);
                List(iter.collect())
            }
            Major5(info, dict) => {
                let iter = dict.into_iter().map(|(k, v)| (k, Kind::from(v)));
                Dict(HashMap::from_iter(iter))
            }
            Major6(info, Tag::Link(cid)) => Link(cid),
            Major7(info, SimpleValue::Unassigned) => {
                let prefix = format!("{}:{}", file!(), line!());
                let msg = "unassigned simple-value".to_string();
                Err(Error::DecodeError(prefix, msg))?
            }
            Major7(info, SimpleValue::True) => Bool(true),
            Major7(info, SimpleValue::False) => Bool(false),
            Major7(info, SimpleValue::Null) => Null,
            Major7(info, SimpleValue::Undefined) => {
                let prefix = format!("{}:{}", file!(), line!());
                let msg = "undefined simple-value".to_string();
                Err(Error::DecodeError(prefix, msg))?
            }
            Major7(info, SimpleValue::F16(_)) => {
                let prefix = format!("{}:{}", file!(), line!());
                let msg = "half-precision not supported".to_string();
                Err(Error::DecodeError(prefix, msg))?
            }
            Major7(info, SimpleValue::F32(val)) => Float(val as f64),
            Major7(info, SimpleValue::F64(val)) => Float(val),
            Major7(info, SimpleValue::Break) => {
                let prefix = format!("{}:{}", file!(), line!());
                let msg = "indefinite length not supported".to_string();
                Err(Error::DecodeError(prefix, msg))?
            }
        };

        Ok(kind)
    }
}
