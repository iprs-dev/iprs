//! Module implement the data-model for IPLD.

use std::{collections::BTreeMap, convert::TryFrom};

use crate::{cid::Cid, ipld::cbor::Cbor, Error, Result};

// NOTE: Operational behaviour on data.
//
// * Serialization and De-serialization.
// * Hash-digest on serialized block.
// * Schema-matching on deserialized kind.
// * Indexing operation within list and map kinds.

pub enum Kind {
    Null,
    Bool(bool),
    Integer(i128), // TODO: i128 might an overkill, 8 more bytes than 64-bit !!
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Link(Cid),
    List(Vec<Kind>),
    Dict(BTreeMap<String, Kind>),
}

impl TryFrom<Cbor> for Kind {
    type Error = Error;

    fn try_from(val: Cbor) -> Result<Kind> {
        use crate::ipld::cbor::{self, Cbor::*};
        use Kind::*;

        let kind = match val {
            Major0(_, num) => Integer(num.into()),
            Major1(_, num) => Integer(-(i128::from(num) + 1)),
            Major2(_, byts) => Bytes(byts),
            Major3(_, text) => Text(text),
            Major4(_, list) => {
                let mut klist = vec![];
                for item in list.into_iter() {
                    klist.push(Kind::try_from(item)?);
                }
                List(klist)
            }
            Major5(_, dict) => {
                let mut kdict: BTreeMap<String, Kind> = BTreeMap::new();
                for (k, v) in dict.into_iter() {
                    kdict.insert(k, Kind::try_from(v)?);
                }
                Dict(kdict)
            }
            Major6(_, cbor::Tag::Link(cid)) => Link(cid),
            Major7(_, cbor::SimpleValue::Unassigned) => {
                err_at!(FailConvert, msg: "unassigned simple-value")?
            }
            Major7(_, cbor::SimpleValue::True) => Bool(true),
            Major7(_, cbor::SimpleValue::False) => Bool(false),
            Major7(_, cbor::SimpleValue::Null) => Null,
            Major7(_, cbor::SimpleValue::Undefined) => {
                err_at!(FailConvert, msg: "undefined simple-value")?
            }
            Major7(_, cbor::SimpleValue::Reserved24(_)) => {
                err_at!(FailConvert, msg: "single byte simple-value")?
            }
            Major7(_, cbor::SimpleValue::F16(_)) => {
                err_at!(FailConvert, msg: "half-precision not supported")?
            }
            Major7(_, cbor::SimpleValue::F32(val)) => Float(val as f64),
            Major7(_, cbor::SimpleValue::F64(val)) => Float(val),
            Major7(_, cbor::SimpleValue::Break) => {
                err_at!(FailConvert, msg: "indefinite length not supported")?
            }
        };

        Ok(kind)
    }
}
