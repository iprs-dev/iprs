//! Module implement the data-model for IPLD.

use std::collections::HashMap;

use crate::cid::Cid;

pub enum Link {
    Cid(Cid),
}

pub enum Kind {
    Null,
    Boolean(bool),
    Integer(i128),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Link(Link),
    List(Vec<Kind>),
    Map(HashMap<String, Kind>),
}
