use std::str::FromStr;

use crate::{Error, Result};

#[derive(Debug)]
pub enum Token {
    Newline(String),
}

#[derive(Debug)]
pub enum Scalar {
    Str,
}

#[derive(Debug)]
pub enum Kind {
    Str,
}

impl From<Scalar> for Kind {
    fn from(val: Scalar) -> Kind {
        match val {
            Scalar::Str => Kind::Str,
        }
    }
}

#[derive(Debug)]
pub struct Type {
    name: String,
    kind: Kind,
}

impl From<(String, Kind)> for Type {
    fn from((name, kind): (String, Kind)) -> Type {
        Type { name, kind }
    }
}

#[derive(Debug)]
pub enum Record {
    Type(Type),
}

impl From<Type> for Record {
    fn from(val: Type) -> Record {
        Record::Type(val)
    }
}

#[derive(Debug)]
pub struct Records(Vec<Record>);

impl From<Vec<Record>> for Records {
    fn from(arr: Vec<Record>) -> Self {
        Records(arr)
    }
}
