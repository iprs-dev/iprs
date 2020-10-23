//! Module implement the data-model for IPLD.

use std::{cmp, collections::BTreeMap, convert::TryFrom, fmt, result};

use crate::{cid::Cid, ipld::cbor::Cbor, Error, Result};

/// Every thing is a Node, almost.
pub trait Node {
    fn as_key(&self) -> Option<Key>;

    /// return the kind.
    fn to_kind(&self) -> Kind;

    /// use key as index within the container.
    fn get(&self, key: &Key) -> Result<&dyn Node>;

    /// set (key, value) within the container, using key as the index,
    /// and, return a new mutated version of node.
    fn set(&self, key: &Key, value: Box<dyn Node>) -> Result<Box<dyn Node>>;

    /// delete the entry identified by key within the container, and,
    /// return a new mutated version of node.
    fn delete(&self, key: &Key) -> Result<Box<dyn Node>>;

    /// iterate over values.
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &dyn Node> + 'a>;

    /// iterate over (key, value) entry, in case of list key is index
    /// offset of value within the list.
    fn iter_entries<'a>(&'a self) -> Box<dyn Iterator<Item = (Key, &dyn Node)> + 'a>;

    /// if kind is container type, return the length.
    fn len(&self) -> Option<usize>;

    fn is_null(&self) -> bool;

    fn to_bool(&self) -> Option<bool>;

    fn to_integer(&self) -> Option<i128>;

    fn to_float(&self) -> Option<f64>;

    fn as_string(&self) -> Option<Result<&str>>;

    fn as_ffi_string(&self) -> Option<&str>;

    fn as_bytes(&self) -> Option<&[u8]>;

    fn as_link(&self) -> Option<&Cid>;
}

/// A subset of Basic, that can be used to index into recursive type, like
/// list and map. Can be seen as the path-segment.
pub enum Key {
    Bool(bool),
    Offset(usize),
    Text(String),
    Bytes(Vec<u8>),
    Keyable(Box<dyn ToString>),
}

impl Clone for Key {
    fn clone(&self) -> Self {
        match self {
            val @ Key::Bool(_) => val.clone(),
            val @ Key::Offset(_) => val.clone(),
            val @ Key::Text(_) => val.clone(),
            val @ Key::Bytes(_) => val.clone(),
            Key::Keyable(val) => Key::Keyable(Box::new(val.to_string())),
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        use Key::*;

        match self {
            Bool(val) => write!(f, "key-bool-{}", val),
            Offset(val) => write!(f, "key-off-{}", val),
            Text(val) => write!(f, "key-str-{}", val),
            Bytes(val) => write!(f, "key-bytes-{:?}", val), // TODO: use base64 encoding.
            Keyable(val) => write!(f, "key-key-{}", val.to_string()),
        }
    }
}

impl Eq for Key {}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        use Key::*;

        match (self, other) {
            (Bool(a), Bool(b)) => a == b,
            (Offset(a), Offset(b)) => a == b,
            (Text(a), Text(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Keyable(a), Keyable(b)) => a.to_string() == b.to_string(),
            (_, _) => false,
        }
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Key {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        use Key::*;

        match self.to_variant().cmp(&other.to_variant()) {
            cmp::Ordering::Equal => match (self, other) {
                (Bool(false), Bool(true)) => cmp::Ordering::Less,
                (Bool(true), Bool(false)) => cmp::Ordering::Greater,
                (Offset(a), Offset(b)) => a.cmp(b),
                (Text(a), Text(b)) => a.cmp(b),
                (Bytes(a), Bytes(b)) => a.cmp(b),
                (Keyable(a), Keyable(b)) => a.to_string().cmp(&b.to_string()),
                (_, _) => unreachable!(),
            },
            cval => cval,
        }
    }
}

impl Key {
    fn to_variant(&self) -> u32 {
        use Key::*;

        match self {
            Bool(_) => 20,
            Offset(_) => 30,
            Text(_) => 40,
            Bytes(_) => 50,
            Keyable(_) => 60,
        }
    }
}

/// Basic defines IPLD data-model.
pub enum Basic {
    Null,
    Bool(bool),
    Integer(i128), // TODO: i128 might an overkill, 8 more bytes than 64-bit !!
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Link(Cid),
    List(Box<dyn Node + 'static>),
    Map(Box<dyn Node + 'static>),
}

/// Kind of data in data-model.
pub enum Kind {
    Null,
    Bool,
    Integer,
    Float,
    Text,
    Bytes,
    Link,
    List,
    Map,
}

impl Node for Basic {
    fn as_key(&self) -> Option<Key> {
        use std::str::from_utf8;
        use Basic::*;

        match self {
            Null => None,
            Bool(val) => Some(Key::Bool(val.clone())),
            Integer(val) => Some(Key::Offset(usize::try_from(val.clone()).unwrap())),
            Float(_val) => None,
            Text(val) => Some(Key::Text(from_utf8(val.as_bytes()).ok()?.to_string())),
            Bytes(val) => Some(Key::Bytes(val.clone())),
            Link(_val) => None,
            List(val) => val.as_key(),
            Map(val) => val.as_key(),
        }
    }

    fn to_kind(&self) -> Kind {
        use Basic::*;

        match self {
            Null => Kind::Null,
            Bool(_) => Kind::Bool,
            Integer(_) => Kind::Integer,
            Float(_) => Kind::Float,
            Text(_) => Kind::Text,
            Bytes(_) => Kind::Bytes,
            Link(_) => Kind::Link,
            List(_) => Kind::List,
            Map(_) => Kind::Map,
        }
    }

    fn get(&self, key: &Key) -> Result<&dyn Node> {
        match self {
            Basic::List(list) => list.get(key),
            Basic::Map(map) => map.get(key),
            _ => err_at!(IndexFail, msg: "cannot index scalar type"),
        }
    }

    fn set(&self, key: &Key, value: Box<dyn Node>) -> Result<Box<dyn Node>> {
        match self {
            Basic::List(list) => list.set(key, value),
            Basic::Map(map) => map.set(key, value),
            _ => err_at!(IndexFail, msg: "cannot index scalar type"),
        }
    }

    fn delete(&self, key: &Key) -> Result<Box<dyn Node>> {
        match self {
            Basic::List(list) => list.delete(key),
            Basic::Map(map) => map.delete(key),
            _ => err_at!(IndexFail, msg: "cannot index scalar type"),
        }
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &dyn Node> + 'a> {
        match self {
            Basic::List(list) => list.iter(),
            Basic::Map(map) => map.iter(),
            _ => Box::new(vec![].into_iter()),
        }
    }

    fn iter_entries<'a>(&'a self) -> Box<dyn Iterator<Item = (Key, &dyn Node)> + 'a> {
        match self {
            Basic::List(list) => list.iter_entries(),
            Basic::Map(map) => map.iter_entries(),
            _ => Box::new(vec![].into_iter()),
        }
    }

    fn len(&self) -> Option<usize> {
        match self {
            Basic::List(list) => list.len(),
            Basic::Map(map) => map.len(),
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        match self {
            Basic::Null => true,
            _ => false,
        }
    }

    fn to_bool(&self) -> Option<bool> {
        match self {
            Basic::Bool(val) => Some(*val),
            _ => None,
        }
    }

    fn to_integer(&self) -> Option<i128> {
        match self {
            Basic::Integer(val) => Some(*val),
            _ => None,
        }
    }

    fn to_float(&self) -> Option<f64> {
        match self {
            Basic::Float(val) => Some(*val),
            _ => None,
        }
    }

    fn as_string(&self) -> Option<Result<&str>> {
        use std::str::from_utf8;

        match self {
            Basic::Text(val) => Some(err_at!(FailConvert, from_utf8(val.as_bytes()))),
            _ => None,
        }
    }

    fn as_ffi_string(&self) -> Option<&str> {
        match self {
            Basic::Text(val) => Some(val),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Basic::Bytes(val) => Some(val),
            _ => None,
        }
    }

    fn as_link(&self) -> Option<&Cid> {
        match self {
            Basic::Link(val) => Some(val),
            _ => None,
        }
    }
}

impl TryFrom<Cbor> for Basic {
    type Error = Error;

    fn try_from(val: Cbor) -> Result<Basic> {
        use crate::ipld::cbor::{self, Cbor::*};
        use Basic::*;

        let kind = match val {
            Major0(_, num) => Integer(num.into()),
            Major1(_, num) => Integer(-(i128::from(num) + 1)),
            Major2(_, byts) => Bytes(byts),
            Major3(_, text) => Text(text),
            Major4(_, list) => {
                let mut klist: Vec<Box<dyn Node>> = vec![];
                for item in list.into_iter() {
                    klist.push(Box::new(Basic::try_from(item)?));
                }
                List(Box::new(klist))
            }
            Major5(_, dict) => {
                let mut kdict: BTreeMap<Key, Box<dyn Node>> = BTreeMap::new();
                for (k, v) in dict.into_iter() {
                    kdict.insert(Key::Text(k), Box::new(Basic::try_from(v)?));
                }
                Map(Box::new(kdict))
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

impl Node for BTreeMap<Key, Box<dyn Node>> {
    fn as_key(&self) -> Option<Key> {
        todo!()
    }

    fn to_kind(&self) -> Kind {
        Kind::Map
    }

    fn get(&self, key: &Key) -> Result<&dyn Node> {
        match self.get(key) {
            Some(val) => Ok(val.as_ref()),
            None => err_at!(IndexFail, msg: "missing key in btreemap {}", key),
        }
    }

    fn set(&self, _key: &Key, _value: Box<dyn Node>) -> Result<Box<dyn Node>> {
        todo!()
    }

    fn delete(&self, _key: &Key) -> Result<Box<dyn Node>> {
        todo!()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &dyn Node> + 'a> {
        Box::new(self.values().map(|v| v.as_ref()))
    }

    fn iter_entries<'a>(&'a self) -> Box<dyn Iterator<Item = (Key, &dyn Node)> + 'a> {
        Box::new(self.iter().map(|(k, v)| (k.clone(), v.as_ref())))
    }

    fn len(&self) -> Option<usize> {
        Some(self.len())
    }

    fn is_null(&self) -> bool {
        false
    }

    fn to_bool(&self) -> Option<bool> {
        None
    }

    fn to_integer(&self) -> Option<i128> {
        None
    }

    fn to_float(&self) -> Option<f64> {
        None
    }

    fn as_string(&self) -> Option<Result<&str>> {
        None
    }

    fn as_ffi_string(&self) -> Option<&str> {
        None
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        None
    }

    fn as_link(&self) -> Option<&Cid> {
        None
    }
}

impl Node for Vec<Box<dyn Node>> {
    fn as_key(&self) -> Option<Key> {
        todo!()
    }

    fn to_kind(&self) -> Kind {
        Kind::List
    }

    fn get(&self, key: &Key) -> Result<&dyn Node> {
        match key {
            Key::Offset(off) => match self.as_slice().get(*off) {
                Some(val) => Ok(val.as_ref()),
                None => err_at!(IndexFail, msg: "missing off in vec {}", off),
            },
            Key::Text(key) => {
                let off: usize = err_at!(FailConvert, key.parse())?;
                self.get(&Key::Offset(off))
            }
            _ => err_at!(IndexFail, msg: "can't index scalar-kind"),
        }
    }

    fn set(&self, _key: &Key, _value: Box<dyn Node>) -> Result<Box<dyn Node>> {
        todo!()
    }

    fn delete(&self, _key: &Key) -> Result<Box<dyn Node>> {
        todo!()
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &dyn Node> + 'a> {
        Box::new(self.as_slice().iter().map(|v| v.as_ref()))
    }

    fn iter_entries<'a>(&'a self) -> Box<dyn Iterator<Item = (Key, &dyn Node)> + 'a> {
        Box::new(
            (0..self.len())
                .map(Key::Offset)
                .zip(self.as_slice().iter().map(|v| v.as_ref())),
        )
    }

    fn len(&self) -> Option<usize> {
        Some(self.len())
    }

    fn is_null(&self) -> bool {
        false
    }

    fn to_bool(&self) -> Option<bool> {
        None
    }

    fn to_integer(&self) -> Option<i128> {
        None
    }

    fn to_float(&self) -> Option<f64> {
        None
    }

    fn as_string(&self) -> Option<Result<&str>> {
        None
    }

    fn as_ffi_string(&self) -> Option<&str> {
        None
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        None
    }

    fn as_link(&self) -> Option<&Cid> {
        None
    }
}

// NOTE: Operational behaviour on data.
//
// * Serialization and De-serialization.
// * Hash-digest on serialized block.
// * Schema-matching on deserialized kind.
// * Indexing operation within list and map kinds.
// * Iteration on list and map kinds.
