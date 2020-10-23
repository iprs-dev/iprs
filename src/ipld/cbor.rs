use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    io,
};

use crate::{cid::Cid, ipld::kind::Node, Error, Result};

// TODO: https://github.com/cbor/test-vectors

/// TAG ID for IPLD Content identifier, registered with IANA.
pub const TAG_IPLD_CID: u64 = 42;

/// Recursion limit for nested Cbor objects.
pub const RECURSION_LIMIT: u32 = 1000;

/// Cbor type, sole purpose is to correspond with [Basic] data-model.
#[derive(Clone)]
pub enum Cbor {
    Major0(Info, u64),                    // uint 0-23,24,25,26,27
    Major1(Info, u64),                    // nint 0-23,24,25,26,27
    Major2(Info, Vec<u8>),                // byts 0-23,24,25,26,27,31
    Major3(Info, String),                 // text 0-23,24,25,26,27,31
    Major4(Info, Vec<Cbor>),              // list 0-23,24,25,26,27,31
    Major5(Info, BTreeMap<String, Cbor>), // dict 0-23,24,25,26,27,31
    Major6(Info, Tag),                    // tags similar to major0
    Major7(Info, SimpleValue),            // type refer SimpleValue
}

impl TryFrom<&dyn Node> for Cbor {
    type Error = Error;

    fn try_from(node: &dyn Node) -> Result<Cbor> {
        use crate::ipld::kind::{Key, Kind::*};
        use Cbor::*;

        let val: Cbor = match node.to_kind() {
            Null => Cbor::try_from(SimpleValue::Null)?,
            Bool => match node.to_bool().unwrap() {
                true => Cbor::try_from(SimpleValue::True)?,
                false => Cbor::try_from(SimpleValue::False)?,
            },
            Integer => match node.to_integer().unwrap() {
                num if num >= 0 => {
                    let num: u64 = err_at!(FailConvert, num.try_into())?;
                    Major0(num.into(), num)
                }
                num => {
                    let num: u64 = err_at!(FailConvert, u64::try_from(i128::abs(num)))? - 1;
                    Major1(num.into(), num)
                }
            },
            Float => Cbor::try_from(SimpleValue::F64(node.to_float().unwrap()))?,
            Bytes => {
                let byts = node.as_bytes().unwrap().to_vec();
                let n: u64 = err_at!(FailConvert, byts.len().try_into())?;
                Major2(n.into(), byts)
            }
            Text => {
                let text = node.as_string().unwrap()?.to_string();
                let n: u64 = err_at!(FailConvert, text.len().try_into())?;
                Major3(n.into(), text)
            }
            Link => {
                let tag = Tag::Link(node.as_link().unwrap().clone());
                Major6(u64::from(tag.clone()).into(), tag)
            }
            List => {
                let mut items = vec![];
                for x in node.iter() {
                    items.push(Cbor::try_from(x)?)
                }
                let n: u64 = err_at!(FailConvert, items.len().try_into())?;
                Major4(n.into(), items)
            }
            Map => {
                let mut map: BTreeMap<String, Cbor> = BTreeMap::new();
                for (key, value) in node.iter_entries() {
                    let key = match key {
                        Key::Text(key) => Ok(key),
                        _ => err_at!(FailConvert, msg: "invalid key type"),
                    }?;
                    let value = Cbor::try_from(value)?;
                    map.insert(key, value);
                }
                let n: u64 = err_at!(FailConvert, map.len().try_into())?;
                Major5(n.into(), map)
            }
        };

        Ok(val)
    }
}

impl Cbor {
    /// Serialize this cbor value.
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<usize> {
        self.do_encode(buf, 1)
    }

    fn do_encode(&self, buf: &mut Vec<u8>, depth: u32) -> Result<usize> {
        if depth > RECURSION_LIMIT {
            return err_at!(FailCbor, msg: "encode recursion limit exceeded");
        }

        match self {
            Cbor::Major0(info, num) => {
                let n = encode_hdr(Major::M0, *info, buf)?;
                Ok(n + encode_addnl(*num, buf)?)
            }
            Cbor::Major1(info, num) => {
                let n = encode_hdr(Major::M1, *info, buf)?;
                Ok(n + encode_addnl(*num - 1, buf)?)
            }
            Cbor::Major2(info, byts) => {
                let n = encode_hdr(Major::M2, *info, buf)?;
                let m = encode_addnl(byts.len().try_into().unwrap(), buf)?;
                buf.copy_from_slice(&byts);
                Ok(n + m + byts.len())
            }
            Cbor::Major3(info, text) => {
                let n = encode_hdr(Major::M3, *info, buf)?;
                let m = encode_addnl(text.len().try_into().unwrap(), buf)?;
                buf.copy_from_slice(text.as_bytes());
                Ok(n + m + text.len())
            }
            Cbor::Major4(info, list) => {
                let n = encode_hdr(Major::M4, *info, buf)?;
                let m = encode_addnl(list.len().try_into().unwrap(), buf)?;
                let mut acc = 0;
                for x in list {
                    acc += x.do_encode(buf, depth + 1)?;
                }
                Ok(n + m + acc)
            }
            Cbor::Major5(info, dict) => {
                let n = encode_hdr(Major::M5, *info, buf)?;
                let m = encode_addnl(dict.len().try_into().unwrap(), buf)?;
                let mut acc = 0;
                for (key, val) in dict.iter() {
                    let info: Info = {
                        let num: u64 = key.len().try_into().unwrap();
                        num.into()
                    };
                    acc += Cbor::Major3(info, key.clone()).encode(buf)?;
                    acc += val.do_encode(buf, depth + 1)?;
                }
                Ok(n + m + acc)
            }
            Cbor::Major6(info, tagg) => {
                let n = encode_hdr(Major::M6, *info, buf)?;
                let m = tagg.encode(buf)?;
                Ok(n + m)
            }
            Cbor::Major7(info, sval) => {
                let n = encode_hdr(Major::M7, *info, buf)?;
                let m = sval.encode(buf)?;
                Ok(n + m)
            }
        }
    }

    /// Deserialize a bytes from reader `r` to Cbor value.
    pub fn decode<R: io::Read>(r: &mut R) -> Result<Cbor> {
        Self::do_decode(r, 1)
    }

    fn do_decode<R: io::Read>(r: &mut R, depth: u32) -> Result<Cbor> {
        if depth > RECURSION_LIMIT {
            return err_at!(FailCbor, msg: "decode recursion limt exceeded");
        }

        let (major, info) = decode_hdr(r)?;

        let val = match major {
            Major::M0 => Cbor::Major0(info, decode_addnl(info, r)?),
            Major::M1 => Cbor::Major1(info, decode_addnl(info, r)?),
            Major::M2 => {
                let n: usize = decode_addnl(info, r)?.try_into().unwrap();
                let mut data = vec![0; n];
                err_at!(IOError, r.read(&mut data))?;
                Cbor::Major2(info, data)
            }
            Major::M3 => {
                let n: usize = decode_addnl(info, r)?.try_into().unwrap();
                let mut data = vec![0; n];
                err_at!(IOError, r.read(&mut data))?;
                let s = unsafe { std::str::from_utf8_unchecked(&data) };
                Cbor::Major3(info, s.to_string())
            }
            Major::M4 => {
                let mut list: Vec<Cbor> = vec![];
                let n = decode_addnl(info, r)?;
                for _ in 0..n {
                    list.push(Self::do_decode(r, depth + 1)?);
                }
                Cbor::Major4(info, list)
            }
            Major::M5 => {
                let mut dict: BTreeMap<String, Cbor> = BTreeMap::new();
                let n = decode_addnl(info, r)?;
                for _ in 0..n {
                    let key = extract_key(Self::decode(r)?)?;
                    let val = Self::do_decode(r, depth + 1)?;
                    dict.insert(key, val);
                }
                Cbor::Major5(info, dict)
            }
            Major::M6 => Cbor::Major6(info, Tag::decode(info, r)?),
            Major::M7 => Cbor::Major7(info, SimpleValue::decode(info, r)?),
        };
        Ok(val)
    }
}

/// 3-bit value for major-type.
#[derive(Copy, Clone)]
pub enum Major {
    M0 = 0,
    M1,
    M2,
    M3,
    M4,
    M5,
    M6,
    M7,
}

impl TryFrom<u8> for Major {
    type Error = Error;

    fn try_from(b: u8) -> Result<Major> {
        let val = match b {
            0 => Major::M0,
            1 => Major::M1,
            2 => Major::M2,
            3 => Major::M3,
            4 => Major::M4,
            5 => Major::M5,
            6 => Major::M6,
            7 => Major::M7,
            _ => err_at!(Fatal, msg: "unreachable")?,
        };

        Ok(val)
    }
}

/// 5-bit value for additional info.
#[derive(Copy, Clone)]
pub enum Info {
    Tiny(u8), // 0..=23
    U8,
    U16,
    U32,
    U64,
    Reserved28,
    Reserved29,
    Reserved30,
    Indefinite,
}

impl TryFrom<u8> for Info {
    type Error = Error;

    fn try_from(b: u8) -> Result<Info> {
        let val = match b {
            0..=23 => Info::Tiny(b),
            24 => Info::U8,
            25 => Info::U16,
            26 => Info::U32,
            27 => Info::U64,
            28 => Info::Reserved28,
            29 => Info::Reserved29,
            30 => Info::Reserved30,
            31 => Info::Indefinite,
            _ => err_at!(Fatal, msg: "unreachable")?,
        };

        Ok(val)
    }
}

impl From<u64> for Info {
    fn from(num: u64) -> Info {
        match num {
            0..=23 => Info::Tiny(num as u8),
            n if n <= (u8::MAX as u64) => Info::U8,
            n if n <= (u16::MAX as u64) => Info::U16,
            n if n <= (u32::MAX as u64) => Info::U32,
            _ => Info::U64,
        }
    }
}

fn encode_hdr(major: Major, info: Info, buf: &mut Vec<u8>) -> Result<usize> {
    let info = match info {
        Info::Tiny(val) if val <= 23 => val,
        Info::Tiny(val) => err_at!(FailCbor, msg: "{} > 23", val)?,
        Info::U8 => 24,
        Info::U16 => 25,
        Info::U32 => 26,
        Info::U64 => 27,
        Info::Reserved28 => 28,
        Info::Reserved29 => 29,
        Info::Reserved30 => 30,
        Info::Indefinite => 31,
    };
    buf.push((major as u8) << 5 | info);
    Ok(1)
}

fn decode_hdr<R: io::Read>(r: &mut R) -> Result<(Major, Info)> {
    let mut scratch = [0_u8; 8];
    err_at!(IOError, r.read(&mut scratch[..1]))?;

    let b = scratch[0];

    let major = (b & 0xe0) >> 5;
    let info = b & 0x1f;
    Ok((major.try_into()?, info.try_into()?))
}

fn encode_addnl(num: u64, buf: &mut Vec<u8>) -> Result<usize> {
    let mut scratch = [0_u8; 8];
    let n = match num {
        0..=23 => 0,
        n if n <= (u8::MAX as u64) => {
            scratch.copy_from_slice(&(n as u8).to_be_bytes());
            1
        }
        n if n <= (u16::MAX as u64) => {
            scratch.copy_from_slice(&(n as u16).to_be_bytes());
            2
        }
        n if n <= (u32::MAX as u64) => {
            scratch.copy_from_slice(&(n as u32).to_be_bytes());
            4
        }
        n => {
            scratch.copy_from_slice(&n.to_be_bytes());
            8
        }
    };
    buf.copy_from_slice(&scratch[..n]);
    Ok(n)
}

fn decode_addnl<R: io::Read>(info: Info, r: &mut R) -> Result<u64> {
    let mut scratch = [0_u8; 8];
    let n = match info {
        Info::Tiny(num) => num as u64,
        Info::U8 => {
            err_at!(IOError, r.read(&mut scratch[..1]))?;
            u8::from_be_bytes(scratch[..1].try_into().unwrap()) as u64
        }
        Info::U16 => {
            err_at!(IOError, r.read(&mut scratch[..2]))?;
            u16::from_be_bytes(scratch[..2].try_into().unwrap()) as u64
        }
        Info::U32 => {
            err_at!(IOError, r.read(&mut scratch[..4]))?;
            u32::from_be_bytes(scratch[..4].try_into().unwrap()) as u64
        }
        Info::U64 => {
            err_at!(IOError, r.read(&mut scratch[..8]))?;
            u64::from_be_bytes(scratch[..8].try_into().unwrap()) as u64
        }
        _ => err_at!(FailCbor, msg: "no additional value")?,
    };
    Ok(n)
}

#[derive(Clone)]
pub enum Tag {
    Link(Cid), // TAG_IPLD_CID
}

impl From<Tag> for u64 {
    fn from(tag: Tag) -> u64 {
        match tag {
            Tag::Link(_) => TAG_IPLD_CID,
        }
    }
}

impl Tag {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<usize> {
        match self {
            Tag::Link(cid) => {
                buf.copy_from_slice(&TAG_IPLD_CID.to_be_bytes());
                let n = {
                    let data = cid.encode()?;
                    let m: u64 = err_at!(FailCbor, data.len().try_into())?;
                    Cbor::Major2(m.into(), data).encode(buf)?
                };
                Ok(1 + n)
            }
        }
    }

    fn decode<R: io::Read>(info: Info, r: &mut R) -> Result<Tag> {
        match decode_addnl(info, r)? {
            42 => match Cbor::decode(r)? {
                Cbor::Major2(_, bytes) => {
                    let (cid, _) = Cid::decode(&bytes)?;
                    Ok(Tag::Link(cid))
                }
                _ => err_at!(FailCbor, msg: "invalid cid"),
            },
            num => err_at!(FailCbor, msg: "invalid tag value {}", num),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SimpleValue {
    // 0..=19 unassigned
    Unassigned,
    True,           // 20, tiny simple-value
    False,          // 21, tiny simple-value
    Null,           // 22, tiny simple-value
    Undefined,      // 23, tiny simple-value
    Reserved24(u8), // 24, one-byte simple-value
    F16(u16),       // 25, not-implemented
    F32(f32),       // 26, single-precision float
    F64(f64),       // 27, single-precision float
    // 28..=30 unassigned
    Break, // 31
           // 32..=255 on-byte simple-value unassigned
}

impl TryFrom<SimpleValue> for Cbor {
    type Error = Error;

    fn try_from(sval: SimpleValue) -> Result<Cbor> {
        use SimpleValue::*;

        let val = match sval {
            Unassigned => err_at!(FailConvert, msg: "simple-value-unassigned")?,
            True => Cbor::Major7(Info::Tiny(20), sval),
            False => Cbor::Major7(Info::Tiny(21), sval),
            Null => Cbor::Major7(Info::Tiny(22), sval),
            Undefined => err_at!(FailConvert, msg: "simple-value-undefined")?,
            Reserved24(_) => err_at!(FailConvert, msg: "simple-value-unassigned1")?,
            F16(_) => err_at!(FailConvert, msg: "simple-value-f16")?,
            F32(_) => Cbor::Major7(Info::U32, sval),
            F64(_) => Cbor::Major7(Info::U64, sval),
            Break => err_at!(FailConvert, msg: "simple-value-break")?,
        };

        Ok(val)
    }
}

impl SimpleValue {
    fn encode(&self, buf: &mut Vec<u8>) -> Result<usize> {
        use SimpleValue::*;

        let mut scratch = [0_u8; 8];
        let n = match self {
            True | False | Null | Undefined | Break | Unassigned => 0,
            Reserved24(num) => {
                scratch[0] = *num;
                1
            }
            F16(f) => {
                scratch.copy_from_slice(&f.to_be_bytes());
                2
            }
            F32(f) => {
                scratch.copy_from_slice(&f.to_be_bytes());
                4
            }
            F64(f) => {
                scratch.copy_from_slice(&f.to_be_bytes());
                8
            }
        };
        buf.copy_from_slice(&scratch[..n]);
        Ok(n)
    }

    fn decode<R: io::Read>(info: Info, r: &mut R) -> Result<SimpleValue> {
        let mut scratch = [0_u8; 8];
        let val = match info {
            Info::Tiny(20) => SimpleValue::True,
            Info::Tiny(21) => SimpleValue::False,
            Info::Tiny(22) => SimpleValue::Null,
            Info::Tiny(23) => err_at!(FailCbor, msg: "simple-value-undefined")?,
            Info::Tiny(_) => err_at!(FailCbor, msg: "simple-value-unassigned")?,
            Info::U8 => err_at!(FailCbor, msg: "simple-value-unassigned1")?,
            Info::U16 => err_at!(FailCbor, msg: "simple-value-f16")?,
            Info::U32 => {
                err_at!(IOError, r.read(&mut scratch[..4]))?;
                let val = f32::from_be_bytes(scratch[..4].try_into().unwrap());
                SimpleValue::F32(val)
            }
            Info::U64 => {
                err_at!(IOError, r.read(&mut scratch[..8]))?;
                let val = f64::from_be_bytes(scratch[..8].try_into().unwrap());
                SimpleValue::F64(val)
            }
            Info::Reserved28 => err_at!(FailCbor, msg: "simple-value-reserved")?,
            Info::Reserved29 => err_at!(FailCbor, msg: "simple-value-reserved")?,
            Info::Reserved30 => err_at!(FailCbor, msg: "simple-value-reserved")?,
            Info::Indefinite => err_at!(FailCbor, msg: "simple-value-break")?,
        };
        Ok(val)
    }
}

fn extract_key(val: Cbor) -> Result<String> {
    match val {
        Cbor::Major3(_, s) => {
            let key = err_at!(FailConvert, std::str::from_utf8(s.as_bytes()))?;
            Ok(key.to_string())
        }
        _ => err_at!(FailCbor, msg: "invalid key"),
    }
}
