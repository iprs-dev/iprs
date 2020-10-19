use std::{collections::HashMap, convert::TryInto, io};

use crate::{cid::Cid, Error, Result, ipld::kind::Kind};

// TODO: https://github.com/cbor/test-vectors

/// TAG ID for IPLD Content identifier, registered with IANA.
pub const TAG_IPLD_CID: u64 = 42;

/// Recursion limit for nested Cbor objects.
pub const RECURSION_LIMIT: u32 = 1000;

/// Cbor type, sole purpose is to correspond with [Kind].
#[derive(Clone)]
pub enum Cbor {
    Major0(Info, u64),                   // uint 0-23,24,25,26,27
    Major1(Info, u64),                   // nint 0-23,24,25,26,27
    Major2(Info, Vec<u8>),               // byts 0-23,24,25,26,27,31
    Major3(Info, String),                // text 0-23,24,25,26,27,31
    Major4(Info, Vec<Cbor>),             // list 0-23,24,25,26,27,31
    Major5(Info, HashMap<String, Cbor>), // dict 0-23,24,25,26,27,31
    Major6(Info, Tag),                   // tags similar to major0
    Major7(Info, SimpleValue),           // type refer SimpleValue
}

impl TryFrom<Kind> for Cbor {
    type Error = Error;

    fn try_from(val: Cbor) -> Result<Kind> {
        use crate::ipld::kind::Kind::*;
        use Cbor::*;

        let kind = match val {
            Null => Major7(SimpleValue::Null.into(), SimpleValue::Null),
            Bool(true) => Major7(SimpleValue::True.into(), SimpleValue::True),
            Bool(false) => Major7(SimpleValue::False.into(), SimpleValue::False),
            Integer(num) if num >= 0 => {
                let num: u64 = err_at!(Overflow, num.try_into())?;
                Major0(num.into(), num)
            }
            Integer(num) => {
                let num: u64 = err_at!(Overflow, i128::abs(num).try_into() - 1)?;
                Major1(num.into(), num)
            }
            Float(num) => {
                let val = SimpleValue::F64(val);
                Major7(val.into(), SimpleValue::F32(val))
            }
            Bytes(byts) => {
                let n: u64 = err_at!(Overflow, byts.len().try_into())?;
                Major2(n.into(), byts)
            }
            Text(text) => {
                let n: u64 = err_at!(Overflow, text.len().try_into())?;
                Major2(n.into(), text)
            }
            Link(cid) => {
                let tag = Tag::Link(cid);
                Major6(u64::from(tag.clone()).into(), tag)
            }
            List(Vec<Kind>) => {
                todo!()
            }
            Dict(HashMap<String, Kind>) => {
                todo!()
            }
        };

        Ok(kind)
    }
}

impl Cbor {
    /// Serialize this cbor value.
    pub fn encode(&self, buf: &mut Vec<u8>) -> Result<usize> {
        self.do_encode(buf, 1)
    }

    fn do_encode(&self, buf: &mut Vec<u8>, depth: u32) -> Result<usize> {
        if depth > RECURSION_LIMIT {
            let prefix = format!("{}:{}", file!(), line!());
            let msg = "do_encode recursion limit exceeded".to_string();
            return Err(Error::Overflow(prefix, msg));
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
            let prefix = format!("{}:{}", file!(), line!());
            let msg = "do_decode recursion limit exceeded".to_string();
            return Err(Error::Overflow(prefix, msg));
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
                let s = err_at!(DecodeError, std::str::from_utf8(&data))?;
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
                let mut dict: HashMap<String, Cbor> = HashMap::new();
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

impl From<u8> for Major {
    fn from(b: u8) -> Major {
        match b {
            0 => Major::M0,
            1 => Major::M1,
            2 => Major::M2,
            3 => Major::M3,
            4 => Major::M4,
            5 => Major::M5,
            6 => Major::M6,
            7 => Major::M7,
            _ => unreachable!(),
        }
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

impl From<u8> for Info {
    fn from(b: u8) -> Info {
        match b {
            0..=23 => Info::Tiny(b),
            24 => Info::U8,
            25 => Info::U16,
            26 => Info::U32,
            27 => Info::U64,
            28 => Info::Reserved28,
            29 => Info::Reserved29,
            30 => Info::Reserved30,
            31 => Info::Indefinite,
            _ => unreachable!(),
        }
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
        Info::Tiny(val) => err_at!(EncodeError, msg: format!("{} > 23", val))?,
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
    Ok((major.into(), info.into()))
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
        _ => err_at!(DecodeError, msg: format!("no additional value"))?,
    };
    Ok(n)
}

#[derive(Clone)]
pub enum Tag {
    Link(Cid), // TAG_IPLD_CID
    Num(u64),
}

impl From<Tag> for u64 {
    fn from(tag: Tag) -> u64 {
        match tag {
            Tag::Link(_) => TAG_IPLD_CID,
            Tag::Num(num) => num,
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
                    let m: u64 = data.len().try_into().unwrap();
                    Cbor::Major2(m.into(), data).encode(buf)?
                };
                Ok(1 + n)
            }
            Tag::Num(num) => encode_addnl(*num, buf),
        }
    }

    fn decode<R: io::Read>(info: Info, r: &mut R) -> Result<Tag> {
        match decode_addnl(info, r)? {
            42 => match Cbor::decode(r)? {
                Cbor::Major2(_, bytes) => {
                    let (cid, _) = Cid::decode(&bytes)?;
                    Ok(Tag::Link(cid))
                }
                _ => {
                    let prefix = format!("{}:{}", file!(), line!());
                    let msg = "invalid cid".to_string();
                    Err(Error::DecodeError(prefix, msg))
                }
            },
            num => Ok(Tag::Num(num)),
        }
    }
}

#[derive(Clone)]
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

    fn try_from(sval: SimpleValue) -> Result<Info> {
        use SimpleValue::*;

        match sval {
            Unassigned => {
                err_at!(NotSupported, msg: format!("simple-value-unassigned")?
            }
            True => Info::Tiny(20),
            False => Info::Tiny(21),
            Null => Info::Tiny(22),
            Undefined => Info::Tiny(23),
            Reserved24(_) => Info::U8,
            F16(_) => Info::U16,
            F32(_) => Info::U32,
            F64(_) => Info::U64,
            Break => Info::Indefinite,
        }
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
            Info::Tiny(23) => SimpleValue::Undefined,
            Info::Tiny(_) => SimpleValue::Unassigned,
            Info::U8 => {
                err_at!(IOError, r.read(&mut scratch[..1]))?;
                SimpleValue::Reserved24(scratch[0])
            }
            Info::U16 => {
                err_at!(IOError, r.read(&mut scratch[..2]))?;
                let val = u16::from_be_bytes(scratch[..2].try_into().unwrap());
                SimpleValue::F16(val)
            }
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
            Info::Reserved28 => SimpleValue::Unassigned,
            Info::Reserved29 => SimpleValue::Unassigned,
            Info::Reserved30 => SimpleValue::Unassigned,
            Info::Indefinite => SimpleValue::Break,
        };
        Ok(val)
    }
}

fn extract_key(val: Cbor) -> Result<String> {
    match val {
        Cbor::Major3(_, s) => Ok(s),
        _ => {
            let prefix = format!("{}:{}", file!(), line!());
            Err(Error::DecodeError(prefix, "invalid key".to_string()))
        }
    }
}
