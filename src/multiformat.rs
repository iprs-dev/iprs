use crate::{
    multibase::Multibase,
    multicodec::{self, Codepoint, Multicodec},
    multihash::Multihash,
    Error, Result,
};

pub enum Multiformats {
    Multibase(Multibase),
    Multihash(Multihash),
}

impl Multiformats {
    pub fn from_slice<'a, 'b>(
        buf: &'a [u8],
        code_points: Option<&'b [Codepoint]>,
    ) -> Result<(Multiformats, &'a [u8])> {
        let codes = code_points.unwrap_or(multicodec::TABLE.as_ref());

        let (codec, _) = Multicodec::from_slice(buf)?;

        let mut iter = codes.iter();
        let (val, rem) = loop {
            match iter.next() {
                Some(code_point) => match code_point.tag.as_str() {
                    "multibase" => {
                        let val = Multibase::from_slice(buf)?;
                        break (Multiformats::Multibase(val), &buf[buf.len()..]);
                    }
                    "multihash" => {
                        let (val, rem) = Multihash::from_slice(buf)?;
                        break (Multiformats::Multihash(val), rem);
                    }
                    _ => (),
                },
                None => err_at!(BadInput, msg: format!("{}", codec))?,
            }
        };
        Ok((val, rem))
    }
}
