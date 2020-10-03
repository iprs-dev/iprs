use crate::{
    multicodec::{self, Multicodec},
    Error, Result,
};

#[derive(Clone, Eq, PartialEq)]
pub struct Unix {
    path: String,
}

impl Unix {
    pub(crate) fn from_text(parts: &[&str]) -> Result<Self> {
        let val = match parts.len() {
            n if n > 0 => {
                // it's a path protocol (terminal).
                let path = "/".to_string() + &parts.join("/");
                Unix { path }
            }
            _ => err_at!(BadAddr, msg: format!("dns {:?}", parts))?,
        };

        Ok(val)
    }

    pub(crate) fn to_text(&self) -> Result<String> {
        Ok("/unix".to_string() + &self.path)
    }

    pub(crate) fn decode(data: &[u8]) -> Result<(Self, &[u8])> {
        use std::str::from_utf8;
        use unsigned_varint::decode::u128 as uv_decode;

        let val = {
            let (n, data) = err_at!(DecodeError, uv_decode(data))?;
            let (path, data) = read_slice!(data, (n as usize), "unix")?;
            let path = err_at!(DecodeError, from_utf8(path))?.to_string();
            (Unix { path }, data)
        };

        Ok(val)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        use unsigned_varint::encode::u128 as uv_encode;

        let mut buf = [0_u8; 19];

        let mut data = Multicodec::from_code(multicodec::UNIX)?.encode()?;
        data.extend_from_slice(uv_encode(self.path.len() as u128, &mut buf));
        data.extend_from_slice(self.path.as_bytes());
        Ok(data)
    }
}
