use std::{io, marker::PhantomData};

use crate::{util, Error, Result};

/// Implemented by types that can negotiate protocol with remote and
/// upgrade a connection C, to a protocol instance P.
pub trait Protocol<C, P>: Clone
where
    C: io::Read + io::Write,
{
    fn to_proto_path(&self) -> String;

    fn try_match(&self, proto: &str) -> bool;

    fn upgrade(self, conn: C) -> P;
}

/// Multistream select to upgrade connection C to protocol P.
pub enum Multistream<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    V1 {
        ver: Version1<C, P, T>,
        protocol: Option<T>,
        handlers: Vec<T>,
    },
}

impl<C, P, T> Default for Multistream<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    fn default() -> Self {
        use Multistream::*;

        V1 {
            ver: Version1::default(),
            protocol: None,
            handlers: vec![],
        }
    }
}

impl<C, P, T> Multistream<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    pub fn new_v1(protocol: Option<T>) -> Self {
        Multistream::V1 {
            ver: Version1::default(),
            protocol,
            handlers: vec![],
        }
    }

    pub fn add_handler(&mut self, handler: T) -> &mut Self {
        use Multistream::*;

        match self {
            V1 { handlers, .. } => handlers.push(handler),
        }
        self
    }

    pub fn negotiate(&mut self, conn: &mut C) -> Result<()> {
        use Multistream::*;

        match self {
            V1 {
                ver,
                protocol,
                handlers,
            } => ver.handshake(protocol.as_ref(), handlers, conn),
        }
    }

    pub fn upgrade(self, _conn: C) -> Result<P> {
        todo!()
    }
}

impl<C, P, T> Multistream<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    fn ls(protocol: Option<&T>, handlers: &[T]) -> Result<Vec<u8>> {
        let mut ps: Vec<String> = {
            let iter = handlers.iter().map(|h| h.to_proto_path());
            iter.collect()
        };
        protocol.map(|x| ps.insert(0, x.to_proto_path()));

        // de-duplicate
        let mut ss = vec![];
        for p in ps.iter() {
            if !ss.contains(p) {
                ss.push(p.clone())
            }
        }

        let mut data = vec![];
        Self::encodes(&mut data, ps.iter().map(|x| x.as_bytes()).collect())?;
        Ok(data)
    }

    fn encode(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<usize> {
        let n = util::write_lpm(buf, bytes)?;
        buf.push('\n' as u8);
        Ok(n + 1)
    }

    fn encodes(buf: &mut Vec<u8>, bytess: Vec<&[u8]>) -> Result<usize> {
        let mut data = vec![];
        for bytes in bytess.iter() {
            Self::encode(&mut data, bytes)?;
        }
        let n = util::write_lpm(buf, &data)?;
        buf.push('\n' as u8);
        Ok(n + 1)
    }
}

pub enum Version1<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    Handshake(PhantomData<C>, PhantomData<P>),
    Fin(T),
}

impl<C, P, T> Default for Version1<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    fn default() -> Self {
        Version1::Handshake(PhantomData, PhantomData)
    }
}

impl<C, P, T> Version1<C, P, T>
where
    C: io::Read + io::Write,
    T: Clone + Protocol<C, P>,
{
    fn handshake(&mut self, _protocol: Option<&T>, _handlers: &[T], _conn: &mut C) -> Result<()> {
        todo!()
    }
}

fn read<T: io::Read>(r: &mut T) -> Result<Vec<String>> {
    use std::str::from_utf8;

    let nl = '\n' as u8;
    let mut data = util::read_lpm(r)?;
    let lines = match data.pop() {
        None => err_at!(IOError, msg: "empty multistream read")?,
        Some(b) if b == nl => {
            let mut lines = vec![];
            for line in data.rsplit(|b| *b == nl) {
                lines.push(err_at!(DecodeError, from_utf8(line))?.to_string())
            }
            lines
        }
        _ => err_at!(IOError, msg: "multistream miss nl suffix")?,
    };

    Ok(lines)
}
