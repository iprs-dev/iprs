// TODO: raw-socket, ip-network

use std::{net, os::unix};

use crate::{net_addr::NetAddr, Error, Result};

pub enum Listener {
    Tcp(net::TcpListener),
    Unix(unix::net::UnixListener),
}

impl Listener {
    pub fn bind(addr: NetAddr) -> Result<Listener> {
        let val = match addr {
            NetAddr::Tcp(addr) => {
                let listn = err_at!(IOError, net::TcpListener::bind(addr))?;
                Listener::Tcp(listn)
            }
            NetAddr::Unix(addr) if addr.as_pathname().is_some() => {
                let path = addr.as_pathname().unwrap();
                let listn = err_at!(IOError, unix::net::UnixListener::bind(path))?;
                Listener::Unix(listn)
            }
            NetAddr::Unix(addr) => {
                let msg = format!("invalid addr {:?}", addr);
                err_at!(Invalid, msg: msg)?
            }
            NetAddr::Udp(_) => {
                let msg = format!("no listener for udp {:?}", addr);
                err_at!(Invalid, msg: msg)?
            }
        };

        Ok(val)
    }

    pub fn accept(&self) -> Result<Conn> {
        let conn = match self {
            Listener::Tcp(listn) => {
                let (conn, raddr) = err_at!(IOError, listn.accept())?;
                Conn::Tcp {
                    laddr: self.to_local_addr()?,
                    raddr: NetAddr::Tcp(raddr),
                    conn,
                }
            }
            Listener::Unix(listn) => {
                let (conn, raddr) = err_at!(IOError, listn.accept())?;
                Conn::Unix {
                    laddr: self.to_local_addr()?,
                    raddr: NetAddr::Unix(raddr),
                    conn,
                }
            }
        };

        Ok(conn)
    }

    pub fn to_local_addr(&self) -> Result<NetAddr> {
        let addr = match self {
            Listener::Tcp(listn) => {
                let addr = err_at!(IOError, listn.local_addr())?;
                NetAddr::Tcp(addr)
            }
            Listener::Unix(listn) => {
                todo!()
                //let addr = err_at!(IOError, listn.local_addr())?;
                //NetAddr::Unix(addr)
            }
        };

        Ok(addr)
    }
}

pub enum Conn {
    Tcp {
        laddr: NetAddr,
        raddr: NetAddr,
        conn: net::TcpStream,
    },
    Unix {
        laddr: NetAddr,
        raddr: NetAddr,
        conn: unix::net::UnixStream,
    },
}

impl Conn {
    pub fn dial(raddr: NetAddr) -> Result<Conn> {
        let conn = match raddr {
            NetAddr::Tcp(raddr) => {
                let conn = err_at!(IOError, net::TcpStream::connect(&raddr))?;
                let laddr = err_at!(IOError, conn.local_addr())?;
                Conn::Tcp {
                    laddr: NetAddr::Tcp(laddr),
                    raddr: NetAddr::Tcp(raddr),
                    conn,
                }
            }
            NetAddr::Unix(raddr) if raddr.as_pathname().is_some() => {
                let path = raddr.as_pathname().unwrap();
                let conn = err_at!(IOError, unix::net::UnixStream::connect(path))?;
                Conn::Unix {
                    laddr: NetAddr::Unix(err_at!(IOError, conn.local_addr())?),
                    raddr: NetAddr::Unix(raddr),
                    conn,
                }
            }
            NetAddr::Unix(raddr) => {
                let msg = format!("invalid addr {:?}", raddr);
                err_at!(Invalid, msg: msg)?
            }
            NetAddr::Udp(_) => {
                let msg = format!("no dial for udp {:?}", raddr);
                err_at!(Invalid, msg: msg)?
            }
        };

        Ok(conn)
    }

    pub fn recv(&self) {
        todo!()
    }

    pub fn send(&self) {
        todo!()
    }

    pub fn close(self) {
        todo!()
    }

    pub fn set_read_timeout(&self) {
        todo!()
    }

    pub fn set_write_timeout(&self) {
        todo!()
    }

    pub fn to_local_addr(&self) -> Result<NetAddr> {
        todo!()
    }

    pub fn to_remote_addr(&self) -> Result<NetAddr> {
        todo!()
    }

    pub fn close_read(&mut self) -> Result<()> {
        todo!()
    }

    pub fn close_write(&mut self) -> Result<()> {
        todo!()
    }
}
