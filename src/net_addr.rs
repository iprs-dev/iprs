// IPv6-Zone:
//   https://github.com/rust-lang/rfcs/issues/1992
//   https://tools.ietf.org/html/rfc2553#section-3.3

use std::{convert::TryInto, net, os};

use crate::{
    multiaddr::{self, Multiaddr},
    Error, Result,
};

#[derive(Debug)]
pub enum NetAddr {
    Tcp(net::SocketAddr),
    Udp(net::SocketAddr),
    Unix(os::unix::net::SocketAddr),
}

impl NetAddr {
    pub fn from_multiaddr(ma: Multiaddr) -> Result<NetAddr> {
        let netaddr = match ma.parse() {
            Multiaddr::Ip4(ipval, box Multiaddr::Tcp(tcpval, _)) => {
                let ip = ipval.to_addr();
                let addr = net::SocketAddr::from((ip, tcpval.to_port()));
                NetAddr::Tcp(addr)
            }
            Multiaddr::Ip4(ipval, box Multiaddr::Udp(udpval, _)) => {
                let ip = ipval.to_addr();
                let addr = net::SocketAddr::from((ip, udpval.to_port()));
                NetAddr::Udp(addr)
            }
            Multiaddr::Ip6(ipval, box Multiaddr::Tcp(tcpval, _)) => {
                let (ip, port) = (ipval.to_addr(), tcpval.to_port());
                let addr = net::SocketAddr::from((ip, port));
                NetAddr::Tcp(addr)
            }
            Multiaddr::Ip6(ipval, box Multiaddr::Udp(udpval, _)) => {
                let (ip, port) = (ipval.to_addr(), udpval.to_port());
                let addr = net::SocketAddr::from((ip, port));
                NetAddr::Udp(addr)
            }
            Multiaddr::Dns(dns, box Multiaddr::Tcp(tcpval, _)) => {
                use std::net::ToSocketAddrs;

                let port = tcpval.to_port();
                let addr = {
                    let name = dns.as_str()?;
                    let mut iter = err_at!(DnsError, (name, port).to_socket_addrs())?;
                    match iter.next() {
                        Some(addr) => addr,
                        None => err_at!(DnsError, msg: format!("{}", name))?,
                    }
                };
                NetAddr::Tcp(addr)
            }
            Multiaddr::Dns(dns, box Multiaddr::Udp(udpval, _)) => {
                use std::net::ToSocketAddrs;

                let port = udpval.to_port();
                let addr = {
                    let name = dns.as_str()?;
                    let mut iter = err_at!(DnsError, (name, port).to_socket_addrs())?;
                    match iter.next() {
                        Some(addr) => addr,
                        None => err_at!(DnsError, msg: format!("{}", name))?,
                    }
                };
                NetAddr::Tcp(addr)
            }
            Multiaddr::Dns4(dns, box Multiaddr::Tcp(tcpval, _)) => {
                let addr = {
                    let addr = dns.as_str()?;
                    let ip4: net::Ipv4Addr = err_at!(BadAddr, addr.parse())?;
                    net::SocketAddr::from((ip4, tcpval.to_port()))
                };
                NetAddr::Tcp(addr)
            }
            Multiaddr::Dns4(dns, box Multiaddr::Udp(udpval, _)) => {
                let addr = {
                    let addr = dns.as_str()?;
                    let ip4: net::Ipv4Addr = err_at!(BadAddr, addr.parse())?;
                    net::SocketAddr::from((ip4, udpval.to_port()))
                };
                NetAddr::Udp(addr)
            }
            Multiaddr::Dns6(dns, box Multiaddr::Tcp(tcpval, _)) => {
                let addr = {
                    let addr = dns.as_str()?;
                    let ip6: net::Ipv6Addr = err_at!(BadAddr, addr.parse())?;
                    net::SocketAddr::from((ip6, tcpval.to_port()))
                };
                NetAddr::Tcp(addr)
            }
            Multiaddr::Dns6(dns, box Multiaddr::Udp(udpval, _)) => {
                let addr = {
                    let addr = dns.as_str()?;
                    let ip6: net::Ipv6Addr = err_at!(BadAddr, addr.parse())?;
                    net::SocketAddr::from((ip6, udpval.to_port()))
                };
                NetAddr::Udp(addr)
            }
            Multiaddr::Unix(unix, _) => {
                let addr = {
                    let res = os::unix::net::UnixDatagram::bind(unix.to_path());
                    let addr = err_at!(IOError, res)?.local_addr();
                    err_at!(IOError, addr)?
                };
                NetAddr::Unix(addr)
            }
            _ => {
                let s = ma.to_text()?;
                err_at!(Invalid, msg: format!("bad net addr {}", s))?
            }
        };

        Ok(netaddr)
    }

    pub fn to_multiaddr(&self) -> Result<Multiaddr> {
        let ma = match self {
            NetAddr::Tcp(addr) => match addr {
                net::SocketAddr::V4(addr) => {
                    let ma_tcp = {
                        let tcp: multiaddr::tcp::Tcp = addr.port().into();
                        Multiaddr::Tcp(tcp, Box::new(Multiaddr::None))
                    };
                    let ip4: multiaddr::ip4::Ip4 = addr.ip().clone().into();
                    Multiaddr::Ip4(ip4, Box::new(ma_tcp))
                }
                net::SocketAddr::V6(addr) => {
                    let ma_tcp = {
                        let tcp: multiaddr::tcp::Tcp = addr.port().into();
                        Multiaddr::Tcp(tcp, Box::new(Multiaddr::None))
                    };
                    let ip6: multiaddr::ip6::Ip6 = addr.ip().clone().into();
                    Multiaddr::Ip6(ip6, Box::new(ma_tcp))
                }
            },
            NetAddr::Udp(addr) => match addr {
                net::SocketAddr::V4(addr) => {
                    let ma_tcp = {
                        let tcp: multiaddr::tcp::Tcp = addr.port().into();
                        Multiaddr::Tcp(tcp, Box::new(Multiaddr::None))
                    };
                    let ip4: multiaddr::ip4::Ip4 = addr.ip().clone().into();
                    Multiaddr::Ip4(ip4, Box::new(ma_tcp))
                }
                net::SocketAddr::V6(addr) => {
                    let ma_tcp = {
                        let tcp: multiaddr::tcp::Tcp = addr.port().into();
                        Multiaddr::Tcp(tcp, Box::new(Multiaddr::None))
                    };
                    let ip6: multiaddr::ip6::Ip6 = addr.ip().clone().into();
                    Multiaddr::Ip6(ip6, Box::new(ma_tcp))
                }
            },
            NetAddr::Unix(addr) => match addr.as_pathname() {
                Some(path) => {
                    let unix: multiaddr::unix::Unix = path.try_into()?;
                    Multiaddr::Unix(unix, Box::new(Multiaddr::None))
                }
                None => {
                    let msg = format!("invalid unix net path {:?}", addr);
                    err_at!(Invalid, msg: msg)?
                }
            },
        };

        Ok(ma)
    }
}
