use std::fmt;

use crate::{
    multiaddr::{self, Multiaddr},
    peer_id::PeerId,
    Error, Result,
};

/// Type AddrInfo is a small struct used to pass around a peer with
/// a set of addresses.
pub struct AddrInfo {
    peer_id: PeerId,
    // This list of multiaddr shall have its /p2p/Qm.. part pruned away.
    addrs: Vec<Multiaddr>,
}

impl fmt::Display for AddrInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addrs = {
            let iter = self.addrs.iter().filter_map(|a| a.to_text().ok());
            let addrs: Vec<String> = iter.collect();
            addrs.join(",")
        };
        write!(f, "{{{} : {}}}", self.peer_id, addrs)
    }
}

impl AddrInfo {
    pub fn from_p2p_multiaddrs(addrs: Vec<Multiaddr>) -> Result<Vec<AddrInfo>> {
        // TODO: using an array for book keeping might be in-efficient
        // for large dataset. try using a Map container.
        let mut addr_infos: Vec<AddrInfo> = vec![];

        for addr in addrs.into_iter() {
            let mut new_a = Self::from_p2p_multiaddr(addr)?;
            let off = {
                let mut iter = addr_infos.iter().enumerate();
                loop {
                    match iter.next() {
                        Some((i, a)) if new_a.peer_id == a.peer_id => break Some(i),
                        Some(_) => continue,
                        None => break None,
                    }
                }
            };
            match off {
                Some(i) => addr_infos[i].addrs.append(&mut new_a.addrs),
                None => addr_infos.push(new_a),
            }
        }

        Ok(addr_infos)
    }

    pub fn from_p2p_multiaddr(addr: Multiaddr) -> Result<AddrInfo> {
        let mut comps = addr.split()?;
        let peer_id = match comps.pop() {
            Some(Multiaddr::P2p(val, _)) => val.to_peer_id(),
            Some(Multiaddr::Ipfs(val, _)) => val.to_peer_id(),
            _ => err_at!(Invalid, msg: "not p2p address")?,
        };

        let addr_info = AddrInfo {
            peer_id,
            addrs: vec![Multiaddr::join(comps)?],
        };

        Ok(addr_info)
    }

    pub fn to_p2p_multiaddrs(&self) -> Result<Vec<Multiaddr>> {
        let p2p_addr = {
            let val = multiaddr::p2p::P2p::new(self.peer_id.clone());
            Multiaddr::P2p(val, Box::new(Multiaddr::None))
        };

        let mut addrs = vec![];
        for addr in self.addrs.clone().into_iter() {
            let mut comps = addr.split()?;
            comps.push(p2p_addr.clone());
            addrs.push(Multiaddr::join(comps)?);
        }

        Ok(addrs)
    }

    pub fn to_peer_id(&self) -> PeerId {
        self.peer_id.clone()
    }

    pub fn to_multiaddrs(&self) -> Vec<Multiaddr> {
        self.addrs.clone()
    }
}
