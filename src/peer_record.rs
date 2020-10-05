use std::{
    convert::{TryFrom, TryInto},
    time,
};

use crate::{
    addr_info::AddrInfo,
    multiaddr::Multiaddr,
    multicodec::{self, Multicodec},
    pb::peer_record_proto,
    peer_id::PeerId,
    Error, Result,
};

// Multicodec value for libp2p-peer-record
pub const MULTICODEC: u128 = multicodec::LIBP2P_PEER_RECORD;

// TODO: How to sign a peer_record and return the envelope.

/// PeerRecord contains information that is broadly useful to share
/// with other peers, either through a direct exchange (as in the libp2p
/// identify protocol), or through a Peer Routing provider, such as a DHT.
///
/// Currently, a PeerRecord contains the public listen addresses for a peer,
/// but this is expected to expand to include other information in the future.
///
/// PeerRecords are ordered in time by their Seq field. Newer PeerRecords
/// must have greater Seq values than older records.
///
/// Failing to set the Seq field will not result in an error, however, a
/// PeerRecord with a Seq value of zero may be ignored or rejected by other
/// peers.
///
/// PeerRecords are intended to be shared with other peers inside a signed
/// Envelope.
///
#[derive(Clone, Eq, PartialEq)]
pub struct PeerRecord {
    // ID of the peer this record pertains to.
    peer_id: PeerId,
    // Addrs contains the public addresses of the peer this record
    // pertains to.
    addrs: Vec<Multiaddr>,
    // Seq is a monotonically-increasing sequence counter that's used to
    // order PeerRecords in time. The interval between Seq values is
    // unspecified, but newer PeerRecords MUST have a greater Seq value
    // than older records for the same peer.
    seq: u128,
}

impl TryFrom<AddrInfo> for PeerRecord {
    type Error = Error;

    fn try_from(val: AddrInfo) -> Result<Self> {
        let dur = {
            let now = time::SystemTime::now();
            err_at!(Fatal, now.duration_since(time::UNIX_EPOCH))?
        };
        let val = PeerRecord {
            peer_id: val.to_peer_id(),
            addrs: val.to_multiaddrs(),
            seq: dur.as_nanos(),
        };

        Ok(val)
    }
}

impl TryFrom<peer_record_proto::PeerRecord> for PeerRecord {
    type Error = Error;

    fn try_from(val: peer_record_proto::PeerRecord) -> Result<Self> {
        let mut addrs = vec![];
        for addr in val.addresses.iter() {
            let (ma, _) = Multiaddr::decode(&addr.multiaddr)?;
            addrs.push(ma)
        }

        let (peer_id, _) = PeerId::decode(&val.peer_id)?;

        let rec = PeerRecord {
            peer_id,
            addrs,
            seq: val.seq.into(),
        };

        Ok(rec)
    }
}

impl TryFrom<PeerRecord> for peer_record_proto::PeerRecord {
    type Error = Error;

    fn try_from(val: PeerRecord) -> Result<Self> {
        let mut addresses = vec![];
        for addr in val.addrs.into_iter() {
            let address = peer_record_proto::peer_record::AddressInfo {
                multiaddr: addr.encode()?,
            };
            addresses.push(address);
        }

        let pr = peer_record_proto::PeerRecord {
            peer_id: val.peer_id.encode()?,
            seq: val.seq as u64,
            addresses,
        };

        Ok(pr)
    }
}

impl PeerRecord {
    pub fn from_peer_id(peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<PeerRecord> {
        let dur = {
            let now = time::SystemTime::now();
            err_at!(Fatal, now.duration_since(time::UNIX_EPOCH))?
        };

        let val = PeerRecord {
            peer_id,
            addrs,
            seq: dur.as_nanos(),
        };
        Ok(val)
    }

    pub fn decode_protobuf(data: &[u8]) -> Result<Self> {
        use prost::Message;
        let pr = {
            let res = peer_record_proto::PeerRecord::decode(data);
            err_at!(DecodeError, res)?
        };
        Ok(pr.try_into()?)
    }

    pub fn encode_protobuf(self) -> Result<Vec<u8>> {
        use prost::Message;

        let pr: peer_record_proto::PeerRecord = self.try_into()?;

        let mut buf = Vec::with_capacity(pr.encoded_len());
        err_at!(EncodeError, pr.encode(&mut buf))?;
        Ok(buf)
    }

    pub fn to_domain(&self) -> String {
        "libp2p-peer-record".to_string()
    }

    pub fn to_multicodec(&self) -> Multicodec {
        multicodec::LIBP2P_PEER_RECORD.into()
    }
}
