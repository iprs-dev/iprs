use crate::{identity, PeerId};

#[test]
fn peer_id_is_public_key() {
    let key = identity::Keypair::generate_ed25519().public();
    let peer_id = key.clone().into_peer_id();
    assert_eq!(peer_id.is_public_key(&key), Some(true));
}

#[test]
fn peer_id_into_bytes_then_from_bytes() {
    let peer_id = identity::Keypair::generate_ed25519()
        .public()
        .into_peer_id();
    let second = PeerId::from_bytes(peer_id.clone().into_bytes()).unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn peer_id_to_base58_then_back() {
    let peer_id = identity::Keypair::generate_ed25519()
        .public()
        .into_peer_id();
    let second: PeerId = peer_id.to_base58().parse().unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn random_peer_id_is_valid() {
    for _ in 0..5000 {
        let peer_id = PeerId::random();
        assert_eq!(
            peer_id,
            PeerId::from_bytes(peer_id.clone().into_bytes()).unwrap()
        );
    }
}
