use super::*;
use crate::identity;

#[test]
fn test_peer_id_is_public_key() {
    let key = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key();

    let peer_id = key.clone().into_peer_id().unwrap();
    assert_eq!(peer_id.is_public_key(&key), Some(true));
}

#[test]
fn test_peer_id_encode_decode() {
    let peer_id = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();

    let bytes = peer_id.clone().encode().unwrap();
    let (second, _) = PeerId::decode(&bytes).unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn test_peer_id_to_base58_then_back1() {
    let peer_id = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();
    let text = peer_id.to_base58btc().unwrap();
    println!(".... PEER_ID BASE58 {}", text);
    let second: PeerId = PeerId::from_text(&text).unwrap();
    assert_eq!(peer_id, second);
}

const RSA_KEY: &'static [u8] = include_bytes!("identity/testdata/rsa-2048.pk8");

#[test]
fn peer_id_to_base58_then_back2() {
    let mut key = RSA_KEY.to_vec();
    let peer_id = identity::Keypair::from_rsa_pkcs8(&mut key)
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();
    let text = peer_id.to_base58btc().unwrap();
    println!(".... PEER_ID BASE58 {}", text);
    let second: PeerId = PeerId::from_text(&text).unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn test_peer_id_examples() {
    let text = "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe";
    let peer_id = PeerId::from_text(text).unwrap();
    // TODO: verify the hash value.
    assert_eq!(peer_id.to_base_text(Base::Base32Lower).unwrap(), text);
    let data = peer_id.encode().unwrap();
    assert_eq!(PeerId::decode(&data).unwrap().0, peer_id);

    let text = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
    let peer_id = PeerId::from_text(text).unwrap();
    // TODO: verify the hash value.
    assert_eq!(peer_id.to_base58btc().unwrap(), text);
    let data = peer_id.encode().unwrap();
    assert_eq!(PeerId::decode(&data).unwrap().0, peer_id);

    let text = "12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA";
    let peer_id = PeerId::from_text(text).unwrap();
    // TODO: verify the hash value.
    assert_eq!(peer_id.to_base58btc().unwrap(), text);
    let data = peer_id.encode().unwrap();
    assert_eq!(PeerId::decode(&data).unwrap().0, peer_id);
}
