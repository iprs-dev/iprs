use super::*;
use crate::identity;

#[test]
fn peer_id_is_public_key() {
    let key = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key();

    let peer_id = key.clone().into_peer_id().unwrap();
    assert_eq!(peer_id.is_public_key(&key), Some(true));
}

#[test]
fn peer_id_into_bytes_then_from_bytes() {
    let peer_id = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();

    let bytes = peer_id.clone().into_bytes().unwrap();
    let (second, _) = PeerId::from_slice(&bytes).unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn peer_id_to_base58_then_back1() {
    let peer_id = identity::Keypair::generate_ed25519()
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();
    println!("PEER_ID BASE58 {}", peer_id.to_base58().unwrap());
    let second: PeerId = PeerId::from_base58(&peer_id.to_base58().unwrap()).unwrap();
    assert_eq!(peer_id, second);
}

const RSA_KEY: &'static [u8] = include_bytes!("identity/test/rsa-2048.pk8");

#[test]
fn peer_id_to_base58_then_back2() {
    let mut key = RSA_KEY.to_vec();
    let peer_id = identity::Keypair::from_rsa_pkcs8(&mut key)
        .unwrap()
        .to_public_key()
        .into_peer_id()
        .unwrap();
    println!("PEER_ID BASE58 {}", peer_id.to_base58().unwrap());
    let second: PeerId = PeerId::from_base58(&peer_id.to_base58().unwrap()).unwrap();
    assert_eq!(peer_id, second);
}

#[test]
fn from_bs32() {
    use crate::multibase::Multibase;

    let data = "bafzbeie5745rpv2m6tjyuugywy4d5ewrqgqqhfnf445he3omzpjbx5xqxe";
    let mb = Multibase::decode(data.as_bytes()).unwrap();
}

//#[test]
//fn peer_id_to_base58_then_back1() {
//    let peer_id = identity::Keypair::generate_ed25519()
//        .unwrap()
//        .to_public_key()
//        .into_peer_id()
//        .unwrap();
//    println!("PEER_ID BASE58 {}", peer_id.to_base58().unwrap());
//    let second: PeerId = PeerId::from_base58(&peer_id.to_base58().unwrap()).unwrap();
//    assert_eq!(peer_id, second);
//}
//
//#[test]
//fn peer_id_to_base58_then_back2() {
//    let mut key = RSA_KEY.to_vec();
//    let peer_id = identity::Keypair::rsa_from_pkcs8(&mut key)
//        .unwrap()
//        .to_public_key()
//        .into_peer_id()
//        .unwrap();
//    println!("PEER_ID BASE58 {}", peer_id.to_base58().unwrap());
//    let second: PeerId = PeerId::from_base58(&peer_id.to_base58().unwrap()).unwrap();
//    assert_eq!(peer_id, second);
//}

//#[test]
//fn random_peer_id_is_valid() {
//    for _ in 0..5000 {
//        let peer_id = PeerId::random();
//        assert_eq!(
//            peer_id,
//            PeerId::from_bytes(peer_id.clone().into_bytes()).unwrap()
//        );
//    }
//}
