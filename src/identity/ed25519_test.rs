use super::*;
use quickcheck::*;

fn eq_keypairs(kp1: &Keypair, kp2: &Keypair) -> bool {
    let ok = kp1.to_public_key() == kp2.to_public_key();
    ok && (kp1.key_pair.secret.as_bytes() == kp2.key_pair.secret.as_bytes())
}

#[test]
fn ed25519_keypair_encode_decode() {
    fn prop() -> bool {
        let kp1 = Keypair::generate().unwrap();
        let mut kp1_enc = kp1.encode();
        let kp2 = Keypair::decode(&mut kp1_enc).unwrap();
        eq_keypairs(&kp1, &kp2) && kp1_enc.iter().all(|b| *b == 0)
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
}

#[test]
fn ed25519_keypair_from_secret() {
    fn prop() -> bool {
        let kp1 = Keypair::generate().unwrap();
        let mut sk = kp1.key_pair.secret.to_bytes();
        let kp2 = Keypair::from(SecretKey::from_bytes(&mut sk).unwrap());
        eq_keypairs(&kp1, &kp2) && sk == [0u8; 32]
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
}

#[test]
fn ed25519_signature() {
    let kp = Keypair::generate().unwrap();
    let pk = kp.to_public_key();

    let msg = "hello world".as_bytes();
    let sig = kp.sign(msg).unwrap();
    assert!(pk.verify(msg, &sig));

    let mut invalid_sig = sig.clone();
    invalid_sig[3..6].copy_from_slice(&[10, 23, 42]);
    assert!(!pk.verify(msg, &invalid_sig));

    let invalid_msg = "h3ll0 w0rld".as_bytes();
    assert!(!pk.verify(invalid_msg, &sig));
}
