use quickcheck::*;
use rand::seq::SliceRandom;

use std::fmt;

use super::*;

const KEY1: &'static [u8] = include_bytes!("testdata/rsa-2048.pk8");
const KEY2: &'static [u8] = include_bytes!("testdata/rsa-3072.pk8");
const KEY3: &'static [u8] = include_bytes!("testdata/rsa-4096.pk8");

#[derive(Clone)]
struct SomeKeypair(Keypair);

impl fmt::Debug for SomeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SomeKeypair")
    }
}

impl Arbitrary for SomeKeypair {
    fn arbitrary<G: Gen>(g: &mut G) -> SomeKeypair {
        let mut key = [KEY1, KEY2, KEY3].choose(g).unwrap().to_vec();
        SomeKeypair(Keypair::from_pkcs8(&mut key).unwrap())
    }
}

#[test]
fn rsa_from_pkcs8() {
    assert!(Keypair::from_pkcs8(&mut KEY1.to_vec()).is_ok());
    assert!(Keypair::from_pkcs8(&mut KEY2.to_vec()).is_ok());
    assert!(Keypair::from_pkcs8(&mut KEY3.to_vec()).is_ok());
}

#[test]
fn rsa_x509_encode_decode() {
    fn prop(SomeKeypair(kp): SomeKeypair) -> Result<bool> {
        let pk = kp.to_public_key();
        PublicKey::decode_x509(&pk.encode_x509()?).map(|pk2| pk2 == pk)
    }
    QuickCheck::new().tests(10).quickcheck(prop as fn(_) -> _);
}

#[test]
fn rsa_sign_verify() {
    fn prop(SomeKeypair(kp): SomeKeypair, msg: Vec<u8>) -> Result<bool> {
        kp.sign(&msg).map(|s| kp.to_public_key().verify(&msg, &s))
    }
    QuickCheck::new()
        .tests(10)
        .quickcheck(prop as fn(_, _) -> _);
}
