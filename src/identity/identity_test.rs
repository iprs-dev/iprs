use super::*;

const RSA_KEY: &'static [u8] = include_bytes!("testdata/rsa-2048.pk8");

#[test]
fn rsa_api() {
    let mut key = RSA_KEY.to_vec();
    println!(".... RSA Keypair len : {}", key.len());

    let kp = Keypair::from_rsa_pkcs8(&mut key).unwrap();

    let signature = kp.sign("hello world".as_bytes()).unwrap();

    assert!(kp
        .to_public_key()
        .verify("hello world".as_bytes(), &signature))
}

#[test]
fn ed25519_api() {
    let kp = Keypair::generate_ed25519().unwrap();
    let mut data = match kp {
        Keypair::Ed25519(kp) => kp.encode(),
        _ => unreachable!(),
    };

    println!(".... ED25519 Keypair len : {}", data.len());

    let kp = Keypair::from_ed25519_bytes(&mut data).unwrap();

    let signature = kp.sign("hello world".as_bytes()).unwrap();

    assert!(kp
        .to_public_key()
        .verify("hello world".as_bytes(), &signature))
}

//#[test]
//fn secp256k1_api() {
//    let kp = Keypair::generate_secp256k1().unwrap();
//    let mut data = match kp {
//        Keypair::Secp256k1(kp) => kp.as_secret_key().to_bytes(),
//        _ => unreachable!(),
//    };
//
//    println!("SECP256K1 Keypair len : {}", data.len());
//
//    let kp = Keypair::secp256k1_from_der(&mut data).unwrap();
//
//    let signature = kp.sign("hello world".as_bytes()).unwrap();
//
//    assert!(kp
//        .to_public_key()
//        .verify("hello world".as_bytes(), &signature))
//}
