use super::*;

use digest::Digest;

#[test]
fn test_cid_v1() {
    let data = b"beep boop";
    let cid = {
        let base = Base::Base32Lower;
        Cid::new_v1(base, multicodec::DAG_PB.into(), data).unwrap()
    };

    let return_cid = Cid::decode(&cid.encode().unwrap()).unwrap().0;
    assert_eq!(cid, return_cid);

    let return_cid = Cid::from_text(&cid.to_text(None).unwrap()).unwrap();
    assert_eq!(cid, return_cid);

    assert_eq!(cid.to_version(), Version::One);
    assert_eq!(cid.to_base(), Base::Base32Lower);
    assert_eq!(cid.to_content_type(), multicodec::DAG_PB.into());

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize_reset().as_slice().to_vec();
    assert_eq!(cid.to_multihash().to_digest().unwrap(), digest);
}

#[test]
fn test_cid_v0() {
    let data = b"beep boop";
    let cid = Cid::new_v0(data).unwrap();

    let return_cid = Cid::decode(&cid.encode().unwrap()).unwrap().0;
    assert_eq!(cid, return_cid);

    let return_cid = Cid::from_text(&cid.to_text(None).unwrap()).unwrap();
    assert_eq!(cid, return_cid);

    assert_eq!(cid.to_version(), Version::Zero);
    assert_eq!(cid.to_base(), Base::Base58Btc);
    assert_eq!(cid.to_content_type(), multicodec::DAG_PB.into());

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize_reset().as_slice().to_vec();
    assert_eq!(cid.to_multihash().to_digest().unwrap(), digest);
}

#[test]
fn test_cid_v0_decode() {
    let s = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n";
    let cid = Cid::from_text(s).unwrap();

    assert_eq!(cid.to_version(), Version::Zero);
    assert_eq!(cid.to_text(None).unwrap(), s);
}

#[test]
fn test_cid_v0_str() {
    let cid: Cid = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n"
        .parse()
        .unwrap();
    assert_eq!(cid.to_version(), Version::Zero);

    let bad = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zIII".parse::<Cid>();
    assert!(bad.is_err())
}

#[test]
fn test_cid_v0_error() {
    let cid: Result<Cid> = "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zIII".parse();
    assert!(cid.is_err())
}

#[test]
fn test_cid_v1_base32() {
    let cid = {
        let s = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
        Cid::from_str(s).unwrap()
    };
    assert_eq!(cid.to_version(), Version::One);
    assert_eq!(cid.to_content_type(), multicodec::RAW.into());
    let digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"foo");
        hasher.finalize_reset().as_slice().to_vec()
    };
    assert_eq!(cid.to_multihash().to_digest().unwrap(), digest);

    let expected_cid = "bafkreibme22gw2h7y2h7tg2fhqotaqjucnbc24deqo72b6mkl2egezxhvy";
    let cid = Cid::new_v1(Base::Base32Lower, multicodec::RAW.into(), b"foo").unwrap();
    assert_eq!(cid.to_text(None).unwrap(), expected_cid);
}

#[test]
fn test_cid_v1_base64() {
    let expected_cid = "mAVUSICwmtGto/8aP+ZtFPB0wQTQTQi1wZIO/oPmKXohiZueu";
    let cid = Cid::new_v1(Base::Base64, multicodec::RAW.into(), b"foo").unwrap();
    assert_eq!(cid.to_text(None).unwrap(), expected_cid);
}

#[test]
fn to_string_of_base58_v0() {
    let expected_cid = "QmRJzsvyCQyizr73Gmms8ZRtvNxmgqumxc2KUp71dfEmoj";
    let cid = Cid::new_v0(b"foo").unwrap();
    assert_eq!(cid.to_text(None).unwrap(), expected_cid);
}
