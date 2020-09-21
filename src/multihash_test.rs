// Copyright (c) 2020 R Pratap Chakravarthy

use super::*;
use multibase::Base;

#[test]
fn test_sha2_256() {
    use crate::multibase;

    let mut mh = Multihash::from_codec(multicodec::SHA2_256.into()).unwrap();
    mh.write("hello world".as_bytes())
        .unwrap()
        .finish()
        .unwrap();

    let data = mh.encode().unwrap();
    let mb = multibase::Multibase::from_base(Base::Base16Lower, &data).unwrap();
    let orig = "f1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    assert_eq!(mb.encode().unwrap(), orig);

    mh.reset().unwrap();
    mh.write("hello world".as_bytes())
        .unwrap()
        .finish()
        .unwrap();

    let data = mh.encode().unwrap();
    let mb = multibase::Multibase::from_base(Base::Base16Lower, &data).unwrap();
    let orig = "f1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    assert_eq!(mb.encode().unwrap(), orig);
}

#[test]
fn test_multihash_pretty() {
    let mut mh = Multihash::from_codec(multicodec::SHA2_256.into()).unwrap();
    mh.write("hello world".as_bytes())
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        format!("{}", mh),
        "sha2-256-256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
}
