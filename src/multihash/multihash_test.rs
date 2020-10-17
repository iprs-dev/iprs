use super::*;
use multibase::Base;

#[test]
fn test_sha1() {
    use crate::multibase;

    let mh = {
        let data = "Hello world".as_bytes();
        Multihash::new(multicodec::SHA1.into(), data).unwrap()
    };

    {
        let orig = "f11147b502c3a1f48c8609ae212cdfb639dee39673f5e";
        let data = mh.encode().unwrap();
        let mb = multibase::Multibase::with_base(Base::Base16Lower, &data).unwrap();
        assert_eq!(mb.to_text().unwrap(), orig);
    }
    {
        let orig = "f7b502c3a1f48c8609ae212cdfb639dee39673f5e";
        let data = mh.to_digest().unwrap();
        let mb = multibase::Multibase::with_base(Base::Base16Lower, &data).unwrap();
        assert_eq!(mb.to_text().unwrap(), orig);
    }
}

#[test]
fn test_sha2_256() {
    use crate::multibase;

    let mut mh = {
        let data = "Hello world".as_bytes();
        Multihash::new(multicodec::SHA2_256.into(), data).unwrap()
    };

    {
        let orig = "f122064ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c";
        let data = mh.encode().unwrap();
        let mb = multibase::Multibase::with_base(Base::Base16Lower, &data).unwrap();
        assert_eq!(mb.to_text().unwrap(), orig);
    }
    {
        let orig = "f64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c";
        let data = mh.to_digest().unwrap();
        let mb = multibase::Multibase::with_base(Base::Base16Lower, &data).unwrap();
        assert_eq!(mb.to_text().unwrap(), orig);
    }

    mh.reset().unwrap();
    mh.write("hello world".as_bytes())
        .unwrap()
        .finish()
        .unwrap();

    let data = mh.encode().unwrap();
    let mb = multibase::Multibase::with_base(Base::Base16Lower, &data).unwrap();
    let orig = "f1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    assert_eq!(mb.to_text().unwrap(), orig);
}

#[test]
fn test_multihash_pretty() {
    let mh = {
        let data = "hello world".as_bytes();
        Multihash::new(multicodec::SHA2_256.into(), data).unwrap()
    };
    assert_eq!(
        format!("{}", mh),
        "sha2-256-256-b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9".to_string(),
    );
}
