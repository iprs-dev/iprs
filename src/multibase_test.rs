use super::*;
use reqwest::blocking::get;

#[test]
fn test_base_spec() {
    let spec = {
        let uri = "https://raw.githubusercontent.com/multiformats/multibase/master/multibase.csv";
        get(uri).unwrap().text().unwrap()
    };

    let spec_lines: Vec<(String, char, String)> = {
        let mut total_lines: Vec<String> = {
            let iter = spec.lines().map(|s| s.to_string());
            iter.collect()
        };
        total_lines.remove(0); // remove the column header.
        total_lines
            .into_iter()
            .map(|s| {
                let mut cols: Vec<&str> = s.split(",").map(|col| col.trim()).collect();
                cols.pop();
                match cols.as_slice() {
                    [n, "0x00", d] => (n.to_string(), '\0', d.to_string()),
                    [n, ch, d] => {
                        let ch = ch.chars().nth(0).unwrap();
                        (n.to_string(), ch, d.to_string())
                    }
                    _ => panic!("{:?}", cols),
                }
            })
            .collect()
    };

    let pkg_lines: Vec<(String, char, String)> = (&TABLE)
        .to_vec()
        .into_iter()
        .map(|(name, ch, descr)| (name.to_string(), ch, descr.to_string()))
        .collect();

    assert_eq!(
        spec_lines.len(),
        pkg_lines.len(),
        "{} {}",
        spec_lines.len(),
        pkg_lines.len()
    );

    for (x, y) in spec_lines.into_iter().zip(pkg_lines.into_iter()) {
        assert_eq!(x.0, y.0, "{:?}, {:?}", x, y);
        assert_eq!(x.1, y.1, "{:?}, {:?}", x, y);
        assert_eq!(x.2, y.2, "{:?}, {:?}", x, y);
    }
}

#[test]
fn test_base_formats() {
    use std::str::from_utf8;

    for row in TABLE.iter() {
        match row.1 {
            'k' | 'K' => continue,
            _ => (),
        }

        let mb = Multibase::from_char(row.1, "hello world".as_bytes()).unwrap();
        let out = mb.encode().unwrap();
        println!("{:?} {}", row.1, from_utf8(&out).unwrap());

        let data = Multibase::decode(&out).unwrap().to_bytes().unwrap();
        let text = from_utf8(&data).unwrap();
        assert_eq!(text, "hello world");
    }
}
