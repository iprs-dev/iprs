use std::{fs, path};

use crate::ipld::sgrammar;

#[test]
fn test_ipld_schema() {
    let test_files: Vec<(path::PathBuf, String)> = fs::read_dir("./src/ipld/testdata")
        .expect("fail-readdir")
        .map(|e| e.expect("invalid-entry"))
        .filter_map(|e| {
            path::Path::new(&e.file_name())
                .extension()
                .map(|x| (e.path(), x.to_os_string()))
        })
        .filter_map(|(p, x)| x.to_str().map(|x| (p, x.to_string())))
        .collect();

    for (test_file, ext) in test_files.into_iter() {
        if "ipld" != ext.as_str() {
            continue;
        }
        let mut data = fs::read(test_file).unwrap();
        let text = {
            data.push('\n' as u8);
            std::str::from_utf8(&data).unwrap()
        };
        let ast = sgrammar::RecordsParser::new().parse(text).unwrap();
        println!("{:?}", ast);
    }
}
