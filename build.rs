use std::process;

macro_rules! check_exit {
    ($res:expr, $n:expr) => {{
        match $res {
            Ok(_) => (),
            Err(err) => {
                println!("{}", err);
                process::exit($n);
            }
        }
    }};
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    check_exit!(build_proto(), 1)
}

fn build_proto() -> Result<(), String> {
    // mark for rerun

    let protos = ["src/keys.proto"];
    let includes = ["src"];

    prost_build::compile_protos(&protos, &includes).map_err(|e| e.to_string())?;

    for file in protos.iter() {
        println!("cargo:rerun-if-changed={}", file)
    }

    Ok(())
}
