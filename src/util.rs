//! Module implement useful functions.

use crossbeam_channel as cbm;
use rand::{
    rngs::{SmallRng, StdRng},
    SeedableRng,
};

use std::{ffi, path, time};

use crate::{Error, Result};

/// Short form to compose Error values.
///
/// Here are few possible ways:
///
/// ```ignore
/// use crate::Error;
/// err_at!(Error::Invalid(String::default(), "bad argument"));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, msg: format!("bad argument"));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, std::io::read(buf));
/// ```
///
/// ```ignore
/// use crate::Error;
/// err_at!(Invalid, std::fs::read(file_path), format!("read failed"));
/// ```
///
#[macro_export]
macro_rules! err_at {
    ($v:ident, msg:$m:expr) => {{
        use log::error;

        let prefix = format!("{}:{}", file!(), line!());
        let err = Error::$v(prefix, format!("{}", $m));
        error!(target: "libp2p", "{}", err);
        Err(err)
    }};
    ($v:ident, $e:expr) => {{
        use log::error;

        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                let err = Error::$v(prefix, format!("{}", err));
                error!(target: "libp2p", "{}", err);

                Err(err)
            }
        }
    }};
    ($v:ident, $e:expr, $m:expr) => {{
        use log::error;

        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                let err = Error::$v(prefix, format!("{} {}", $m, err));
                error!(target: "libp2p", "{}", err);

                Err(err)
            }
        }
    }};
}

pub fn ctrl_channel() -> Result<cbm::Receiver<time::Instant>> {
    let (sender, receiver) = cbm::bounded(100);
    err_at!(
        SysFail,
        ctrlc::set_handler(move || {
            let _ = sender.send(time::Instant::now());
        })
    )?;

    Ok(receiver)
}

/// Convert relative path, and ~ path into absolute path. Note that
/// the supplied path must exist.
pub fn canonicalize(loc: ffi::OsString) -> Result<ffi::OsString> {
    use std::iter::FromIterator;

    let loc = err_at!(FilePath, loc.into_string().map_err(|e| format!("{:?}", e)))?;
    let mut chars = loc.chars();

    let home = dirs::home_dir();
    let mut pbuf = path::PathBuf::new();

    let loc = match (chars.next(), chars.next()) {
        (Some('~'), Some(path::MAIN_SEPARATOR)) if home.is_some() => {
            pbuf.push(home.unwrap());
            pbuf.push(String::from_iter(
                loc.chars().take(2).collect::<Vec<char>>(),
            ));
            pbuf.into()
        }
        (Some('~'), Some(path::MAIN_SEPARATOR)) => loc.into(),
        _ => {
            pbuf.push(loc);
            err_at!(FilePath, pbuf.canonicalize())?.into()
        }
    };

    Ok(loc)
}

/// Create a new insecure but fast psuedo-random-number-generator.
pub fn new_prng(seed: Option<u128>) -> Result<SmallRng> {
    let rng = match seed {
        Some(seed) => SmallRng::from_seed(seed.to_be_bytes()),
        None => SmallRng::from_entropy(),
    };

    Ok(rng)
}

/// Create a new cryptographically secure psuedo-random-number-generator.
pub fn new_csprng(seed: Option<u128>) -> Result<StdRng> {
    let seed = seed.unwrap_or(
        err_at!(
            SysFail,
            time::SystemTime::now().duration_since(time::UNIX_EPOCH)
        )?
        .as_nanos(),
    );
    let seed = {
        let mut s = [0_u8; 32];
        let seed = seed.to_be_bytes();
        s[..16].copy_from_slice(&seed);
        s[16..].copy_from_slice(&seed);
        s
    };
    Ok(StdRng::from_seed(seed))
}

/// Check whether _ENV_VAR_ `name` is set to "true" or "t" or "1"
pub fn get_env_bool(name: String) -> bool {
    use std::env;

    match env::var(&name).unwrap_or("".to_string()).as_str() {
        "true" | "t" | "1" => true,
        _ => false,
    }
}

/// XOR two slice and return the new slice.
#[inline]
pub fn xor_slice(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
