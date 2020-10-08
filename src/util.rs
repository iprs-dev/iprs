// Copyright (c) 2020 R Pratap Chakravarthy

use crossbeam_channel as cbm;

use std::time;

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
