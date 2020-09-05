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
    ($e:expr) => {{
        use Error::{IOError, Invalid};

        let p = format!("{}:{}", file!(), line!());
        match $e {
            Ok(val) => Ok(val),
            Err(Invalid(_, s)) => Err(Invalid(p, s)),
            Err(IOError(_, s)) => Err(IOError(p, s)),
        }
    }};
    ($v:ident, msg:$m:expr) => {{
        let prefix = format!("{}:{}", file!(), line!());
        Err(Error::$v(prefix, format!("{}", $m)))
    }};
    ($v:ident, $e:expr) => {
        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                Err(Error::$v(prefix, format!("{}", err)))
            }
        }
    };
    ($v:ident, $e:expr, $m:expr) => {
        match $e {
            Ok(val) => Ok(val),
            Err(err) => {
                let prefix = format!("{}:{}", file!(), line!());
                Err(Error::$v(prefix, format!("{} {}", $m, err)))
            }
        }
    };
}
