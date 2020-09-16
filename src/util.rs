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
        use Error::*;

        let p = format!("{}:{}", file!(), line!());
        match $e {
            Ok(val) => Ok(val),
            Err(Fatal(_, s)) => Err(Fatal(p, s)),
            Err(IOError(_, s)) => Err(IOError(p, s)),
            Err(Invalid(_, s)) => Err(Invalid(p, s)),
            Err(DecodeError(_, s)) => Err(DecodeError(p, s)),
            Err(EncodeError(_, s)) => Err(EncodeError(p, s)),
            Err(SigningError(_, s)) => Err(SigningError(p, s)),
            Err(BadInput(_, s)) => Err(BadInput(p, s)),
            Err(BadCodec(_, s)) => Err(BadCodec(p, s)),
            Err(HashFail(_, s)) => Err(HashFail(p, s)),
            Err(NotImplemented(_, s)) => Err(NotImplemented(p, s)),
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
