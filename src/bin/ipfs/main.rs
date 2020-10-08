#![feature(partition_point)]

#[allow(unused_imports)]
use log::debug;
use structopt::StructOpt;

use std::io;

use iprs::{
    err_at,
    ipfsd::{self, Ipfsd},
    Error, Result,
};

// TODO: cpu-profiling, mem-profiling.

#[derive(Debug, StructOpt)]
pub struct Opt {
    #[structopt(long = "seed")]
    seed: Option<u128>,

    #[structopt(long = "log-file")]
    log_file: Option<String>,

    #[structopt(short = "v", long = "verbose")]
    verbose: bool,

    #[structopt(long = "trace")]
    trace: bool,
}

// main 'o' main
fn main() -> Result<()> {
    let (args, cmd_args) = split_args(std::env::args().collect());

    let opts = Opt::from_iter(args.into_iter()); // "ipfs" options
    init_logger(opts.log_file, opts.verbose, opts.trace).unwrap();

    let d = err_at!(ThreadFail, Ipfsd::spawn())?;
    d.close_wait()?;

    Ok(())
}

fn split_args<T>(args: Vec<T>) -> (Vec<T>, Vec<T>)
where
    T: ToString + Clone,
{
    if args.len() == 0 {
        return (vec![], vec![]);
    }
    let i = args[1..].partition_point(|x| x.to_string().starts_with("-")) + 1;
    (args[..i].to_vec(), args[i..].to_vec())
}

fn init_logger(log_file: Option<String>, verbose: bool, trace: bool) -> Result<()> {
    use std::{env, fs, path};

    let level_filter = if trace {
        simplelog::LevelFilter::Trace
    } else if verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };

    let config = {
        let mut config = simplelog::ConfigBuilder::new();
        config
            .set_location_level(level_filter)
            .set_target_level(simplelog::LevelFilter::Off)
            .set_thread_mode(simplelog::ThreadLogMode::Both)
            .set_thread_level(simplelog::LevelFilter::Off)
            .set_time_to_local(true)
            .set_time_format("[%Y-%m-%dT%H:%M:%S%.3fZ]".to_string())
            .build()
    };

    let val = match log_file {
        Some(log_file) => {
            let p = path::Path::new(&log_file);
            let log_file = if p.is_relative() {
                let mut cwd = err_at!(Fatal, env::current_dir())?;
                cwd.push(&p);
                cwd.into_os_string()
            } else {
                p.as_os_str().to_os_string()
            };
            let fl = err_at!(Fatal, fs::File::create(&log_file))?;
            err_at!(
                Fatal,
                simplelog::WriteLogger::init(level_filter, config, fl)
            )?
        }
        None => err_at!(
            Fatal,
            simplelog::WriteLogger::init(level_filter, config, io::stdout())
        )?,
    };

    Ok(val)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_split_args() {
        let (args, cmd_args) = split_args::<String>(vec![]);
        assert_eq!(args, Vec::<String>::default());
        assert_eq!(cmd_args, Vec::<String>::default());

        let (args, cmd_args) = split_args(vec!["ipfs"]);
        assert_eq!(args, vec!["ipfs"]);
        assert_eq!(cmd_args, Vec::<String>::default());

        let (args, cmd_args) = split_args(vec!["ipfs", "--help"]);
        assert_eq!(args, vec!["ipfs", "--help"]);
        assert_eq!(cmd_args, Vec::<String>::default());

        let (args, cmd_args) = split_args(vec!["ipfs", "--version", "init"]);
        assert_eq!(args, vec!["ipfs", "--version"]);
        assert_eq!(cmd_args, vec!["init"]);

        let (args, cmd_args) = split_args(vec!["ipfs", "--version", "init", "--help"]);
        assert_eq!(args, vec!["ipfs", "--version"]);
        assert_eq!(cmd_args, vec!["init", "--help"]);
    }
}
