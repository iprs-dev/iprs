use log::{debug, error, info, trace, warn};
use simplelog;

use std::io;

fn main() {
    init_logger(None, true, true).unwrap();
}

fn init_logger(log_file: Option<String>, trace: bool, verbose: bool) -> Result<(), String> {
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
            .set_location_level(simplelog::LevelFilter::Off)
            .set_target_level(simplelog::LevelFilter::Off)
            .set_thread_mode(simplelog::ThreadLogMode::Both)
            .set_thread_level(simplelog::LevelFilter::Error)
            .set_time_to_local(true)
            .set_time_format("[%Y-%m-%dT%H:%M:%S%.3fZ]".to_string())
            .build()
    };

    match log_file {
        Some(log_file) => {
            let p = path::Path::new(&log_file);
            let log_file = if p.is_relative() {
                let mut cwd = env::current_dir().map_err(|e| e.to_string())?;
                cwd.push(&p);
                cwd.into_os_string()
            } else {
                p.as_os_str().to_os_string()
            };
            let fl = fs::File::create(&log_file).map_err(|e| e.to_string())?;
            simplelog::WriteLogger::init(level_filter, config, fl)
        }
        None => simplelog::WriteLogger::init(level_filter, config, io::stdout()),
    }
    .map_err(|e| e.to_string())
}
