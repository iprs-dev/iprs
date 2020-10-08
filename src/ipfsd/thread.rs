use crossbeam_channel::{self as cbm, select};
use log::{debug, error};

use std::thread;

use crate::{util, Error, Result};

const MAX_CHANSIZE: usize = 16;

pub enum Req {
    Fin,
}

pub enum Res {
    None,
}

/// Client handle to communicate with ipfs-daemon.
pub struct Client {
    tx: cbm::Sender<(Req, Option<cbm::Sender<Res>>)>,
}

impl Client {
    /// post a request to ipfs-daemon and return.
    pub fn post(&mut self, msg: Req) -> Result<()> {
        err_at!(IPCFail, self.tx.send((msg, None)))?;
        Ok(())
    }

    /// request a response from ipfs-daemon.
    pub fn request(&mut self, request: Req) -> Result<Res> {
        let (tx, rx) = cbm::bounded(MAX_CHANSIZE);
        let ctrl_rx = util::ctrl_channel()?;

        err_at!(IPCFail, self.tx.send((request, Some(tx))))?;

        let rsp = select! {
            recv(rx) -> rsp => err_at!(IPCFail, rsp)?,
            recv(ctrl_rx) -> tm => {
                let tm = err_at!(IPCFail, tm)?;
                debug!("received control-c at {:?}", tm);
                Res::None
            }
        };

        Ok(rsp)
    }
}

/// Ipfs daemon.
pub struct Ipfsd {
    tx: cbm::Sender<(Req, Option<cbm::Sender<Res>>)>,
    handle: Option<thread::JoinHandle<Result<()>>>,
}

impl Ipfsd {
    /// Create a daemon, using asynchronous channel with infinite buffer.
    pub fn spawn() -> Result<Ipfsd> {
        debug!("spawned in async mode");
        let (tx, rx) = cbm::bounded(MAX_CHANSIZE);
        let handle = Some(thread::spawn(|| run(rx)));
        Ok(Ipfsd { tx, handle })
    }

    /// Return a sender channel.
    pub fn to_client(&self) -> Client {
        Client {
            tx: self.tx.clone(),
        }
    }

    /// Recommended call to exit and shutdown the daemon.
    pub fn close_wait(mut self) -> Result<()> {
        self.to_client().request(Req::Fin)?;
        match self.handle.take() {
            Some(handle) => match handle.join() {
                Ok(val) => Ok(val?),
                Err(err) => err_at!(ThreadFail, msg: format!("{:?}", err)),
            },
            None => Ok(()),
        }
    }
}

impl Drop for Ipfsd {
    fn drop(&mut self) {
        match self.handle.take() {
            Some(handle) => match self.to_client().request(Req::Fin) {
                Ok(_) => match handle.join() {
                    Ok(_) => debug!("ipfsd dropped"),
                    Err(err) => error!("drop fail {:?}", err),
                },
                Err(err) => error!("fin fail {}", err),
            },
            None => debug!("ipfsd dropped"),
        }
    }
}

fn run(rx: cbm::Receiver<(Req, Option<cbm::Sender<Res>>)>) -> Result<()> {
    for q in rx {
        match q {
            (Req::Fin, tx) => {
                run_fin(tx)?;
                break;
            }
        }
    }

    Ok(())
}

fn run_fin(tx: Option<cbm::Sender<Res>>) -> Result<()> {
    match tx {
        Some(tx) => err_at!(IPCFail, tx.send(Res::None))?,
        None => (),
    }

    Ok(())
}
