use log::{debug, error};

use std::{sync::mpsc, thread};

use crate::{Error, Result};

pub enum Req {
    Fin,
}

pub enum Res {
    None,
}

/// Client handle to communicate with ipfs-daemon.
pub struct Client {
    tx: mpsc::SyncSender<(Req, Option<mpsc::Sender<Res>>)>,
}

impl Client {
    /// post a request to ipfs-daemon and return.
    pub fn post(&mut self, msg: Req) -> Result<()> {
        err_at!(IPCFail, self.tx.send((msg, None)))?;
        Ok(())
    }

    /// request a response from ipfs-daemon.
    pub fn request(&mut self, request: Req) -> Result<Res> {
        let (tx, rx) = mpsc::channel();
        err_at!(IPCFail, self.tx.send((request, Some(tx))))?;
        Ok(err_at!(IPCFail, rx.recv())?)
    }
}

/// Ipfs daemon.
pub struct Ipfsd {
    tx: mpsc::SyncSender<(Req, Option<mpsc::Sender<Res>>)>,
    handle: Option<thread::JoinHandle<Result<()>>>,
}

impl Ipfsd {
    /// Create a daemon, using asynchronous channel with infinite buffer.
    pub fn spawn() -> Result<Ipfsd> {
        debug!("spawned in async mode");
        let (tx, rx) = mpsc::sync_channel(16); // TODO: no magic num.
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
        match self.to_client().request(Req::Fin) {
            Ok(_) => match self.handle.take() {
                Some(handle) => match handle.join() {
                    Ok(_) => debug!("ipfsd dropped"),
                    Err(err) => error!("drop fail {:?}", err),
                },
                None => debug!("ipfsd dropped"),
            },
            Err(err) => error!("fin fail {}", err),
        }
    }
}

fn run(rx: mpsc::Receiver<(Req, Option<mpsc::Sender<Res>>)>) -> Result<()> {
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

fn run_fin(tx: Option<mpsc::Sender<Res>>) -> Result<()> {
    match tx {
        Some(tx) => err_at!(IPCFail, tx.send(Res::None))?,
        None => (),
    }

    Ok(())
}
