/// # Example POP3 Session
///
/// S: <wait for connection on TCP port 110>
/// C: <open connection>
/// S:    +OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
/// C:    APOP mrose c4c9334bac560ecc979e58001b3e22fb
/// S:    +OK mrose's maildrop has 2 messages (320 octets)
/// C:    STAT
/// S:    +OK 2 320
/// C:    LIST
/// S:    +OK 2 messages (320 octets)
/// S:    1 120
/// S:    2 200
/// S:    .
/// C:    RETR 1
/// S:    +OK 120 octets
/// S:    <the POP3 server sends message 1>
/// S:    .
/// C:    DELE 1
/// S:    +OK message 1 deleted
/// C:    RETR 2
/// S:    +OK 200 octets
/// S:    <the POP3 server sends message 2>
/// S:    .
/// C:    DELE 2
/// S:    +OK message 2 deleted
/// C:    QUIT
/// S:    +OK dewey POP3 server signing off (maildrop empty)
/// C:  <close connection>
/// S:  <wait for next connection>
use std::borrow::BorrowMut;
use std::fmt::{Display, Formatter, Write};
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Error, Result};
use log::{debug, error, info, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Semaphore};
use tokio::time::{self, Duration};

use crate::shutdown::Shutdown;
pub use proto::*;
use sled::IVec;

mod proto;
mod shutdown;

const MAX_CONNECTIONS: usize = 1024;

#[derive(Debug)]
struct Listener {
    db: sled::Db,

    listener: TcpListener,
    limit_connections: Arc<Semaphore>,
    notify_shutdown: broadcast::Sender<()>,
    shutdown_complete_rx: mpsc::Receiver<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
}

#[derive(Debug)]
struct Handler {
    db: sled::Db,

    connection: TcpStream,
    limit_connections: Arc<Semaphore>,
    shutdown: Shutdown,
}

pub async fn run(
    path: &std::path::Path,
    listener: TcpListener,
    shutdown: impl Future,
) -> Result<()> {
    let (notify_shutdown, _) = broadcast::channel(1);
    let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

    let mut server = Listener {
        db: sled::open(path)?,
        listener,
        limit_connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        notify_shutdown,
        shutdown_complete_tx,
        shutdown_complete_rx,
    };

    tokio::select! {
        res = server.run() => {
            if let Err(err) = res {
                error!("accept: {}", err);
            }
        },
        _ = shutdown => {
            info!("shutting down");
        }
    }

    let Listener {
        mut shutdown_complete_rx,
        shutdown_complete_tx,
        notify_shutdown,
        ..
    } = server;

    drop(notify_shutdown);
    drop(shutdown_complete_tx);

    let _ = shutdown_complete_rx.recv().await;

    Ok(())
}

impl Listener {
    async fn run(&mut self) -> Result<()> {
        info!("postman pop3 server is running");

        loop {
            self.limit_connections.acquire().await.forget();

            let socket = self.accept().await?;

            let mut handler = Handler {
                connection: socket,
                db: self.db.clone(),

                // The connection state needs a handle to the max connections
                // semaphore. When the handler is done processing the
                // connection, a permit is added back to the semaphore.
                limit_connections: self.limit_connections.clone(),

                // Receive shutdown notifications.
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
            };

            tokio::spawn(async move {
                if let Err(err) = handler.run().await {
                    error!("{}", err);
                }
            });
        }

        Ok(())
    }

    async fn accept(&mut self) -> crate::Result<TcpStream> {
        let mut backoff = 1;

        // Try to accept a few times
        loop {
            // Perform the accept operation. If a socket is successfully
            // accepted, return it. Otherwise, save the error.
            match self.listener.accept().await {
                Ok((socket, _)) => return Ok(socket),
                Err(err) => {
                    if backoff > 64 {
                        // Accept has failed too many times. Return the error.
                        return Err(err.into());
                    }
                }
            }

            // Pause execution until the back off period elapses.
            time::sleep(Duration::from_secs(backoff)).await;

            // Double the back off
            backoff *= 2;
        }
    }
}

impl Handler {
    fn get(&self, key: usize) -> Result<MessageMeta> {
        match self.db.get(key.to_be_bytes()) {
            Err(e) => Err(anyhow::anyhow!("db: read {}: {}", key, e)),
            Ok(v) => match v {
                None => Err(anyhow::anyhow!("db: read {}: not found")),
                Some(v) => Ok(bincode::deserialize(v.as_ref())?),
            },
        }
    }
    fn set(&self, key: usize, value: &MessageMeta) -> Result<()> {
        self.db
            .insert(key.to_be_bytes(), bincode::serialize(value)?.as_slice())?;

        Ok(())
    }
    async fn run(&mut self) -> crate::Result<()> {
        let (mut r, mut w) = self.connection.split();

        let greet = Response::GREET("Welcome to postman pop3 server".to_string());
        info!("S: {:?}", &greet);
        w.write(greet.to_string()?.as_bytes()).await?;

        let mut r = BufReader::new(r);
        loop {
            let s = read_line(&mut r).await?;
            if s.is_empty() {
                continue;
            }

            let req = Request::from_str(s.as_str())?;
            info!("C: {:?}", &req);

            let resp = match req {
                Request::USER(v) => Response::USER("".to_string()),
                Request::PASS(_) => Response::PASS("".to_string()),
                Request::STAT => Response::STAT { count: 10, size: 8 },
                Request::UIDL(_) => unimplemented!(),
                Request::LIST(_) => unimplemented!(),
                Request::RETR(_) => unimplemented!(),
                Request::DELE(_) => unimplemented!(),
                Request::NOOP => unimplemented!(),
                Request::RSET => unimplemented!(),
                Request::QUIT => unimplemented!(),
                Request::AUTH(v) => match v {
                    None => Response::AUTH(AuthResponse::All(Vec::new())),
                    Some(auth) => unimplemented!(),
                },
                Request::CAPA => {
                    let mut caps = Vec::new();
                    caps.push(String::from("TOP"));
                    caps.push(String::from("USER"));
                    caps.push(String::from("UIDL"));

                    Response::CAPA(caps)
                }
                Request::TOP { id, lines } => unimplemented!(),
                Request::APOP { username, digest } => unimplemented!(),
            };

            info!("S: {:?}", &resp);
            w.write(resp.to_string()?.as_bytes()).await;
        }

        Ok(())
    }
}

async fn read_line(mut src: impl AsyncBufReadExt + Unpin) -> Result<String> {
    let mut data: Vec<u8> = Vec::with_capacity(1024);

    loop {
        let n = src.read_until(b'\n', &mut data).await?;
        // No data read, just return current buf instead.
        if n == 0 && data.is_empty() {
            return Ok(String::from_utf8_lossy(data.as_ref()).to_string());
        }
        // Reach EOF or data is end with "\r\n", return current buf directly.
        if n == 0 || data.ends_with("\r\n".as_bytes()) {
            break;
        }
    }

    debug!(
        "read from tcp: {:?}",
        String::from_utf8_lossy(data.as_ref()).to_string()
    );
    Ok(String::from_utf8_lossy(data.as_ref()).to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tokio::net::TcpListener;
    use tokio::signal;

    #[tokio::test]
    async fn debug_run() -> Result<()> {
        let mut log_builder = env_logger::Builder::new();
        log_builder.filter_level(log::LevelFilter::Debug);
        log_builder.filter_module("sled", log::LevelFilter::Error);
        log_builder.parse_default_env();
        log_builder.init();

        let listener = TcpListener::bind(&format!("127.0.0.1:{}", 8080)).await?;

        run(
            PathBuf::from_str("/tmp/data")?.as_path(),
            listener,
            signal::ctrl_c(),
        )
        .await
    }
}
