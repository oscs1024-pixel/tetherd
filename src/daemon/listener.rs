use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::config::Config;
use crate::daemon::connection::{serve, SharedState};
use crate::daemon::control;
use crate::{Error, Result};

pub async fn run(config: Arc<Config>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let psk = Arc::new(config.auth.load_psk()?);
    let listener = TcpListener::bind(config.daemon.listen).await?;
    let local_addr = listener.local_addr()?;
    log::info!("daemon started listening={local_addr}");

    let state = Arc::new(SharedState::default());
    let connections = Arc::new(Semaphore::new(config.daemon.max_connections));
    let mut sessions = JoinSet::new();
    let mut control_task = tokio::spawn(control::serve(
        config.daemon.control_socket.clone(),
        state.clone(),
        Duration::from_secs(config.daemon.control_timeout_secs),
        Duration::from_secs(config.daemon.control_request_timeout_secs),
        config.daemon.max_control_connections,
        shutdown.clone(),
    ));

    let loop_result = loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, remote_addr) = match accepted {
                    Ok(value) => value,
                    Err(err) => break Err(err.into()),
                };
                if let Err(err) = stream.set_nodelay(true) {
                    log::warn!("failed to configure peer socket remote={} error={err}", remote_addr);
                    continue;
                }
                log::info!("peer connected addr={remote_addr}");
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!("connection limit reached remote={remote_addr}");
                        drop(stream);
                        continue;
                    }
                };
                let psk = psk.clone();
                let state = state.clone();
                let credential = config.auth.credential.clone();
                let heartbeat_timeout = config.heartbeat_timeout();
                let handshake_timeout = Duration::from_secs(config.daemon.handshake_timeout_secs);
                sessions.spawn(async move {
                    let _permit = permit;
                    serve(
                        stream,
                        remote_addr,
                        psk,
                        credential,
                        heartbeat_timeout,
                        handshake_timeout,
                        state,
                    )
                    .await
                    .map_err(|err| (remote_addr, err))
                });
            }
            joined = sessions.join_next(), if !sessions.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err((remote, err)))) => {
                        log::warn!("peer session ended remote={} error={err}", remote);
                    }
                    Some(Err(err)) if err.is_cancelled() => {}
                    Some(Err(err)) => log::warn!("peer task join failure error={err}"),
                    None => {}
                }
            }
            control_result = &mut control_task => {
                break match control_result {
                    Ok(Ok(())) if *shutdown.borrow() => Ok(()),
                    Ok(Ok(())) => Err(Error::Control("control service exited unexpectedly".into())),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(Error::Control(format!("control task failed: {err}"))),
                };
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
        }
    };

    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    if !control_task.is_finished() {
        control_task.abort();
    }
    log::info!("daemon stopped");
    loop_result
}
