use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    let mut limiter = HandshakeLimiter::new(
        config.daemon.max_handshakes_per_minute,
        config.daemon.max_handshakes_per_ip_per_minute,
    );
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
                if !limiter.allow(remote_addr.ip(), Instant::now()) {
                    log::warn!("handshake rate limit reached remote={remote_addr}");
                    drop(stream);
                    continue;
                }
                if let Err(err) = stream.set_nodelay(true) {
                    log::warn!("failed to configure peer socket remote={} error={err}", remote_addr);
                    continue;
                }
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!("connection limit reached remote={remote_addr}");
                        drop(stream);
                        continue;
                    }
                };
                log::info!("peer connected addr={remote_addr}");
                let psk = psk.clone();
                let state = state.clone();
                let credential = config.auth.credential.clone();
                let heartbeat_timeout = config.heartbeat_timeout();
                let handshake_timeout = Duration::from_secs(config.daemon.handshake_timeout_secs);
                let write_timeout = Duration::from_secs(config.daemon.write_timeout_secs);
                sessions.spawn(async move {
                    let _permit = permit;
                    serve(
                        stream,
                        remote_addr,
                        psk,
                        credential,
                        heartbeat_timeout,
                        handshake_timeout,
                        write_timeout,
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
    let _ = control_task.await;
    log::info!("daemon stopped");
    loop_result
}

struct HandshakeLimiter {
    window: Duration,
    global_limit: usize,
    per_ip_limit: usize,
    global: VecDeque<Instant>,
    per_ip: HashMap<IpAddr, VecDeque<Instant>>,
}

impl HandshakeLimiter {
    fn new(global_limit: usize, per_ip_limit: usize) -> Self {
        Self {
            window: Duration::from_secs(60),
            global_limit,
            per_ip_limit,
            global: VecDeque::new(),
            per_ip: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        prune(&mut self.global, now, self.window);
        let bucket = self.per_ip.entry(ip).or_default();
        prune(bucket, now, self.window);
        if self.global.len() >= self.global_limit || bucket.len() >= self.per_ip_limit {
            return false;
        }
        self.global.push_back(now);
        bucket.push_back(now);

        // Keep the map bounded by opportunistically pruning empty stale buckets.
        if self.per_ip.len() > self.global_limit.saturating_mul(2).max(1024) {
            self.per_ip.retain(|_, entries| {
                prune(entries, now, self.window);
                !entries.is_empty()
            });
        }
        true
    }
}

fn prune(entries: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while entries
        .front()
        .is_some_and(|instant| now.duration_since(*instant) >= window)
    {
        entries.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::HandshakeLimiter;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    #[test]
    fn handshake_limiter_enforces_per_ip_and_global_limits() {
        let mut limiter = HandshakeLimiter::new(3, 2);
        let now = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        assert!(limiter.allow(a, now));
        assert!(limiter.allow(a, now));
        assert!(!limiter.allow(a, now));
        assert!(limiter.allow(b, now));
        assert!(!limiter.allow(b, now));
        assert!(limiter.allow(a, now + Duration::from_secs(61)));
    }
}
