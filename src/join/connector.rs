use rand::Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::config::Config;
use crate::join::executor::Executor;
use crate::protocol::cipher::{read_encrypted, write_encrypted};
use crate::protocol::handshake::client_handshake;
use crate::protocol::message::Message;
use crate::protocol::transport::{spawn_message_transport, stop_transport};
use crate::{Error, Result};

const SESSION_QUEUE_CAPACITY: usize = 128;
const STABLE_SESSION_SECS: u64 = 30;

pub async fn run(config: Arc<Config>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let psk = config.auth.load_psk()?;
    let executor = Executor::new(config.exec.clone())?;
    let mut failures = 0u32;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let attempt_started = Instant::now();
        let result = connect_once(config.clone(), &psk, executor.clone(), shutdown.clone()).await;
        if *shutdown.borrow() {
            return Ok(());
        }

        let stable = attempt_started.elapsed() >= Duration::from_secs(STABLE_SESSION_SECS);
        if stable {
            failures = 0;
        } else {
            failures = failures.saturating_add(1);
        }

        let delay = reconnect_delay(&config, failures, result.as_ref().err());
        match &result {
            Ok(()) => log::warn!(
                "connection ended, scheduling reconnect delay_ms={}",
                delay.as_millis()
            ),
            Err(err) => log::warn!(
                "connection failed error={} reconnect_delay_ms={}",
                err,
                delay.as_millis()
            ),
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

fn reconnect_delay(config: &Config, failures: u32, error: Option<&Error>) -> Duration {
    let base_secs = if matches!(error, Some(Error::Authentication | Error::Protocol(_))) {
        config.join.auth_failure_backoff_secs
    } else {
        let exponent = failures.saturating_sub(1).min(16);
        config
            .join
            .reconnect_secs
            .saturating_mul(1u64 << exponent)
            .min(config.join.reconnect_max_secs)
    };

    let capped_secs = base_secs.min(config.join.reconnect_max_secs).max(1);
    let cap_ms = capped_secs.saturating_mul(1000);
    let jitter_ms = rand::thread_rng().gen_range(0..=cap_ms);
    Duration::from_millis(jitter_ms.max(250))
}

async fn connect_once(
    config: Arc<Config>,
    psk: &[u8],
    executor: Executor,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let stream = tokio::time::timeout(
        Duration::from_secs(config.join.connect_timeout_secs),
        TcpStream::connect(config.join.server),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    stream.set_nodelay(true)?;
    log::info!("connected server={}", config.join.server);

    let mut channel = tokio::time::timeout(
        Duration::from_secs(config.join.connect_timeout_secs),
        client_handshake(stream, psk),
    )
    .await
    .map_err(|_| Error::Timeout)??;

    let write_timeout = Duration::from_secs(config.join.write_timeout_secs);
    tokio::time::timeout(
        write_timeout,
        write_encrypted(
            &mut channel.writer,
            &mut channel.send_cipher,
            &Message::Register {
                credential: config.auth.credential.clone(),
                name: config.join.name.clone(),
            },
        ),
    )
    .await
    .map_err(|_| Error::Timeout)??;

    let registration = tokio::time::timeout(
        Duration::from_secs(config.join.connect_timeout_secs),
        read_encrypted::<_, Message>(&mut channel.reader, &mut channel.recv_cipher),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    match registration {
        Message::RegisterAck { ok: true, .. } => {}
        Message::RegisterAck { ok: false, .. } => {
            log::warn!("registration rejected by server");
            return Err(Error::Authentication);
        }
        _ => return Err(Error::Protocol("expected register_ack".into())),
    }

    log::info!(
        "handshake completed credential={} name={}",
        config.auth.credential,
        config.join.name
    );

    let mut transport = spawn_message_transport(channel, write_timeout, SESSION_QUEUE_CAPACITY);
    let mut exec_tasks = JoinSet::<Message>::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(config.join.heartbeat_secs));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut watchdog = tokio::time::interval(Duration::from_secs(1));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let heartbeat_timeout = Duration::from_secs(config.join.heartbeat_timeout_secs);
    let mut last_pong = Instant::now();
    let mut nonce = 0u64;

    let result = loop {
        tokio::select! {
            incoming = transport.incoming.recv() => {
                let Some(message) = incoming else {
                    break Err(Error::Disconnected);
                };
                match message {
                    Message::Pong { .. } => last_pong = Instant::now(),
                    Message::Ping { nonce } => {
                        if let Err(err) = try_send_message(
                            &transport.outgoing,
                            Message::Pong { nonce },
                        ) {
                            break Err(err);
                        }
                    }
                    Message::ExecRequest { id, argv, timeout_secs } => {
                        match executor.try_reserve() {
                            Ok(permit) => {
                                let executor = executor.clone();
                                exec_tasks.spawn(async move {
                                    executor.execute_reserved(id, argv, timeout_secs, permit).await
                                });
                            }
                            Err(error) => {
                                let response = Message::ExecResponse {
                                    id,
                                    exit_code: None,
                                    stdout: String::new(),
                                    stderr: String::new(),
                                    truncated: false,
                                    timed_out: false,
                                    elapsed_ms: 0,
                                    error: Some(error.to_string()),
                                };
                                if let Err(err) = try_send_message(&transport.outgoing, response) {
                                    break Err(err);
                                }
                            }
                        }
                    }
                    other => log::debug!("ignoring unexpected message kind={}", other.kind()),
                }
            }
            completed = exec_tasks.join_next(), if !exec_tasks.is_empty() => {
                match completed {
                    Some(Ok(response)) => {
                        if let Err(err) = try_send_message(&transport.outgoing, response) {
                            break Err(err);
                        }
                    }
                    Some(Err(err)) if err.is_cancelled() => {}
                    Some(Err(err)) => {
                        break Err(Error::Protocol(format!("executor task failed: {err}")));
                    }
                    None => {}
                }
            }
            _ = heartbeat.tick() => {
                nonce = nonce.wrapping_add(1);
                if let Err(err) = try_send_message(
                    &transport.outgoing,
                    Message::Ping { nonce },
                ) {
                    break Err(err);
                }
            }
            _ = watchdog.tick() => {
                if last_pong.elapsed() > heartbeat_timeout {
                    break Err(Error::Timeout);
                }
            }

            failure = transport.failures.recv() => {
                let Some(failure) = failure else {
                    break Err(Error::Disconnected);
                };
                log::debug!("transport failure side={:?}", failure.side);
                break Err(failure.error);
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
        }
    };

    exec_tasks.abort_all();
    while exec_tasks.join_next().await.is_some() {}
    stop_transport(&mut transport).await;
    result
}

fn try_send_message(sender: &mpsc::Sender<Message>, message: Message) -> Result<()> {
    match sender.try_send(message) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            Err(Error::Busy("session outbound queue is saturated".into()))
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(Error::Disconnected),
    }
}

#[cfg(test)]
mod tests {
    use super::reconnect_delay;
    use crate::config::Config;
    use crate::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn config() -> Config {
        let dir = tempdir().unwrap();
        let psk = dir.path().join("psk");
        fs::write(&psk, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        fs::set_permissions(&psk, fs::Permissions::from_mode(0o600)).unwrap();
        let config = dir.path().join("tetherd.toml");
        fs::write(
            &config,
            format!(
                r#"
[auth]
credential = "pair"
psk_file = {:?}

[join]
reconnect_secs = 2
reconnect_max_secs = 32
auth_failure_backoff_secs = 20
"#,
                psk
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        Config::load(config).unwrap()
    }

    #[test]
    fn reconnect_delay_is_capped_and_auth_errors_use_long_backoff() {
        let config = config();
        let normal = reconnect_delay(&config, 20, None);
        assert!(normal <= std::time::Duration::from_secs(32));

        let auth = reconnect_delay(&config, 1, Some(&Error::Authentication));
        assert!(auth <= std::time::Duration::from_secs(20));
        assert!(auth >= std::time::Duration::from_millis(250));
    }
}
