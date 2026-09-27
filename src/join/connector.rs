use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::join::executor::{ExecutionResult, Executor};
use crate::protocol::cipher::{read_encrypted, write_encrypted};
use crate::protocol::handshake::client_handshake;
use crate::protocol::message::{Message, OutputStream};
use crate::{Error, Result};

const SESSION_QUEUE_CAPACITY: usize = 128;
const OUTPUT_CHUNK_BYTES: usize = 64 * 1024;
const MAX_RECONNECT_SECS: u64 = 300;
const PERMANENT_ERROR_FLOOR_SECS: u64 = 60;

pub async fn run(config: Arc<Config>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let psk = config.auth.load_psk()?;
    let executor = Executor::new(config.exec.clone())?;
    let mut failures = 0u32;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let started = Instant::now();
        let result = connect_once(config.clone(), &psk, executor.clone(), shutdown.clone()).await;
        if matches!(result, Ok(())) && *shutdown.borrow() {
            return Ok(());
        }

        let lived = started.elapsed();
        if lived >= Duration::from_secs(config.join.heartbeat_timeout_secs.max(60)) {
            failures = 0;
        } else {
            failures = failures.saturating_add(1);
        }

        let permanent = matches!(
            result,
            Err(Error::Authentication | Error::Protocol(_) | Error::Crypto)
        );
        match &result {
            Ok(()) => log::warn!("connection ended, scheduling reconnect"),
            Err(err) => log::warn!("connection failed error={err}"),
        }

        let delay = reconnect_delay(
            config.join.reconnect_secs,
            failures,
            permanent,
            &mut rand::thread_rng(),
        );
        log::info!(
            "reconnect scheduled delay_ms={} permanent_error={permanent}",
            delay.as_millis()
        );
        tokio::select! {
            _ = tokio::time::sleep(delay) => {},
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
        }
    }
}

fn reconnect_delay<R: Rng + ?Sized>(
    base_secs: u64,
    failures: u32,
    permanent: bool,
    rng: &mut R,
) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    let factor = 1u64 << exponent;
    let cap_secs = base_secs
        .saturating_mul(factor)
        .min(MAX_RECONNECT_SECS)
        .max(if permanent {
            PERMANENT_ERROR_FLOOR_SECS
        } else {
            base_secs
        });
    let cap_ms = cap_secs.saturating_mul(1000);
    let floor_ms = if permanent {
        PERMANENT_ERROR_FLOOR_SECS.saturating_mul(1000) / 2
    } else {
        250.min(cap_ms)
    };
    Duration::from_millis(rng.gen_range(floor_ms..=cap_ms.max(floor_ms)))
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

    let channel = tokio::time::timeout(
        Duration::from_secs(config.join.connect_timeout_secs),
        client_handshake(stream, psk),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    let mut reader = channel.reader;
    let mut writer = channel.writer;
    let mut recv_cipher = channel.recv_cipher;
    let mut send_cipher = channel.send_cipher;
    let write_timeout = Duration::from_secs(config.join.write_timeout_secs);

    tokio::time::timeout(
        write_timeout,
        write_encrypted(
            &mut writer,
            &mut send_cipher,
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
        read_encrypted::<_, Message>(&mut reader, &mut recv_cipher),
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

    // The read half is exclusively owned by this task after registration.
    // This avoids cancelling read_exact in the middle of a frame.
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Result<Message>>(SESSION_QUEUE_CAPACITY);
    let mut reader_task = tokio::spawn(async move {
        loop {
            match read_encrypted::<_, Message>(&mut reader, &mut recv_cipher).await {
                Ok(message) => {
                    if incoming_tx.send(Ok(message)).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = incoming_tx.send(Err(error)).await;
                    return;
                }
            }
        }
    });

    let (tx, mut rx) = mpsc::channel::<Message>(SESSION_QUEUE_CAPACITY);
    let mut writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            tokio::time::timeout(
                write_timeout,
                write_encrypted(&mut writer, &mut send_cipher, &message),
            )
            .await
            .map_err(|_| Error::Timeout)??;
        }
        Ok::<(), Error>(())
    });

    let mut last_pong = Instant::now();
    let heartbeat_timeout = Duration::from_secs(config.join.heartbeat_timeout_secs);
    let mut watchdog = tokio::time::interval(Duration::from_secs(1));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(config.join.heartbeat_secs));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut nonce = 0u64;

    let result = loop {
        tokio::select! {
            incoming = incoming_rx.recv() => {
                match incoming {
                    Some(Ok(Message::Pong { .. })) => last_pong = Instant::now(),
                    Some(Ok(Message::Ping { nonce })) => {
                        if tx.try_send(Message::Pong { nonce }).is_err() {
                            break Err(Error::Busy("join outbound queue is full".into()));
                        }
                    }
                    Some(Ok(Message::ExecRequest {
                        id,
                        command,
                        args,
                        timeout_secs,
                    })) => {
                        match executor.try_reserve() {
                            Ok(permit) => {
                                let executor = executor.clone();
                                let tx = tx.clone();
                                tokio::spawn(async move {
                                    let result = executor
                                        .execute_reserved(permit, id, command, args, timeout_secs)
                                        .await;
                                    let _ = send_execution_result(&tx, result).await;
                                });
                            }
                            Err(error) => {
                                let response = Message::ExecFinished {
                                    id,
                                    exit_code: None,
                                    truncated: false,
                                    timed_out: false,
                                    elapsed_ms: 0,
                                    error: Some(error.to_string()),
                                };
                                if tx.try_send(response).is_err() {
                                    break Err(Error::Busy("join outbound queue is full".into()));
                                }
                            }
                        }
                    }
                    Some(Ok(other)) => log::debug!("ignoring unexpected message kind={}", other.kind()),
                    Some(Err(error)) => break Err(error),
                    None => break Err(Error::Disconnected),
                }
            }
            _ = heartbeat.tick() => {
                nonce = nonce.wrapping_add(1);
                if tx.try_send(Message::Ping { nonce }).is_err() {
                    break Err(Error::Busy("join outbound queue is full".into()));
                }
            }
            _ = watchdog.tick() => {
                if last_pong.elapsed() > heartbeat_timeout {
                    break Err(Error::Timeout);
                }
            }
            writer_result = &mut writer_task => {
                break match writer_result {
                    Ok(Ok(())) => Err(Error::Disconnected),
                    Ok(Err(err)) => Err(err),
                    Err(err) => Err(Error::Protocol(format!("writer task failed: {err}"))),
                };
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break Ok(()); }
            }
        }
    };

    drop(tx);
    if !reader_task.is_finished() {
        reader_task.abort();
    }
    if !writer_task.is_finished() {
        writer_task.abort();
    }
    let _ = reader_task.await;
    let _ = writer_task.await;
    result
}

async fn send_execution_result(tx: &mpsc::Sender<Message>, result: ExecutionResult) -> Result<()> {
    let mut sequence = 0u32;
    for (stream, bytes) in [
        (OutputStream::Stdout, result.stdout.as_slice()),
        (OutputStream::Stderr, result.stderr.as_slice()),
    ] {
        for chunk in bytes.chunks(OUTPUT_CHUNK_BYTES) {
            tx.send(Message::ExecOutputChunk {
                id: result.id,
                sequence,
                stream,
                data_b64: STANDARD.encode(chunk),
            })
            .await
            .map_err(|_| Error::Disconnected)?;
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("exec output sequence exhausted".into()))?;
        }
    }
    tx.send(Message::ExecFinished {
        id: result.id,
        exit_code: result.exit_code,
        truncated: result.truncated,
        timed_out: result.timed_out,
        elapsed_ms: result.elapsed_ms,
        error: result.error,
    })
    .await
    .map_err(|_| Error::Disconnected)
}

#[cfg(test)]
mod tests {
    use super::reconnect_delay;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn reconnect_backoff_is_capped_and_permanent_errors_slow_down() {
        let mut rng = StdRng::seed_from_u64(7);
        let transient = reconnect_delay(5, 1, false, &mut rng);
        assert!(transient.as_millis() >= 250);
        assert!(transient.as_secs() <= 5);

        let permanent = reconnect_delay(5, 1, true, &mut rng);
        assert!(permanent.as_secs() >= 30);
        assert!(permanent.as_secs() <= 60);

        let capped = reconnect_delay(60, 20, false, &mut rng);
        assert!(capped.as_secs() <= 300);
    }
}
