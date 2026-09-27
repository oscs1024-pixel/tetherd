use rand::Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::join::executor::Executor;
use crate::protocol::cipher::{read_encrypted, write_encrypted};
use crate::protocol::handshake::client_handshake;
use crate::protocol::message::Message;
use crate::{Error, Result};

pub async fn run(config: Arc<Config>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let psk = config.auth.load_psk()?;
    let executor = Executor::new(config.exec.clone())?;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        match connect_once(config.clone(), &psk, executor.clone(), shutdown.clone()).await {
            Ok(()) if *shutdown.borrow() => return Ok(()),
            Ok(()) => log::warn!("connection ended, scheduling reconnect"),
            Err(err) => log::warn!("connection failed error={err}"),
        }

        let base_ms = config.join.reconnect_secs.saturating_mul(1000);
        let jitter_pct = rand::thread_rng().gen_range(80u64..=120u64);
        let delay_ms = base_ms.saturating_mul(jitter_pct) / 100;
        log::info!("reconnect scheduled delay_ms={delay_ms}");
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {},
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
        }
    }
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

    write_encrypted(
        &mut writer,
        &mut send_cipher,
        &Message::Register {
            credential: config.auth.credential.clone(),
            name: config.join.name.clone(),
        },
    )
    .await?;

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

    let (tx, mut rx) = mpsc::channel::<Message>(128);
    let mut writer_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            write_encrypted(&mut writer, &mut send_cipher, &message).await?;
        }
        Ok::<(), Error>(())
    });

    let heartbeat_tx = tx.clone();
    let heartbeat_secs = config.join.heartbeat_secs;
    let heartbeat_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(heartbeat_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut nonce = 0u64;
        loop {
            ticker.tick().await;
            nonce = nonce.wrapping_add(1);
            if heartbeat_tx.send(Message::Ping { nonce }).await.is_err() {
                return;
            }
        }
    });

    let mut last_pong = Instant::now();
    let heartbeat_timeout = Duration::from_secs(config.join.heartbeat_timeout_secs);
    let mut watchdog = tokio::time::interval(Duration::from_secs(1));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            message = read_encrypted::<_, Message>(&mut reader, &mut recv_cipher) => {
                match message {
                    Ok(Message::Pong { .. }) => last_pong = Instant::now(),
                    Ok(Message::Ping { nonce }) => {
                        if tx.send(Message::Pong { nonce }).await.is_err() { break Err(Error::Disconnected); }
                    }
                    Ok(Message::ExecRequest { id, argv, timeout_secs }) => {
                        let executor = executor.clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let response = executor.execute(id, argv, timeout_secs).await;
                            let _ = tx.send(response).await;
                        });
                    }
                    Ok(other) => log::debug!("ignoring unexpected message kind={}", other.kind()),
                    Err(err) => break Err(err),
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
    heartbeat_task.abort();
    if !writer_task.is_finished() {
        writer_task.abort();
    }
    result
}
