use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex, RwLock};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::protocol::cipher::{read_encrypted, write_encrypted};
use crate::protocol::handshake::server_handshake;
use crate::protocol::message::{Message, OutputStream, PeerInfo};
use crate::protocol::MAX_EXEC_OUTPUT_BYTES;
use crate::{Error, Result};

const SESSION_QUEUE_CAPACITY: usize = 128;
const MAX_EXEC_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct PeerHandle {
    session_id: Uuid,
    pub name: String,
    pub remote_addr: SocketAddr,
    pub connected_at: Instant,
    pub tx: mpsc::Sender<Message>,
    cancel: watch::Sender<bool>,
}

struct PendingRequest {
    credential: String,
    session_id: Uuid,
    next_sequence: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    progress: watch::Sender<u64>,
    tx: oneshot::Sender<Result<Message>>,
}

impl PendingRequest {
    fn push_chunk(&mut self, sequence: u32, stream: OutputStream, bytes: &[u8]) -> Result<()> {
        if sequence != self.next_sequence {
            return Err(Error::Protocol(format!(
                "unexpected exec output sequence: got {sequence}, expected {}",
                self.next_sequence
            )));
        }
        let target = match stream {
            OutputStream::Stdout => &mut self.stdout,
            OutputStream::Stderr => &mut self.stderr,
        };
        if target.len().saturating_add(bytes.len()) > MAX_EXEC_OUTPUT_BYTES {
            return Err(Error::Protocol(
                "exec output exceeds aggregate limit".into(),
            ));
        }
        target.extend_from_slice(bytes);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("exec output sequence exhausted".into()))?;
        self.progress.send_replace(u64::from(self.next_sequence));
        Ok(())
    }
}

#[derive(Default)]
pub struct SharedState {
    pub peers: RwLock<HashMap<String, PeerHandle>>,
    pending: Mutex<HashMap<Uuid, PendingRequest>>,
}

impl SharedState {
    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let now = Instant::now();
        let peers = self.peers.read().await;
        let mut result: Vec<_> = peers
            .iter()
            .map(|(credential, peer)| PeerInfo {
                credential: credential.clone(),
                name: peer.name.clone(),
                remote_addr: peer.remote_addr.to_string(),
                connected_secs: now.duration_since(peer.connected_at).as_secs(),
            })
            .collect();
        result.sort_by(|a, b| a.credential.cmp(&b.credential));
        result
    }

    pub async fn exec(
        &self,
        credential: &str,
        command: String,
        args: Vec<String>,
        timeout_secs: u64,
        output_idle_timeout: Duration,
    ) -> Result<Message> {
        let peer = self
            .peers
            .read()
            .await
            .get(credential)
            .cloned()
            .ok_or_else(|| Error::PeerOffline(credential.to_owned()))?;

        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        let (progress_tx, progress_rx) = watch::channel(0u64);
        self.pending.lock().await.insert(
            id,
            PendingRequest {
                credential: credential.to_owned(),
                session_id: peer.session_id,
                next_sequence: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                progress: progress_tx,
                tx,
            },
        );

        match peer.tx.try_send(Message::ExecRequest {
            id,
            command,
            args,
            timeout_secs,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.pending.lock().await.remove(&id);
                return Err(Error::Busy("peer outbound queue is full".into()));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.pending.lock().await.remove(&id);
                return Err(Error::PeerOffline(credential.to_owned()));
            }
        }

        let result = await_exec_response(
            rx,
            progress_rx,
            Duration::from_secs(timeout_secs),
            output_idle_timeout,
        )
        .await;
        if result.is_err() {
            self.pending.lock().await.remove(&id);
        }
        result
    }
}

async fn await_exec_response(
    mut rx: oneshot::Receiver<Result<Message>>,
    mut progress: watch::Receiver<u64>,
    command_timeout: Duration,
    output_idle_timeout: Duration,
) -> Result<Message> {
    let command_deadline = tokio::time::Instant::now() + command_timeout;

    tokio::select! {
        result = &mut rx => {
            return result.map_err(|_| Error::Disconnected)?;
        }
        _ = tokio::time::sleep_until(command_deadline) => {}
    }

    // Once the remote command deadline has elapsed, switch to transport
    // progress semantics. Each output chunk refreshes the inactivity timer,
    // while the absolute transfer budget prevents an authenticated peer from
    // extending the request forever with tiny chunks.
    let transfer_budget = output_transfer_budget(output_idle_timeout);
    let hard_deadline = tokio::time::Instant::now() + transfer_budget;
    let mut idle_deadline = tokio::time::Instant::now() + output_idle_timeout;

    loop {
        tokio::select! {
            result = &mut rx => {
                return result.map_err(|_| Error::Disconnected)?;
            }
            changed = progress.changed() => {
                if changed.is_err() {
                    return Err(Error::Disconnected);
                }
                idle_deadline = tokio::time::Instant::now() + output_idle_timeout;
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                return Err(Error::Timeout);
            }
            _ = tokio::time::sleep_until(hard_deadline) => {
                return Err(Error::Timeout);
            }
        }
    }
}

fn output_transfer_budget(output_idle_timeout: Duration) -> Duration {
    output_idle_timeout
        .saturating_mul(4)
        .max(Duration::from_secs(30))
        .min(Duration::from_secs(300))
}

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    stream: TcpStream,
    remote_addr: SocketAddr,
    psk: Arc<Zeroizing<Vec<u8>>>,
    allowed_credential: String,
    heartbeat_timeout: Duration,
    handshake_timeout: Duration,
    write_timeout: Duration,
    state: Arc<SharedState>,
) -> Result<()> {
    let channel = tokio::time::timeout(handshake_timeout, server_handshake(stream, psk.as_slice()))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut reader = channel.reader;
    let mut writer = channel.writer;
    let mut recv_cipher = channel.recv_cipher;
    let mut send_cipher = channel.send_cipher;

    let (credential, name) = match tokio::time::timeout(
        handshake_timeout,
        read_encrypted::<_, Message>(&mut reader, &mut recv_cipher),
    )
    .await
    .map_err(|_| Error::Timeout)??
    {
        Message::Register { credential, name } => (credential, name),
        _ => return Err(Error::Protocol("expected register message".into())),
    };

    if credential != allowed_credential || !valid_peer_name(&name) {
        let _ = tokio::time::timeout(
            write_timeout,
            write_encrypted(
                &mut writer,
                &mut send_cipher,
                &Message::RegisterAck {
                    ok: false,
                    reason: Some("invalid credential or peer name".into()),
                },
            ),
        )
        .await;
        return Err(Error::Authentication);
    }

    tokio::time::timeout(
        write_timeout,
        write_encrypted(
            &mut writer,
            &mut send_cipher,
            &Message::RegisterAck {
                ok: true,
                reason: None,
            },
        ),
    )
    .await
    .map_err(|_| Error::Timeout)??;

    // From this point on, the read half is owned by exactly one task. It is
    // never recreated inside a select! loop, so a partial read_exact cannot
    // be cancelled and restarted at a different framing offset.
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Result<Message>>(SESSION_QUEUE_CAPACITY);
    let reader_task = tokio::spawn(async move {
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

    let session_id = Uuid::new_v4();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let handle = PeerHandle {
        session_id,
        name: name.clone(),
        remote_addr,
        connected_at: Instant::now(),
        tx: tx.clone(),
        cancel: cancel_tx,
    };
    let replaced = state.peers.write().await.insert(credential.clone(), handle);
    if let Some(old) = replaced {
        log::info!(
            "peer session superseded credential={} old_remote={} new_remote={}",
            credential,
            old.remote_addr,
            remote_addr
        );
        let _ = old.cancel.send(true);
    }
    log::info!(
        "handshake completed credential={} name={} remote={}",
        credential,
        name,
        remote_addr
    );

    let mut last_seen = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(1));
    watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            incoming = incoming_rx.recv() => {
                match incoming {
                    Some(Ok(Message::Ping { nonce })) => {
                        last_seen = Instant::now();
                        if tx.try_send(Message::Pong { nonce }).is_err() {
                            break Err(Error::Busy("peer outbound queue is full".into()));
                        }
                    }
                    Some(Ok(Message::Pong { .. })) => last_seen = Instant::now(),
                    Some(Ok(Message::ExecOutputChunk { id, sequence, stream, data_b64 })) => {
                        last_seen = Instant::now();
                        let bytes = STANDARD
                            .decode(data_b64)
                            .map_err(|_| Error::Protocol("invalid exec output base64".into()))?;
                        if bytes.len() > MAX_EXEC_OUTPUT_CHUNK_BYTES {
                            break Err(Error::Protocol("exec output chunk exceeds protocol limit".into()));
                        }
                        let mut pending = state.pending.lock().await;
                        if let Some(request) = pending.get_mut(&id) {
                            if request.session_id != session_id {
                                log::debug!("ignoring stale exec output chunk id={id}");
                            } else {
                                request.push_chunk(sequence, stream, &bytes)?;
                            }
                        } else {
                            log::debug!("ignoring unknown exec output chunk id={id}");
                        }
                    }
                    Some(Ok(Message::ExecFinished {
                        id,
                        exit_code,
                        truncated,
                        timed_out,
                        elapsed_ms,
                        error,
                    })) => {
                        last_seen = Instant::now();
                        let mut pending = state.pending.lock().await;
                        let matches_session = pending
                            .get(&id)
                            .is_some_and(|request| request.session_id == session_id);
                        if matches_session {
                            if let Some(waiter) = pending.remove(&id) {
                                let message = Message::ExecResponse {
                                    id,
                                    exit_code,
                                    stdout_b64: STANDARD.encode(waiter.stdout),
                                    stderr_b64: STANDARD.encode(waiter.stderr),
                                    truncated,
                                    timed_out,
                                    elapsed_ms,
                                    error,
                                };
                                let _ = waiter.tx.send(Ok(message));
                            }
                        } else {
                            log::debug!("ignoring stale or unknown exec finish id={id}");
                        }
                    }
                    Some(Ok(other)) => {
                        last_seen = Instant::now();
                        log::debug!("ignoring unexpected message kind={}", other.kind());
                    }
                    Some(Err(error)) => break Err(error),
                    None => break Err(Error::Disconnected),
                }
            }
            _ = watchdog.tick() => {
                if last_seen.elapsed() > heartbeat_timeout {
                    break Err(Error::Timeout);
                }
            }
            writer_result = &mut writer_task => {
                break match writer_result {
                    Ok(Ok(())) => Err(Error::Disconnected),
                    Ok(Err(error)) => Err(error),
                    Err(error) => Err(Error::Protocol(format!("writer task failed: {error}"))),
                };
            }
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break Err(Error::Protocol("session superseded by a newer connection".into()));
                }
            }
        }
    };

    cleanup_session(&state, &credential, session_id).await;
    drop(tx);
    if !reader_task.is_finished() {
        reader_task.abort();
    }
    if !writer_task.is_finished() {
        writer_task.abort();
    }
    let _ = reader_task.await;
    let _ = writer_task.await;
    log::info!(
        "peer disconnected credential={} remote={}",
        credential,
        remote_addr
    );
    result
}

async fn cleanup_session(state: &SharedState, credential: &str, session_id: Uuid) {
    let mut peers = state.peers.write().await;
    if peers
        .get(credential)
        .is_some_and(|current| current.session_id == session_id)
    {
        peers.remove(credential);
    }
    drop(peers);

    let mut pending = state.pending.lock().await;
    let affected: Vec<_> = pending
        .iter()
        .filter_map(|(id, request)| {
            (request.credential == credential && request.session_id == session_id).then_some(*id)
        })
        .collect();
    for id in affected {
        if let Some(request) = pending.remove(&id) {
            let _ = request.tx.send(Err(Error::Protocol(
                "result unknown: peer disconnected while command was in flight".into(),
            )));
        }
    }
}

fn valid_peer_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{
        await_exec_response, cleanup_session, output_transfer_budget, PeerHandle, PendingRequest,
        SharedState, SESSION_QUEUE_CAPACITY,
    };
    use crate::protocol::message::Message;
    use crate::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, oneshot, watch};
    use uuid::Uuid;

    #[tokio::test]
    async fn stale_session_cleanup_does_not_remove_replacement_or_its_pending_request() {
        let state = SharedState::default();
        let credential = "pair".to_string();
        let old_session = Uuid::new_v4();
        let new_session = Uuid::new_v4();
        let (peer_tx, _peer_rx) = mpsc::channel::<Message>(1);
        let (cancel_tx, _cancel_rx) = watch::channel(false);
        state.peers.write().await.insert(
            credential.clone(),
            PeerHandle {
                session_id: new_session,
                name: "new".into(),
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                connected_at: Instant::now(),
                tx: peer_tx,
                cancel: cancel_tx,
            },
        );

        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let (old_tx, old_rx) = oneshot::channel();
        let (new_tx, _new_rx) = oneshot::channel();
        let mut pending = state.pending.lock().await;
        pending.insert(
            old_id,
            PendingRequest {
                credential: credential.clone(),
                session_id: old_session,
                next_sequence: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                progress: watch::channel(0u64).0,
                tx: old_tx,
            },
        );
        pending.insert(
            new_id,
            PendingRequest {
                credential: credential.clone(),
                session_id: new_session,
                next_sequence: 0,
                stdout: Vec::new(),
                stderr: Vec::new(),
                progress: watch::channel(0u64).0,
                tx: new_tx,
            },
        );
        drop(pending);

        cleanup_session(&state, &credential, old_session).await;

        assert_eq!(
            state
                .peers
                .read()
                .await
                .get(&credential)
                .map(|peer| peer.session_id),
            Some(new_session)
        );
        let pending = state.pending.lock().await;
        assert!(!pending.contains_key(&old_id));
        assert!(pending.contains_key(&new_id));
        drop(pending);
        assert!(old_rx.await.unwrap().is_err());
    }

    #[test]
    fn pending_output_rejects_out_of_order_and_oversized_chunks() {
        let (tx, _rx) = oneshot::channel();
        let mut pending = PendingRequest {
            credential: "pair".into(),
            session_id: Uuid::new_v4(),
            next_sequence: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            progress: watch::channel(0u64).0,
            tx,
        };
        assert!(pending
            .push_chunk(1, crate::protocol::message::OutputStream::Stdout, b"x")
            .is_err());
        assert!(pending
            .push_chunk(0, crate::protocol::message::OutputStream::Stdout, b"ok")
            .is_ok());
        let oversized = vec![0u8; crate::protocol::MAX_EXEC_OUTPUT_BYTES];
        assert!(pending
            .push_chunk(
                1,
                crate::protocol::message::OutputStream::Stdout,
                &oversized
            )
            .is_err());
    }

    #[tokio::test]
    async fn output_progress_extends_only_the_transport_idle_deadline() {
        let (result_tx, result_rx) = oneshot::channel();
        let (progress_tx, progress_rx) = watch::channel(0u64);
        let waiter = tokio::spawn(await_exec_response(
            result_rx,
            progress_rx,
            Duration::from_millis(20),
            Duration::from_millis(60),
        ));

        tokio::time::sleep(Duration::from_millis(45)).await;
        progress_tx.send_replace(1);
        tokio::time::sleep(Duration::from_millis(45)).await;
        progress_tx.send_replace(2);
        result_tx
            .send(Ok(Message::Pong { nonce: 99 }))
            .expect("waiter must still be alive");

        let result = tokio::time::timeout(Duration::from_millis(200), waiter)
            .await
            .expect("progress should keep transport phase alive")
            .unwrap()
            .unwrap();
        assert!(matches!(result, Message::Pong { nonce: 99 }));
    }

    #[tokio::test]
    async fn output_inactivity_times_out_after_command_deadline() {
        let (_result_tx, result_rx) = oneshot::channel::<crate::Result<Message>>();
        let (_progress_tx, progress_rx) = watch::channel(0u64);
        let started = Instant::now();
        let result = await_exec_response(
            result_rx,
            progress_rx,
            Duration::from_millis(20),
            Duration::from_millis(40),
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[test]
    fn output_transfer_budget_is_absolute_and_bounded() {
        assert_eq!(
            output_transfer_budget(Duration::from_secs(1)),
            Duration::from_secs(30)
        );
        assert_eq!(
            output_transfer_budget(Duration::from_secs(15)),
            Duration::from_secs(60)
        );
        assert_eq!(
            output_transfer_budget(Duration::from_secs(100)),
            Duration::from_secs(300)
        );
    }

    #[tokio::test]
    async fn full_peer_queue_returns_busy_without_waiting() {
        let state = SharedState::default();
        let credential = "pair".to_string();
        let session_id = Uuid::new_v4();
        let (peer_tx, _peer_rx) = mpsc::channel::<Message>(SESSION_QUEUE_CAPACITY);
        for nonce in 0..SESSION_QUEUE_CAPACITY {
            peer_tx
                .try_send(Message::Ping {
                    nonce: nonce as u64,
                })
                .unwrap();
        }
        let (cancel_tx, _cancel_rx) = watch::channel(false);
        state.peers.write().await.insert(
            credential.clone(),
            PeerHandle {
                session_id,
                name: "peer".into(),
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                connected_at: Instant::now(),
                tx: peer_tx,
                cancel: cancel_tx,
            },
        );

        let result = tokio::time::timeout(
            Duration::from_millis(100),
            state.exec(
                &credential,
                "echo".into(),
                vec!["hello".into()],
                1,
                Duration::from_secs(1),
            ),
        )
        .await
        .expect("exec admission must not block");
        assert!(matches!(result, Err(Error::Busy(_))));
        assert!(state.pending.lock().await.is_empty());
    }
}
