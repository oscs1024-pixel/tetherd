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
use crate::protocol::message::{Message, PeerInfo};
use crate::protocol::transport::{spawn_message_transport, stop_transport};
use crate::{Error, Result};

const SESSION_QUEUE_CAPACITY: usize = 128;

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
    tx: oneshot::Sender<Result<Message>>,
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
        response_timeout: Duration,
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
        self.pending.lock().await.insert(
            id,
            PendingRequest {
                credential: credential.to_owned(),
                session_id: peer.session_id,
                tx,
            },
        );

        let request = Message::ExecRequest {
            id,
            command,
            args,
            timeout_secs,
        };
        match peer.tx.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.pending.lock().await.remove(&id);
                return Err(Error::Busy(format!(
                    "peer outbound queue is full: {credential}"
                )));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.pending.lock().await.remove(&id);
                return Err(Error::PeerOffline(credential.to_owned()));
            }
        }

        match tokio::time::timeout(response_timeout, rx).await {
            Ok(Ok(Ok(message))) => Ok(message),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err(Error::Disconnected),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(Error::Timeout)
            }
        }
    }
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
    let mut channel =
        tokio::time::timeout(handshake_timeout, server_handshake(stream, psk.as_slice()))
            .await
            .map_err(|_| Error::Timeout)??;

    let (credential, name) = match tokio::time::timeout(
        handshake_timeout,
        read_encrypted::<_, Message>(&mut channel.reader, &mut channel.recv_cipher),
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
                &mut channel.writer,
                &mut channel.send_cipher,
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
            &mut channel.writer,
            &mut channel.send_cipher,
            &Message::RegisterAck {
                ok: true,
                reason: None,
            },
        ),
    )
    .await
    .map_err(|_| Error::Timeout)??;

    let mut transport = spawn_message_transport(channel, write_timeout, SESSION_QUEUE_CAPACITY);

    let session_id = Uuid::new_v4();
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let handle = PeerHandle {
        session_id,
        name: name.clone(),
        remote_addr,
        connected_at: Instant::now(),
        tx: transport.outgoing.clone(),
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
            incoming = transport.incoming.recv() => {
                let Some(message) = incoming else {
                    break Err(Error::Disconnected);
                };
                last_seen = Instant::now();
                match message {
                    Message::Ping { nonce } => {
                        match transport.outgoing.try_send(Message::Pong { nonce }) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                break Err(Error::Busy("peer outbound queue saturated".into()));
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                break Err(Error::Disconnected);
                            }
                        }
                    }
                    Message::Pong { .. } => {}
                    message @ Message::ExecResponse { id, .. } => {
                        let mut pending = state.pending.lock().await;
                        let matches_session = pending
                            .get(&id)
                            .is_some_and(|request| request.session_id == session_id);
                        if matches_session {
                            if let Some(waiter) = pending.remove(&id) {
                                let _ = waiter.tx.send(Ok(message));
                            }
                        } else {
                            log::debug!("ignoring stale or unknown exec response id={id}");
                        }
                    }
                    other => {
                        log::debug!("ignoring unexpected message kind={}", other.kind());
                    }
                }
            }

            failure = transport.failures.recv() => {
                let Some(failure) = failure else {
                    break Err(Error::Disconnected);
                };
                log::debug!("transport failure side={:?}", failure.side);
                break Err(failure.error);
            }
            _ = watchdog.tick() => {
                if last_seen.elapsed() > heartbeat_timeout {
                    break Err(Error::Timeout);
                }
            }
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow() {
                    break Err(Error::Protocol("session superseded by a newer connection".into()));
                }
            }
        }
    };

    stop_transport(&mut transport).await;
    cleanup_session(&state, &credential, session_id).await;
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
    use super::{cleanup_session, PeerHandle, PendingRequest, SharedState};
    use crate::protocol::message::Message;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, oneshot, watch};
    use uuid::Uuid;

    #[tokio::test]
    async fn saturated_peer_queue_returns_busy_without_leaking_pending_request() {
        let state = Arc::new(SharedState::default());
        let credential = "pair".to_string();
        let session_id = Uuid::new_v4();
        let (peer_tx, _peer_rx) = mpsc::channel::<Message>(1);
        peer_tx.try_send(Message::Ping { nonce: 1 }).unwrap();
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

        let started = Instant::now();
        let error = state
            .exec(
                &credential,
                "echo".into(),
                vec!["hello".into()],
                1,
                Duration::from_secs(30),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, crate::Error::Busy(_)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(state.pending.lock().await.is_empty());
    }

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
                tx: old_tx,
            },
        );
        pending.insert(
            new_id,
            PendingRequest {
                credential: credential.clone(),
                session_id: new_session,
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
}
