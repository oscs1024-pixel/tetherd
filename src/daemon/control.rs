use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use crate::daemon::connection::SharedState;
use crate::protocol::frame::{read_json_frame_limited, write_json_frame};
use crate::protocol::message::{ControlRequest, ControlResponse};
use crate::protocol::MAX_CONTROL_REQUEST_BYTES;
use crate::{Error, Result};

pub async fn serve(
    socket_path: PathBuf,
    state: Arc<SharedState>,
    exec_timeout: Duration,
    request_timeout: Duration,
    max_connections: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    prepare_socket_path(&socket_path)?;
    let listener = UnixListener::bind(&socket_path)?;
    let _cleanup = SocketCleanup(socket_path.clone());
    set_socket_permissions(&socket_path)?;
    log::info!("control socket listening path={}", socket_path.display());

    let connections = Arc::new(Semaphore::new(max_connections));
    let mut clients = JoinSet::new();
    let result = loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => break Err(error.into()),
                };
                let permit = match connections.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log::warn!("control connection limit reached");
                        drop(stream);
                        continue;
                    }
                };
                let state = state.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    handle_client(stream, state, exec_timeout, request_timeout).await
                });
            }
            joined = clients.join_next(), if !clients.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => log::warn!("control client failed error={error}"),
                    Some(Err(error)) if error.is_cancelled() => {}
                    Some(Err(error)) => log::warn!("control task join failure error={error}"),
                    None => {}
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
        }
    };

    clients.abort_all();
    while clients.join_next().await.is_some() {}
    result
}

async fn handle_client(
    mut stream: UnixStream,
    state: Arc<SharedState>,
    exec_timeout: Duration,
    request_timeout: Duration,
) -> Result<()> {
    verify_peer_uid(&stream)?;
    let request: ControlRequest = tokio::time::timeout(
        request_timeout,
        read_json_frame_limited(&mut stream, MAX_CONTROL_REQUEST_BYTES),
    )
    .await
    .map_err(|_| Error::Timeout)??;

    let response = match request {
        ControlRequest::List => ControlResponse::Ok {
            peers: Some(state.list_peers().await),
            result: None,
        },
        ControlRequest::Exec {
            credential,
            command,
            args,
            timeout_secs,
        } => {
            let remote_timeout = timeout_secs
                .unwrap_or(exec_timeout.as_secs())
                .clamp(1, exec_timeout.as_secs().max(1));
            let response_timeout = Duration::from_secs(remote_timeout.saturating_add(5));
            match state
                .exec(&credential, command, args, remote_timeout, response_timeout)
                .await
            {
                Ok(result) => ControlResponse::Ok {
                    peers: None,
                    result: Some(Box::new(result)),
                },
                Err(err) => ControlResponse::Error {
                    message: err.to_string(),
                },
            }
        }
    };

    tokio::time::timeout(request_timeout, write_json_frame(&mut stream, &response))
        .await
        .map_err(|_| Error::Timeout)??;
    Ok(())
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Control("control socket must have a parent directory".into()))?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    validate_socket_parent(parent)?;

    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if !metadata.file_type().is_socket() {
                return Err(Error::Control(format!(
                    "refusing to remove non-socket path {}",
                    path.display()
                )));
            }
        }
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn validate_socket_parent(parent: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() {
        return Err(Error::Control(format!(
            "control socket parent is not a directory: {}",
            parent.display()
        )));
    }
    let euid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(Error::Control(format!(
            "control socket parent must be owned by root or the daemon UID: {} owner={}",
            parent.display(),
            metadata.uid()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::Control(format!(
            "control socket parent must not be group/world writable: {} mode={mode:o}",
            parent.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_socket_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_socket_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_peer_uid(stream: &UnixStream) -> Result<()> {
    let peer = stream.peer_cred()?;
    let current_uid = nix::unistd::Uid::effective().as_raw();
    if peer.uid() != current_uid {
        return Err(Error::Control(format!(
            "control UID mismatch peer={} daemon={}",
            peer.uid(),
            current_uid
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_peer_uid(_stream: &UnixStream) -> Result<()> {
    Ok(())
}

struct SocketCleanup(PathBuf);

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_socket_path;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn control_socket_rejects_group_or_world_writable_parent() {
        let dir = tempdir().unwrap();
        let unsafe_parent = dir.path().join("unsafe");
        fs::create_dir(&unsafe_parent).unwrap();
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
        let socket = unsafe_parent.join("tetherd.sock");
        assert!(prepare_socket_path(&socket).is_err());
    }

    #[test]
    fn control_socket_refuses_to_replace_non_socket_file() {
        let dir = tempdir().unwrap();
        let socket = dir.path().join("tetherd.sock");
        fs::write(&socket, b"do-not-delete").unwrap();
        assert!(prepare_socket_path(&socket).is_err());
        assert_eq!(fs::read(&socket).unwrap(), b"do-not-delete");
    }
}
