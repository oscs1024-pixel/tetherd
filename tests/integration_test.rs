use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tetherd::config::Config;
use tetherd::protocol::message::{ControlRequest, ControlResponse, Message};
use tetherd::{ctl, daemon, join};
use tokio::sync::watch;

fn free_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn daemon_join_ctl_exec_end_to_end() {
    let dir = tempdir().unwrap();
    let port = free_port();
    let psk_path = dir.path().join("psk");
    fs::write(&psk_path, STANDARD.encode([0x55u8; 32])).unwrap();
    fs::set_permissions(&psk_path, fs::Permissions::from_mode(0o600)).unwrap();
    let socket_path = dir.path().join("tetherd.sock");
    let config_path = dir.path().join("tetherd.toml");
    fs::write(
        &config_path,
        format!(
            r#"
[auth]
credential = "pair"
psk_file = {:?}

[daemon]
listen = "127.0.0.1:{}"
control_socket = {:?}
heartbeat_timeout_secs = 5
handshake_timeout_secs = 2
max_connections = 16
control_timeout_secs = 5
control_request_timeout_secs = 2
max_control_connections = 8
write_timeout_secs = 2
max_handshakes_per_minute = 120
max_handshakes_per_minute_per_ip = 60

[join]
server = "127.0.0.1:{}"
name = "integration"
heartbeat_secs = 1
heartbeat_timeout_secs = 4
reconnect_secs = 1
connect_timeout_secs = 2
write_timeout_secs = 2
reconnect_max_secs = 4
auth_failure_backoff_secs = 3

[exec]
allow_exec = ["/bin/echo"]
max_timeout_secs = 3
max_output_bytes = 4096
max_concurrent = 2
output_drain_timeout_secs = 1
"#,
            psk_path, port, socket_path, port
        ),
    )
    .unwrap();

    let config = Arc::new(Config::load(&config_path).unwrap());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let daemon_task = tokio::spawn(daemon::run(config.clone(), shutdown_rx.clone()));

    for _ in 0..50 {
        if socket_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(socket_path.exists(), "control socket did not appear");

    let join_task = tokio::spawn(join::run(config.clone(), shutdown_rx));

    let mut connected = false;
    for _ in 0..100 {
        match ctl::request(&socket_path, ControlRequest::List, Duration::from_secs(2)).await {
            Ok(ControlResponse::Ok {
                peers: Some(peers), ..
            }) if !peers.is_empty() => {
                connected = true;
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    assert!(connected, "join peer did not register");

    let response = ctl::request(
        &socket_path,
        ControlRequest::Exec {
            credential: "pair".into(),
            argv: vec!["/bin/echo".into(), "e2e-ok".into()],
            timeout_secs: Some(2),
        },
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    match response {
        ControlResponse::Ok {
            result: Some(result),
            ..
        } => match *result {
            Message::ExecResponse {
                stdout,
                error: None,
                ..
            } => assert_eq!(stdout, "e2e-ok\n"),
            other => panic!("unexpected exec result: {other:?}"),
        },
        other => panic!("unexpected control response: {other:?}"),
    }

    shutdown_tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), daemon_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), join_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
