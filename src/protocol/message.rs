use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Register {
        credential: String,
        name: String,
    },
    RegisterAck {
        ok: bool,
        reason: Option<String>,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
    ExecRequest {
        id: Uuid,
        argv: Vec<String>,
        timeout_secs: u64,
    },
    ExecResponse {
        id: Uuid,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        truncated: bool,
        timed_out: bool,
        elapsed_ms: u64,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ControlRequest {
    List,
    Exec {
        credential: String,
        argv: Vec<String>,
        timeout_secs: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub credential: String,
    pub name: String,
    pub remote_addr: String,
    pub connected_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Ok {
        peers: Option<Vec<PeerInfo>>,
        result: Option<Box<Message>>,
    },
    Error {
        message: String,
    },
}
