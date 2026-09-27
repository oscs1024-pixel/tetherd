use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

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
    ExecOutputChunk {
        id: Uuid,
        sequence: u32,
        stream: OutputStream,
        data_b64: String,
    },
    ExecFinished {
        id: Uuid,
        exit_code: Option<i32>,
        truncated: bool,
        timed_out: bool,
        elapsed_ms: u64,
        error: Option<String>,
    },
    // Aggregated local control result. This is produced by the daemon after
    // receiving ExecOutputChunk/ExecFinished and is not sent over the peer link.
    ExecResponse {
        id: Uuid,
        exit_code: Option<i32>,
        stdout_b64: String,
        stderr_b64: String,
        truncated: bool,
        timed_out: bool,
        elapsed_ms: u64,
        error: Option<String>,
    },
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "register",
            Self::RegisterAck { .. } => "register_ack",
            Self::Ping { .. } => "ping",
            Self::Pong { .. } => "pong",
            Self::ExecRequest { .. } => "exec_request",
            Self::ExecOutputChunk { .. } => "exec_output_chunk",
            Self::ExecFinished { .. } => "exec_finished",
            Self::ExecResponse { .. } => "exec_response",
        }
    }
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
