use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
        command: String,
        args: Vec<String>,
        timeout_secs: u64,
    },
    ExecOutput {
        id: Uuid,
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
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Register { .. } => "register",
            Self::RegisterAck { .. } => "register_ack",
            Self::Ping { .. } => "ping",
            Self::Pong { .. } => "pong",
            Self::ExecRequest { .. } => "exec_request",
            Self::ExecOutput { .. } => "exec_output",
            Self::ExecFinished { .. } => "exec_finished",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ControlRequest {
    List,
    Exec {
        credential: String,
        command: String,
        args: Vec<String>,
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
pub struct ExecResult {
    pub exit_code: Option<i32>,
    pub stdout_b64: String,
    pub stderr_b64: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlResponse {
    Ok {
        peers: Option<Vec<PeerInfo>>,
        result: Option<ExecResult>,
    },
    Error {
        message: String,
    },
}
