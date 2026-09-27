use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("authentication failed")]
    Authentication,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("frame too large: {actual} bytes (limit {limit})")]
    FrameTooLarge { actual: usize, limit: usize },
    #[error("peer disconnected")]
    Disconnected,
    #[error("peer is not connected: {0}")]
    PeerOffline(String),
    #[error("request timed out")]
    Timeout,
    #[error("execution denied: {0}")]
    ExecutionDenied(String),
    #[error("resource busy: {0}")]
    Busy(String),
    #[error("invalid control request: {0}")]
    Control(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error("cryptographic operation failed")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, Error>;
