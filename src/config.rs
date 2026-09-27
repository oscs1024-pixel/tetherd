use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::LevelFilter;
use serde::Deserialize;
use std::collections::BTreeMap;
#[cfg(not(unix))]
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::logging::{parse_level, ColorMode};
use crate::{Error, Result};

const MAX_DAEMON_CONNECTIONS: usize = 4096;
const MAX_CONTROL_CONNECTIONS: usize = 256;
const MAX_EXEC_CONCURRENT: usize = 64;
const MAX_TIMEOUT_SECS: u64 = 3600;
const MAX_WRITE_TIMEOUT_SECS: u64 = 300;
const MAX_RECONNECT_SECS: u64 = 3600;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_HANDSHAKES_PER_MINUTE: u32 = 120_000;
const MAX_HANDSHAKES_PER_MINUTE_PER_IP: u32 = 6_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub join: JoinConfig,
    #[serde(default)]
    pub exec: ExecConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub color: ColorMode,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            color: ColorMode::Auto,
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub credential: String,
    pub psk_file: Option<PathBuf>,
    pub psk_env: Option<String>,
}

impl AuthConfig {
    pub fn load_psk(&self) -> Result<Zeroizing<Vec<u8>>> {
        match (&self.psk_file, &self.psk_env) {
            (Some(_), Some(_)) => {
                return Err(Error::Config(
                    "configure exactly one of auth.psk_file or auth.psk_env".into(),
                ))
            }
            (None, None) => {
                return Err(Error::Config(
                    "configure one of auth.psk_file or auth.psk_env".into(),
                ))
            }
            _ => {}
        }

        let encoded = Zeroizing::new(if let Some(path) = &self.psk_file {
            read_protected_file(path, FilePolicy::Secret)?
                .trim()
                .to_owned()
        } else {
            let name = self.psk_env.as_ref().expect("validated PSK source");
            std::env::var(name)
                .map_err(|_| Error::Config(format!("environment variable {name} is not set")))?
        });

        let decoded = STANDARD
            .decode(encoded.trim())
            .map_err(|_| Error::Config("PSK is not valid base64".into()))?;
        if decoded.len() != 32 {
            return Err(Error::Config(format!(
                "PSK must decode to exactly 32 bytes, got {}",
                decoded.len()
            )));
        }
        Ok(Zeroizing::new(decoded))
    }
}

#[derive(Clone, Copy)]
enum FilePolicy {
    Config,
    Secret,
}

#[cfg(unix)]
fn read_protected_file(path: &Path, policy: FilePolicy) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "protected path is not a regular file: {}",
            path.display()
        )));
    }

    let euid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != 0 && metadata.uid() != euid {
        return Err(Error::Config(format!(
            "protected file must be owned by root or the service user: {} owner_uid={}",
            path.display(),
            metadata.uid()
        )));
    }

    let mode = metadata.permissions().mode() & 0o777;
    let forbidden = match policy {
        FilePolicy::Config => 0o022,
        FilePolicy::Secret => 0o077,
    };
    if mode & forbidden != 0 {
        return Err(Error::Config(format!(
            "protected file permissions are too broad: {} mode={mode:o}",
            path.display()
        )));
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

#[cfg(not(unix))]
fn read_protected_file(path: &Path, _policy: FilePolicy) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "protected path is not a regular file: {}",
            path.display()
        )));
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_socket_path")]
    pub control_socket: PathBuf,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    #[serde(default = "default_write_timeout_secs")]
    pub write_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_control_timeout_secs")]
    pub control_timeout_secs: u64,
    #[serde(default = "default_control_request_timeout_secs")]
    pub control_request_timeout_secs: u64,
    #[serde(default = "default_max_control_connections")]
    pub max_control_connections: usize,
    #[serde(default = "default_max_handshakes_per_minute")]
    pub max_handshakes_per_minute: u32,
    #[serde(default = "default_max_handshakes_per_minute_per_ip")]
    pub max_handshakes_per_minute_per_ip: u32,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            control_socket: default_socket_path(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            write_timeout_secs: default_write_timeout_secs(),
            max_connections: default_max_connections(),
            control_timeout_secs: default_control_timeout_secs(),
            control_request_timeout_secs: default_control_request_timeout_secs(),
            max_control_connections: default_max_control_connections(),
            max_handshakes_per_minute: default_max_handshakes_per_minute(),
            max_handshakes_per_minute_per_ip: default_max_handshakes_per_minute_per_ip(),
        }
    }
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:1234".parse().expect("static socket address")
}
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/tetherd/tetherd.sock")
}
fn default_heartbeat_timeout_secs() -> u64 {
    180
}
fn default_handshake_timeout_secs() -> u64 {
    10
}
fn default_write_timeout_secs() -> u64 {
    10
}
fn default_max_connections() -> usize {
    128
}
fn default_control_timeout_secs() -> u64 {
    30
}
fn default_control_request_timeout_secs() -> u64 {
    5
}
fn default_max_control_connections() -> usize {
    64
}
fn default_max_handshakes_per_minute() -> u32 {
    1200
}
fn default_max_handshakes_per_minute_per_ip() -> u32 {
    120
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinConfig {
    #[serde(default = "default_server")]
    pub server: SocketAddr,
    #[serde(default = "default_name")]
    pub name: String,
    #[serde(default = "default_heartbeat_secs")]
    pub heartbeat_secs: u64,
    #[serde(default = "default_heartbeat_timeout_secs")]
    pub heartbeat_timeout_secs: u64,
    #[serde(default = "default_reconnect_secs")]
    pub reconnect_secs: u64,
    #[serde(default = "default_reconnect_max_secs")]
    pub reconnect_max_secs: u64,
    #[serde(default = "default_auth_failure_backoff_secs")]
    pub auth_failure_backoff_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_write_timeout_secs")]
    pub write_timeout_secs: u64,
}

impl Default for JoinConfig {
    fn default() -> Self {
        Self {
            server: default_server(),
            name: default_name(),
            heartbeat_secs: default_heartbeat_secs(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            reconnect_secs: default_reconnect_secs(),
            reconnect_max_secs: default_reconnect_max_secs(),
            auth_failure_backoff_secs: default_auth_failure_backoff_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            write_timeout_secs: default_write_timeout_secs(),
        }
    }
}

fn default_server() -> SocketAddr {
    "127.0.0.1:1234".parse().expect("static socket address")
}
fn default_name() -> String {
    "alice".into()
}
fn default_heartbeat_secs() -> u64 {
    60
}
fn default_reconnect_secs() -> u64 {
    5
}
fn default_reconnect_max_secs() -> u64 {
    300
}
fn default_auth_failure_backoff_secs() -> u64 {
    60
}
fn default_connect_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    #[serde(default)]
    pub allow_exec: Vec<PathBuf>,
    #[serde(default = "default_exec_timeout_secs")]
    pub max_timeout_secs: u64,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: usize,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default = "default_output_drain_timeout_secs")]
    pub output_drain_timeout_secs: u64,
    #[serde(default)]
    pub work_dir: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            allow_exec: Vec::new(),
            max_timeout_secs: default_exec_timeout_secs(),
            max_output_bytes: default_output_limit(),
            max_concurrent: default_max_concurrent(),
            output_drain_timeout_secs: default_output_drain_timeout_secs(),
            work_dir: None,
            env: BTreeMap::new(),
        }
    }
}

fn default_exec_timeout_secs() -> u64 {
    30
}
fn default_output_limit() -> usize {
    MAX_OUTPUT_BYTES
}
fn default_max_concurrent() -> usize {
    4
}
fn default_output_drain_timeout_secs() -> u64 {
    2
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = read_protected_file(path.as_ref(), FilePolicy::Config)?;
        let config: Self = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        validate_identifier("auth.credential", &self.auth.credential)?;
        validate_identifier("join.name", &self.join.name)?;

        match (&self.auth.psk_file, &self.auth.psk_env) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(Error::Config(
                    "configure exactly one of auth.psk_file or auth.psk_env".into(),
                ))
            }
            _ => {}
        }

        if let Some(name) = &self.auth.psk_env {
            validate_env_name("auth.psk_env", name)?;
            if self.exec.env.contains_key(name) {
                return Err(Error::Config(
                    "exec.env must never contain the PSK environment variable".into(),
                ));
            }
        }

        if !self.daemon.control_socket.is_absolute() {
            return Err(Error::Config(
                "daemon.control_socket must be an absolute path".into(),
            ));
        }

        validate_u64_range(
            "daemon.heartbeat_timeout_secs",
            self.daemon.heartbeat_timeout_secs,
            1,
            MAX_TIMEOUT_SECS,
        )?;
        validate_u64_range(
            "daemon.handshake_timeout_secs",
            self.daemon.handshake_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;
        validate_u64_range(
            "daemon.write_timeout_secs",
            self.daemon.write_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;
        validate_usize_range(
            "daemon.max_connections",
            self.daemon.max_connections,
            1,
            MAX_DAEMON_CONNECTIONS,
        )?;
        validate_u64_range(
            "daemon.control_timeout_secs",
            self.daemon.control_timeout_secs,
            1,
            MAX_TIMEOUT_SECS,
        )?;
        validate_u64_range(
            "daemon.control_request_timeout_secs",
            self.daemon.control_request_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;
        validate_usize_range(
            "daemon.max_control_connections",
            self.daemon.max_control_connections,
            1,
            MAX_CONTROL_CONNECTIONS,
        )?;
        validate_u32_range(
            "daemon.max_handshakes_per_minute",
            self.daemon.max_handshakes_per_minute,
            1,
            MAX_HANDSHAKES_PER_MINUTE,
        )?;
        validate_u32_range(
            "daemon.max_handshakes_per_minute_per_ip",
            self.daemon.max_handshakes_per_minute_per_ip,
            1,
            MAX_HANDSHAKES_PER_MINUTE_PER_IP,
        )?;

        validate_u64_range(
            "join.heartbeat_secs",
            self.join.heartbeat_secs,
            1,
            MAX_TIMEOUT_SECS,
        )?;
        validate_u64_range(
            "join.heartbeat_timeout_secs",
            self.join.heartbeat_timeout_secs,
            2,
            MAX_TIMEOUT_SECS,
        )?;
        if self.join.heartbeat_timeout_secs <= self.join.heartbeat_secs {
            return Err(Error::Config(
                "join.heartbeat_timeout_secs must exceed join.heartbeat_secs".into(),
            ));
        }
        validate_u64_range(
            "join.reconnect_secs",
            self.join.reconnect_secs,
            1,
            MAX_RECONNECT_SECS,
        )?;
        validate_u64_range(
            "join.reconnect_max_secs",
            self.join.reconnect_max_secs,
            self.join.reconnect_secs,
            MAX_RECONNECT_SECS,
        )?;
        validate_u64_range(
            "join.auth_failure_backoff_secs",
            self.join.auth_failure_backoff_secs,
            self.join.reconnect_secs,
            MAX_RECONNECT_SECS,
        )?;
        validate_u64_range(
            "join.connect_timeout_secs",
            self.join.connect_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;
        validate_u64_range(
            "join.write_timeout_secs",
            self.join.write_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;

        validate_u64_range(
            "exec.max_timeout_secs",
            self.exec.max_timeout_secs,
            1,
            MAX_TIMEOUT_SECS,
        )?;
        validate_usize_range(
            "exec.max_output_bytes",
            self.exec.max_output_bytes,
            1,
            MAX_OUTPUT_BYTES,
        )?;
        validate_usize_range(
            "exec.max_concurrent",
            self.exec.max_concurrent,
            1,
            MAX_EXEC_CONCURRENT,
        )?;
        validate_u64_range(
            "exec.output_drain_timeout_secs",
            self.exec.output_drain_timeout_secs,
            1,
            MAX_WRITE_TIMEOUT_SECS,
        )?;

        if let Some(work_dir) = &self.exec.work_dir {
            if !work_dir.is_absolute() {
                return Err(Error::Config(
                    "exec.work_dir must be an absolute path".into(),
                ));
            }
        }

        for executable in &self.exec.allow_exec {
            if !executable.is_absolute() {
                return Err(Error::Config(format!(
                    "exec allowlist entry must be an absolute path: {}",
                    executable.display()
                )));
            }
            if executable
                .to_string_lossy()
                .chars()
                .any(|ch| ch.is_control())
            {
                return Err(Error::Config(
                    "exec allowlist paths must not contain control characters".into(),
                ));
            }
        }

        for (name, value) in &self.exec.env {
            validate_env_name("exec.env key", name)?;
            if value.as_bytes().contains(&0) {
                return Err(Error::Config(format!(
                    "exec.env value for {name} contains a NUL byte"
                )));
            }
        }

        Ok(())
    }

    pub fn log_level(&self) -> Result<LevelFilter> {
        parse_level(&self.log.level)
    }

    pub fn heartbeat_timeout(&self) -> Duration {
        Duration::from_secs(self.daemon.heartbeat_timeout_secs)
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 {
        return Err(Error::Config(format!("{field} must be 1..=128 bytes")));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Error::Config(format!(
            "{field} may contain only ASCII letters, digits, '.', '_' and '-'"
        )));
    }
    Ok(())
}

fn validate_env_name(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || value.contains('=')
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(Error::Config(format!(
            "{field} is not a valid environment name"
        )));
    }
    Ok(())
}

fn validate_u64_range(field: &str, value: u64, min: u64, max: u64) -> Result<()> {
    if !(min..=max).contains(&value) {
        return Err(Error::Config(format!(
            "{field} must be in the range {min}..={max}"
        )));
    }
    Ok(())
}

fn validate_u32_range(field: &str, value: u32, min: u32, max: u32) -> Result<()> {
    if !(min..=max).contains(&value) {
        return Err(Error::Config(format!(
            "{field} must be in the range {min}..={max}"
        )));
    }
    Ok(())
}

fn validate_usize_range(field: &str, value: usize, min: usize, max: usize) -> Result<()> {
    if !(min..=max).contains(&value) {
        return Err(Error::Config(format!(
            "{field} must be in the range {min}..={max}"
        )));
    }
    Ok(())
}
