use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use log::LevelFilter;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::logging::{parse_level, ColorMode};
use crate::{Error, Result};

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
            read_secret_file(path)?.trim().to_owned()
        } else {
            let name = self.psk_env.as_ref().expect("checked above");
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

#[cfg(unix)]
fn read_secret_file(path: &Path) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "PSK path is not a regular file: {}",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    let euid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(Error::Config(format!(
            "PSK file must be owned by root or the service UID: {} owner={}",
            path.display(),
            metadata.uid()
        )));
    }
    if mode & 0o077 != 0 {
        return Err(Error::Config(format!(
            "PSK file permissions must not grant group/other access: {} mode={mode:o}",
            path.display()
        )));
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

#[cfg(not(unix))]
fn read_secret_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "PSK path is not a regular file: {}",
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
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_control_timeout_secs")]
    pub control_timeout_secs: u64,
    #[serde(default = "default_control_request_timeout_secs")]
    pub control_request_timeout_secs: u64,
    #[serde(default = "default_max_control_connections")]
    pub max_control_connections: usize,
    #[serde(default = "default_write_timeout_secs")]
    pub write_timeout_secs: u64,
    #[serde(default = "default_exec_output_idle_timeout_secs")]
    pub exec_output_idle_timeout_secs: u64,
    #[serde(default = "default_max_handshakes_per_minute")]
    pub max_handshakes_per_minute: usize,
    #[serde(default = "default_max_handshakes_per_ip_per_minute")]
    pub max_handshakes_per_ip_per_minute: usize,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            control_socket: default_socket_path(),
            heartbeat_timeout_secs: default_heartbeat_timeout_secs(),
            handshake_timeout_secs: default_handshake_timeout_secs(),
            max_connections: default_max_connections(),
            control_timeout_secs: default_control_timeout_secs(),
            control_request_timeout_secs: default_control_request_timeout_secs(),
            max_control_connections: default_max_control_connections(),
            write_timeout_secs: default_write_timeout_secs(),
            exec_output_idle_timeout_secs: default_exec_output_idle_timeout_secs(),
            max_handshakes_per_minute: default_max_handshakes_per_minute(),
            max_handshakes_per_ip_per_minute: default_max_handshakes_per_ip_per_minute(),
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
fn default_write_timeout_secs() -> u64 {
    10
}
fn default_exec_output_idle_timeout_secs() -> u64 {
    15
}
fn default_max_handshakes_per_minute() -> usize {
    600
}
fn default_max_handshakes_per_ip_per_minute() -> usize {
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
fn default_connect_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    #[serde(default)]
    pub commands: HashMap<String, CommandProfile>,
    /// Legacy raw-path allowlist. Non-empty values are rejected by validation.
    #[serde(default)]
    pub allow_exec: Vec<PathBuf>,
    #[serde(default = "default_exec_timeout_secs")]
    pub max_timeout_secs: u64,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: usize,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default)]
    pub work_dir: Option<PathBuf>,
    #[serde(default)]
    pub inherit_env: bool,
    #[serde(default = "default_drain_grace_secs")]
    pub drain_grace_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProfile {
    pub program: PathBuf,
    #[serde(default)]
    pub fixed_args: Vec<String>,
    #[serde(default)]
    pub allow_user_args: bool,
    #[serde(default = "default_max_user_args")]
    pub max_user_args: usize,
    #[serde(default = "default_max_user_arg_bytes")]
    pub max_user_arg_bytes: usize,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            commands: HashMap::new(),
            allow_exec: Vec::new(),
            max_timeout_secs: default_exec_timeout_secs(),
            max_output_bytes: default_output_limit(),
            max_concurrent: default_max_concurrent(),
            work_dir: None,
            inherit_env: false,
            drain_grace_secs: default_drain_grace_secs(),
        }
    }
}

fn default_exec_timeout_secs() -> u64 {
    30
}
fn default_output_limit() -> usize {
    1024 * 1024
}
fn default_max_concurrent() -> usize {
    4
}
fn default_drain_grace_secs() -> u64 {
    2
}
fn default_max_user_args() -> usize {
    16
}
fn default_max_user_arg_bytes() -> usize {
    16 * 1024
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = read_config_file(path.as_ref())?;
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
        if self
            .auth
            .psk_env
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(Error::Config("auth.psk_env must not be empty".into()));
        }
        if !self.daemon.control_socket.is_absolute() {
            return Err(Error::Config(
                "daemon.control_socket must be an absolute path".into(),
            ));
        }
        if self.daemon.heartbeat_timeout_secs == 0
            || self.daemon.handshake_timeout_secs == 0
            || self.daemon.max_connections == 0
            || self.daemon.control_timeout_secs == 0
            || self.daemon.control_request_timeout_secs == 0
            || self.daemon.max_control_connections == 0
            || self.daemon.write_timeout_secs == 0
            || self.daemon.exec_output_idle_timeout_secs == 0
            || self.daemon.max_handshakes_per_minute == 0
            || self.daemon.max_handshakes_per_ip_per_minute == 0
            || self.join.heartbeat_secs == 0
            || self.join.heartbeat_timeout_secs <= self.join.heartbeat_secs
            || self.join.reconnect_secs == 0
            || self.join.connect_timeout_secs == 0
            || self.join.write_timeout_secs == 0
            || self.exec.max_timeout_secs == 0
            || self.exec.max_output_bytes == 0
            || self.exec.max_output_bytes > 1024 * 1024
            || self.exec.max_concurrent == 0
        {
            return Err(Error::Config(
                "timeout/limit values must be positive and heartbeat_timeout must exceed heartbeat interval"
                    .into(),
            ));
        }
        if self.daemon.max_connections > 4096
            || self.daemon.max_control_connections > 256
            || self.daemon.max_handshakes_per_minute > 100_000
            || self.daemon.max_handshakes_per_ip_per_minute > self.daemon.max_handshakes_per_minute
            || self.exec.max_concurrent > 64
            || self.daemon.heartbeat_timeout_secs > 3600
            || self.daemon.handshake_timeout_secs > 300
            || self.daemon.control_timeout_secs > 3600
            || self.daemon.control_request_timeout_secs > 300
            || self.daemon.write_timeout_secs > 300
            || self.daemon.exec_output_idle_timeout_secs > 60
            || self.join.heartbeat_secs > 3600
            || self.join.heartbeat_timeout_secs > 7200
            || self.join.reconnect_secs > 3600
            || self.join.connect_timeout_secs > 300
            || self.join.write_timeout_secs > 300
            || self.exec.max_timeout_secs > 3600
            || self.exec.drain_grace_secs > 30
        {
            return Err(Error::Config(
                "configured resource/timeout limit exceeds the production safety ceiling".into(),
            ));
        }
        if self.exec.inherit_env {
            return Err(Error::Config(
                "exec.inherit_env=true is forbidden; child environments are always cleared".into(),
            ));
        }
        if let Some(work_dir) = &self.exec.work_dir {
            if !work_dir.is_absolute() {
                return Err(Error::Config(
                    "exec.work_dir must be an absolute path".into(),
                ));
            }
        }
        if !self.exec.allow_exec.is_empty() {
            return Err(Error::Config(
                "exec.allow_exec is no longer accepted; define least-privilege exec.commands profiles"
                    .into(),
            ));
        }
        for (name, profile) in &self.exec.commands {
            validate_identifier("exec command id", name)?;
            if !profile.program.is_absolute() {
                return Err(Error::Config(format!(
                    "exec.commands.{name}.program must be an absolute path: {}",
                    profile.program.display()
                )));
            }
            if profile
                .program
                .to_string_lossy()
                .chars()
                .any(|ch| ch.is_control())
            {
                return Err(Error::Config(format!(
                    "exec.commands.{name}.program must not contain control characters"
                )));
            }
            if profile.max_user_args > 64 || profile.max_user_arg_bytes > 64 * 1024 {
                return Err(Error::Config(format!(
                    "exec.commands.{name} argument limits exceed the production safety ceiling"
                )));
            }
            if !profile.allow_user_args
                && (profile.max_user_args != default_max_user_args()
                    || profile.max_user_arg_bytes != default_max_user_arg_bytes())
            {
                return Err(Error::Config(format!(
                    "exec.commands.{name} sets user argument limits but allow_user_args=false"
                )));
            }
            validate_argument_vector(
                &format!("exec.commands.{name}.fixed_args"),
                &profile.fixed_args,
                64,
                64 * 1024,
            )?;
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

#[cfg(unix)]
fn read_config_file(path: &Path) -> Result<String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // Open once, validate the opened descriptor, then read from that same
    // descriptor. This removes the pathname TOCTOU window between validation
    // and parsing and rejects a final-component symlink.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "configuration path is not a regular file: {}",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::Config(format!(
            "configuration file must not be group/world writable: {} mode={mode:o}",
            path.display()
        )));
    }
    let euid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err(Error::Config(format!(
            "configuration file must be owned by root or the service UID: {} owner={}",
            path.display(),
            metadata.uid()
        )));
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

#[cfg(not(unix))]
fn read_config_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "configuration path is not a regular file: {}",
            path.display()
        )));
    }
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

fn validate_argument_vector(
    field: &str,
    args: &[String],
    max_args: usize,
    max_bytes: usize,
) -> Result<()> {
    if args.len() > max_args {
        return Err(Error::Config(format!(
            "{field} contains too many arguments"
        )));
    }
    let mut total = 0usize;
    for arg in args {
        if arg.as_bytes().contains(&0) || arg.chars().any(char::is_control) {
            return Err(Error::Config(format!(
                "{field} contains NUL/control characters"
            )));
        }
        total = total
            .checked_add(arg.len())
            .ok_or_else(|| Error::Config(format!("{field} byte count overflow")))?;
    }
    if total > max_bytes {
        return Err(Error::Config(format!(
            "{field} exceeds the configured byte ceiling"
        )));
    }
    Ok(())
}
