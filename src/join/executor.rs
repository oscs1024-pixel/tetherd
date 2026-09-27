use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::config::ExecConfig;
use crate::protocol::message::Message;
use crate::{Error, Result};

#[derive(Clone)]
pub struct Executor {
    config: Arc<ExecConfig>,
    allowed: Arc<HashMap<PathBuf, ExecutableIdentity>>,
    semaphore: Arc<Semaphore>,
}

#[derive(Clone)]
struct ExecutableIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
}

impl Executor {
    pub fn new(config: ExecConfig) -> Result<Self> {
        let max = config.max_concurrent;
        let mut allowed = HashMap::with_capacity(config.allow_exec.len());
        for program in &config.allow_exec {
            let canonical = std::fs::canonicalize(program).map_err(|err| {
                Error::Config(format!(
                    "failed to resolve allowlisted executable {}: {err}",
                    program.display()
                ))
            })?;
            validate_executable(&canonical)?;
            validate_trusted_executable_path(&canonical)?;
            let identity = executable_identity(&canonical)?;
            allowed.insert(canonical, identity);
        }
        Ok(Self {
            config: Arc::new(config),
            allowed: Arc::new(allowed),
            semaphore: Arc::new(Semaphore::new(max)),
        })
    }

    pub fn try_reserve(&self) -> Result<OwnedSemaphorePermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy("executor is at capacity".into()))
    }

    pub async fn execute(&self, id: Uuid, argv: Vec<String>, timeout_secs: u64) -> Message {
        let permit = match self.try_reserve() {
            Ok(permit) => permit,
            Err(error) => return error_response(id, error, Instant::now()),
        };
        self.execute_reserved(permit, id, argv, timeout_secs).await
    }

    pub async fn execute_reserved(
        &self,
        _permit: OwnedSemaphorePermit,
        id: Uuid,
        argv: Vec<String>,
        timeout_secs: u64,
    ) -> Message {
        let started = Instant::now();
        match self.execute_inner(argv, timeout_secs).await {
            Ok((exit_code, stdout, stderr, truncated, timed_out)) => Message::ExecResponse {
                id,
                exit_code,
                stdout,
                stderr,
                truncated,
                timed_out,
                elapsed_ms: elapsed_ms(started),
                error: None,
            },
            Err(error) => error_response(id, error, started),
        }
    }

    async fn execute_inner(
        &self,
        argv: Vec<String>,
        requested_timeout_secs: u64,
    ) -> Result<(Option<i32>, String, String, bool, bool)> {
        validate_argv(&argv)?;

        let requested_program = Path::new(&argv[0]);
        let canonical_program = std::fs::canonicalize(requested_program).map_err(|_| {
            Error::ExecutionDenied(format!(
                "executable is not available: {}",
                requested_program.display()
            ))
        })?;
        let expected_identity = self.allowed.get(&canonical_program).ok_or_else(|| {
            Error::ExecutionDenied(format!(
                "executable is not allowlisted: {}",
                requested_program.display()
            ))
        })?;
        validate_executable(&canonical_program)?;
        validate_trusted_executable_path(&canonical_program)?;
        let current_identity = executable_identity(&canonical_program)?;
        if !same_identity(expected_identity, &current_identity) {
            return Err(Error::ExecutionDenied(format!(
                "allowlisted executable changed since startup: {}",
                canonical_program.display()
            )));
        }

        let timeout_secs = requested_timeout_secs.clamp(1, self.config.max_timeout_secs);
        let drain_grace = Duration::from_secs(self.config.drain_grace_secs);

        let mut command = Command::new(&canonical_program);
        command.args(&argv[1..]);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.kill_on_drop(true);
        #[cfg(unix)]
        command.as_std_mut().process_group(0);
        // Deliberately never inherit the daemon environment. In particular this
        // prevents auth.psk_env from leaking into allowlisted child processes.
        command.env_clear();
        if let Some(work_dir) = &self.config.work_dir {
            command.current_dir(work_dir);
        }

        log::info!(
            "command starting program={} argc={} timeout={}s",
            canonical_program.display(),
            argv.len().saturating_sub(1),
            timeout_secs
        );

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Protocol("child stdout was not piped".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Protocol("child stderr was not piped".into()))?;
        let limit = self.config.max_output_bytes;
        let stdout_task = tokio::spawn(drain_limited(stdout, limit));
        let stderr_task = tokio::spawn(drain_limited(stderr, limit));

        let wait_result =
            tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;
        let (status, timed_out) = match wait_result {
            Ok(status) => (Some(status?), false),
            Err(_) => {
                kill_child_tree(&mut child);
                let status = tokio::time::timeout(drain_grace, child.wait())
                    .await
                    .map_err(|_| Error::Timeout)?
                    .ok();
                (status, true)
            }
        };

        let (stdout_bytes, stdout_truncated) =
            finish_drain(stdout_task, drain_grace, "stdout").await?;
        let (stderr_bytes, stderr_truncated) =
            finish_drain(stderr_task, drain_grace, "stderr").await?;

        Ok((
            status.and_then(|s| s.code()),
            String::from_utf8_lossy(&stdout_bytes).into_owned(),
            String::from_utf8_lossy(&stderr_bytes).into_owned(),
            stdout_truncated || stderr_truncated,
            timed_out,
        ))
    }
}

fn error_response(id: Uuid, error: Error, started: Instant) -> Message {
    Message::ExecResponse {
        id,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        truncated: false,
        timed_out: matches!(error, Error::Timeout),
        elapsed_ms: elapsed_ms(started),
        error: Some(error.to_string()),
    }
}

fn validate_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() {
        return Err(Error::ExecutionDenied("argv must not be empty".into()));
    }
    if argv.len() > 128 {
        return Err(Error::ExecutionDenied("too many arguments".into()));
    }
    if argv.iter().any(|arg| arg.as_bytes().contains(&0)) {
        return Err(Error::ExecutionDenied(
            "argv must not contain NUL bytes".into(),
        ));
    }
    if argv.iter().any(|arg| arg.len() > 64 * 1024) {
        return Err(Error::ExecutionDenied("argument exceeds 64 KiB".into()));
    }
    let total_arg_bytes = argv.iter().try_fold(0usize, |total, arg| {
        total
            .checked_add(arg.len())
            .ok_or_else(|| Error::ExecutionDenied("combined argv size overflow".into()))
    })?;
    if total_arg_bytes > 256 * 1024 {
        return Err(Error::ExecutionDenied(
            "combined argv exceeds 256 KiB".into(),
        ));
    }
    let program = Path::new(&argv[0]);
    if !program.is_absolute() {
        return Err(Error::ExecutionDenied(
            "argv[0] must be an absolute executable path".into(),
        ));
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        Error::Config(format!(
            "failed to inspect allowlisted executable {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "allowlisted executable is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(Error::Config(format!(
            "allowlisted executable is not executable: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_executable_path(path: &Path) -> Result<()> {
    let euid = nix::unistd::Uid::effective().as_raw();
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;
    if metadata.uid() != 0 && metadata.uid() != euid {
        return Err(Error::Config(format!(
            "allowlisted executable must be owned by root or the service UID: {}",
            path.display()
        )));
    }
    if mode & 0o022 != 0 || (metadata.uid() == euid && euid != 0 && mode & 0o200 != 0) {
        return Err(Error::Config(format!(
            "allowlisted executable is mutable by an untrusted/service identity: {} mode={mode:o}",
            path.display()
        )));
    }

    let mut current = path.parent();
    while let Some(dir) = current {
        let metadata = std::fs::metadata(dir)?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 && metadata.uid() != euid {
            return Err(Error::Config(format!(
                "allowlisted executable parent has an untrusted owner: {}",
                dir.display()
            )));
        }
        if mode & 0o022 != 0 || (metadata.uid() == euid && euid != 0 && mode & 0o200 != 0) {
            return Err(Error::Config(format!(
                "allowlisted executable parent is mutable by an untrusted/service identity: {} mode={mode:o}",
                dir.display()
            )));
        }
        current = dir.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_executable_path(_path: &Path) -> Result<()> {
    Ok(())
}

fn executable_identity(path: &Path) -> Result<ExecutableIdentity> {
    let metadata = std::fs::metadata(path)?;
    Ok(ExecutableIdentity {
        #[cfg(unix)]
        dev: metadata.dev(),
        #[cfg(unix)]
        ino: metadata.ino(),
        len: metadata.len(),
    })
}

fn same_identity(expected: &ExecutableIdentity, current: &ExecutableIdentity) -> bool {
    #[cfg(unix)]
    if expected.dev != current.dev || expected.ino != current.ino {
        return false;
    }
    expected.len == current.len
}

fn kill_child_tree(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.start_kill();
}

async fn finish_drain(
    mut task: JoinHandle<Result<(Vec<u8>, bool)>>,
    grace: Duration,
    stream_name: &str,
) -> Result<(Vec<u8>, bool)> {
    match tokio::time::timeout(grace, &mut task).await {
        Ok(result) => result.map_err(|_| Error::Protocol(format!("{stream_name} drain task failed")))?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err(Error::Timeout)
        }
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn drain_limited<R>(mut reader: R, limit: usize) -> Result<(Vec<u8>, bool)>
where
    R: AsyncRead + Unpin,
{
    let mut stored = Vec::with_capacity(limit.min(64 * 1024));
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let remaining = limit.saturating_sub(stored.len());
        if remaining > 0 {
            let take = remaining.min(n);
            stored.extend_from_slice(&buf[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((stored, truncated))
}
