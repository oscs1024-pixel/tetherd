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

use crate::config::{CommandProfile, ExecConfig};
use crate::{Error, Result};

#[derive(Debug)]
pub struct ExecutionResult {
    pub id: Uuid,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
    pub timed_out: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Executor {
    config: Arc<ExecConfig>,
    commands: Arc<HashMap<String, ResolvedCommand>>,
    semaphore: Arc<Semaphore>,
}

#[derive(Clone)]
struct ResolvedCommand {
    program: PathBuf,
    identity: ExecutableIdentity,
    fixed_args: Vec<String>,
    allow_user_args: bool,
    max_user_args: usize,
    max_user_arg_bytes: usize,
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
        let mut commands = HashMap::with_capacity(config.commands.len());
        for (name, profile) in &config.commands {
            commands.insert(name.clone(), resolve_profile(name, profile)?);
        }
        Ok(Self {
            config: Arc::new(config),
            commands: Arc::new(commands),
            semaphore: Arc::new(Semaphore::new(max)),
        })
    }

    pub fn try_reserve(&self) -> Result<OwnedSemaphorePermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy("executor is at capacity".into()))
    }

    pub async fn execute(
        &self,
        id: Uuid,
        command_id: String,
        args: Vec<String>,
        timeout_secs: u64,
    ) -> ExecutionResult {
        let permit = match self.try_reserve() {
            Ok(permit) => permit,
            Err(error) => return error_result(id, error, Instant::now()),
        };
        self.execute_reserved(permit, id, command_id, args, timeout_secs)
            .await
    }

    pub async fn execute_reserved(
        &self,
        _permit: OwnedSemaphorePermit,
        id: Uuid,
        command_id: String,
        args: Vec<String>,
        timeout_secs: u64,
    ) -> ExecutionResult {
        let started = Instant::now();
        match self.execute_inner(&command_id, args, timeout_secs).await {
            Ok((exit_code, stdout, stderr, truncated, timed_out)) => ExecutionResult {
                id,
                exit_code,
                stdout,
                stderr,
                truncated,
                timed_out,
                elapsed_ms: elapsed_ms(started),
                error: None,
            },
            Err(error) => error_result(id, error, started),
        }
    }

    async fn execute_inner(
        &self,
        command_id: &str,
        user_args: Vec<String>,
        requested_timeout_secs: u64,
    ) -> Result<(Option<i32>, Vec<u8>, Vec<u8>, bool, bool)> {
        let profile = self.commands.get(command_id).ok_or_else(|| {
            Error::ExecutionDenied(format!("unknown command profile: {command_id}"))
        })?;
        validate_user_args(profile, &user_args)?;

        validate_executable(&profile.program)?;
        validate_trusted_executable_path(&profile.program)?;
        let current_identity = executable_identity(&profile.program)?;
        if !same_identity(&profile.identity, &current_identity) {
            return Err(Error::ExecutionDenied(format!(
                "command profile executable changed since startup: {command_id}"
            )));
        }

        let timeout_secs = requested_timeout_secs.clamp(1, self.config.max_timeout_secs);
        let drain_grace = Duration::from_secs(self.config.drain_grace_secs);

        let mut command = Command::new(&profile.program);
        command.args(&profile.fixed_args);
        command.args(&user_args);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.kill_on_drop(true);
        #[cfg(unix)]
        command.as_std_mut().process_group(0);
        // Never inherit the service environment. This prevents PSK or other
        // daemon secrets from entering child processes.
        command.env_clear();
        if let Some(work_dir) = &self.config.work_dir {
            command.current_dir(work_dir);
        }

        log::info!(
            "command starting profile={} program={} user_argc={} timeout={}s",
            command_id,
            profile.program.display(),
            user_args.len(),
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
            stdout_bytes,
            stderr_bytes,
            stdout_truncated || stderr_truncated,
            timed_out,
        ))
    }
}

fn resolve_profile(name: &str, profile: &CommandProfile) -> Result<ResolvedCommand> {
    let canonical = std::fs::canonicalize(&profile.program).map_err(|err| {
        Error::Config(format!(
            "failed to resolve exec.commands.{name}.program {}: {err}",
            profile.program.display()
        ))
    })?;
    validate_executable(&canonical)?;
    validate_trusted_executable_path(&canonical)?;
    Ok(ResolvedCommand {
        identity: executable_identity(&canonical)?,
        program: canonical,
        fixed_args: profile.fixed_args.clone(),
        allow_user_args: profile.allow_user_args,
        max_user_args: profile.max_user_args,
        max_user_arg_bytes: profile.max_user_arg_bytes,
    })
}

fn validate_user_args(profile: &ResolvedCommand, args: &[String]) -> Result<()> {
    if !profile.allow_user_args && !args.is_empty() {
        return Err(Error::ExecutionDenied(
            "command profile does not accept user arguments".into(),
        ));
    }
    if args.len() > profile.max_user_args {
        return Err(Error::ExecutionDenied("too many user arguments".into()));
    }
    let total = args.iter().try_fold(0usize, |total, arg| {
        if arg.as_bytes().contains(&0) || arg.chars().any(char::is_control) {
            return Err(Error::ExecutionDenied(
                "user arguments must not contain NUL/control characters".into(),
            ));
        }
        if arg.len() > profile.max_user_arg_bytes {
            return Err(Error::ExecutionDenied(
                "individual user argument exceeds profile byte limit".into(),
            ));
        }
        total
            .checked_add(arg.len())
            .ok_or_else(|| Error::ExecutionDenied("combined argument size overflow".into()))
    })?;
    if total > profile.max_user_arg_bytes {
        return Err(Error::ExecutionDenied(
            "combined user arguments exceed profile byte limit".into(),
        ));
    }
    Ok(())
}

fn error_result(id: Uuid, error: Error, started: Instant) -> ExecutionResult {
    ExecutionResult {
        id,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        truncated: false,
        timed_out: matches!(error, Error::Timeout),
        elapsed_ms: elapsed_ms(started),
        error: Some(error.to_string()),
    }
}

fn validate_executable(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        Error::Config(format!(
            "failed to inspect command profile executable {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "command profile executable is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(Error::Config(format!(
            "command profile executable is not executable: {}",
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
            "command profile executable must be owned by root or the service UID: {}",
            path.display()
        )));
    }
    if mode & 0o022 != 0 || (metadata.uid() == euid && euid != 0 && mode & 0o200 != 0) {
        return Err(Error::Config(format!(
            "command profile executable is mutable by an untrusted/service identity: {} mode={mode:o}",
            path.display()
        )));
    }

    let mut current = path.parent();
    while let Some(dir) = current {
        let metadata = std::fs::metadata(dir)?;
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != 0 && metadata.uid() != euid {
            return Err(Error::Config(format!(
                "command profile executable parent has an untrusted owner: {}",
                dir.display()
            )));
        }
        if mode & 0o022 != 0 || (metadata.uid() == euid && euid != 0 && mode & 0o200 != 0) {
            return Err(Error::Config(format!(
                "command profile executable parent is mutable by an untrusted/service identity: {} mode={mode:o}",
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
        Ok(result) => {
            result.map_err(|_| Error::Protocol(format!("{stream_name} drain task failed")))?
        }
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
