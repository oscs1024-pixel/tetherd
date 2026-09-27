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
use uuid::Uuid;

use crate::config::{CommandConfig, ExecConfig};
use crate::{Error, Result};

#[derive(Debug)]
pub struct ExecutionOutcome {
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
    commands: Arc<HashMap<String, PreparedCommand>>,
    semaphore: Arc<Semaphore>,
}

#[derive(Clone)]
struct PreparedCommand {
    program: PathBuf,
    identity: ExecutableIdentity,
    fixed_args: Vec<String>,
    allow_extra_args: bool,
    max_extra_args: usize,
    timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    canonical: PathBuf,
}

impl Executor {
    pub fn new(config: ExecConfig) -> Result<Self> {
        let max = config.max_concurrent;
        let mut commands = HashMap::with_capacity(config.commands.len());
        for (name, command) in &config.commands {
            commands.insert(name.clone(), prepare_command(command)?);
        }

        if let Some(work_dir) = &config.work_dir {
            let metadata = std::fs::metadata(work_dir).map_err(|err| {
                Error::Config(format!(
                    "failed to inspect exec.work_dir {}: {err}",
                    work_dir.display()
                ))
            })?;
            if !metadata.is_dir() {
                return Err(Error::Config(format!(
                    "exec.work_dir is not a directory: {}",
                    work_dir.display()
                )));
            }
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
            .map_err(|_| Error::Busy("executor is saturated".into()))
    }

    pub async fn execute(
        &self,
        id: Uuid,
        command: String,
        args: Vec<String>,
        timeout_secs: u64,
    ) -> ExecutionOutcome {
        match self.try_reserve() {
            Ok(permit) => {
                self.execute_reserved(id, command, args, timeout_secs, permit)
                    .await
            }
            Err(error) => error_response(id, Instant::now(), error),
        }
    }

    pub async fn execute_reserved(
        &self,
        id: Uuid,
        command: String,
        args: Vec<String>,
        timeout_secs: u64,
        permit: OwnedSemaphorePermit,
    ) -> ExecutionOutcome {
        let started = Instant::now();
        match self
            .execute_inner(&command, args, timeout_secs, permit)
            .await
        {
            Ok((exit_code, stdout, stderr, truncated, timed_out)) => ExecutionOutcome {
                id,
                exit_code,
                stdout,
                stderr,
                truncated,
                timed_out,
                elapsed_ms: elapsed_ms(started),
                error: None,
            },
            Err(error) => error_response(id, started, error),
        }
    }

    async fn execute_inner(
        &self,
        command_name: &str,
        extra_args: Vec<String>,
        requested_timeout_secs: u64,
        _permit: OwnedSemaphorePermit,
    ) -> Result<(Option<i32>, Vec<u8>, Vec<u8>, bool, bool)> {
        let profile = self.commands.get(command_name).ok_or_else(|| {
            Error::ExecutionDenied(format!("unknown command profile: {command_name}"))
        })?;

        validate_extra_args(profile, &extra_args)?;

        let current_identity = validate_trusted_executable(&profile.program)?;
        if current_identity != profile.identity {
            return Err(Error::ExecutionDenied(format!(
                "command executable identity changed: {}",
                profile.program.display()
            )));
        }

        let profile_timeout = profile
            .timeout_secs
            .unwrap_or(self.config.max_timeout_secs)
            .min(self.config.max_timeout_secs);
        let timeout_secs = requested_timeout_secs.clamp(1, profile_timeout);

        let mut command = Command::new(&profile.program);
        command.args(&profile.fixed_args);
        command.args(&extra_args);
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.kill_on_drop(true);
        #[cfg(unix)]
        command.as_std_mut().process_group(0);
        command.env_clear();
        command.envs(&self.config.env);
        if let Some(work_dir) = &self.config.work_dir {
            command.current_dir(work_dir);
        }

        log::info!(
            "command starting profile={} program={} argc={} timeout={}s",
            command_name,
            profile.program.display(),
            profile.fixed_args.len().saturating_add(extra_args.len()),
            timeout_secs
        );

        let mut child = command.spawn()?;
        let mut process_group = ProcessGroupGuard::new(&child);
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Protocol("child stdout was not piped".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Protocol("child stderr was not piped".into()))?;
        let limit = self.config.max_output_bytes;
        let mut stdout_task = tokio::spawn(drain_limited(stdout, limit));
        let mut stderr_task = tokio::spawn(drain_limited(stderr, limit));

        let wait_result =
            tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;
        let (status, timed_out) = match wait_result {
            Ok(status) => (Some(status?), false),
            Err(_) => {
                process_group.kill_now();
                let _ = child.start_kill();
                let status = child.wait().await.ok();
                (status, true)
            }
        };

        let drain_timeout = Duration::from_secs(self.config.output_drain_timeout_secs);
        let drain_result = tokio::time::timeout(drain_timeout, async {
            let (stdout_join, stderr_join) = tokio::join!(&mut stdout_task, &mut stderr_task);
            let stdout_result =
                stdout_join.map_err(|_| Error::Protocol("stdout drain task failed".into()))??;
            let stderr_result =
                stderr_join.map_err(|_| Error::Protocol("stderr drain task failed".into()))??;
            Ok::<_, Error>((stdout_result, stderr_result))
        })
        .await;

        let ((stdout_bytes, stdout_truncated), (stderr_bytes, stderr_truncated)) =
            match drain_result {
                Ok(result) => result?,
                Err(_) => {
                    process_group.kill_now();
                    stdout_task.abort();
                    stderr_task.abort();
                    return Err(Error::Timeout);
                }
            };

        process_group.disarm();
        Ok((
            status.and_then(|s| s.code()),
            stdout_bytes,
            stderr_bytes,
            stdout_truncated || stderr_truncated,
            timed_out,
        ))
    }
}

fn prepare_command(command: &CommandConfig) -> Result<PreparedCommand> {
    let canonical = std::fs::canonicalize(&command.program).map_err(|err| {
        Error::Config(format!(
            "failed to resolve command executable {}: {err}",
            command.program.display()
        ))
    })?;
    let identity = validate_trusted_executable(&canonical)?;
    Ok(PreparedCommand {
        program: canonical,
        identity,
        fixed_args: command.fixed_args.clone(),
        allow_extra_args: command.allow_extra_args,
        max_extra_args: command.max_extra_args,
        timeout_secs: command.timeout_secs,
    })
}

fn validate_extra_args(profile: &PreparedCommand, args: &[String]) -> Result<()> {
    if !profile.allow_extra_args && !args.is_empty() {
        return Err(Error::ExecutionDenied(
            "command profile does not allow extra arguments".into(),
        ));
    }
    if args.len() > profile.max_extra_args {
        return Err(Error::ExecutionDenied(format!(
            "command profile accepts at most {} extra arguments",
            profile.max_extra_args
        )));
    }

    let mut total = 0usize;
    for arg in args {
        if arg.as_bytes().contains(&0) {
            return Err(Error::ExecutionDenied(
                "arguments must not contain NUL bytes".into(),
            ));
        }
        if arg.len() > 64 * 1024 {
            return Err(Error::ExecutionDenied("argument exceeds 64 KiB".into()));
        }
        total = total
            .checked_add(arg.len())
            .ok_or_else(|| Error::ExecutionDenied("combined argument size overflow".into()))?;
    }
    if total > 256 * 1024 {
        return Err(Error::ExecutionDenied(
            "combined arguments exceed 256 KiB".into(),
        ));
    }
    Ok(())
}

fn error_response(id: Uuid, started: Instant, error: Error) -> ExecutionOutcome {
    ExecutionOutcome {
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

#[cfg(unix)]
fn validate_trusted_executable(path: &Path) -> Result<ExecutableIdentity> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        Error::Config(format!(
            "failed to inspect command executable {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "command executable is not a regular file: {}",
            path.display()
        )));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(Error::Config(format!(
            "command executable is not executable: {}",
            path.display()
        )));
    }
    if metadata.uid() != 0 {
        return Err(Error::Config(format!(
            "command executable must be root-owned: {} owner_uid={}",
            path.display(),
            metadata.uid()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(Error::Config(format!(
            "command executable must not be group/world writable: {} mode={:o}",
            path.display(),
            mode & 0o777
        )));
    }

    let mut current = path.parent();
    while let Some(parent) = current {
        let parent_metadata = std::fs::metadata(parent).map_err(|err| {
            Error::Config(format!(
                "failed to inspect executable parent {}: {err}",
                parent.display()
            ))
        })?;
        if !parent_metadata.is_dir()
            || parent_metadata.uid() != 0
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(Error::Config(format!(
                "command executable parent is not trusted: {}",
                parent.display()
            )));
        }
        current = parent.parent();
    }

    Ok(ExecutableIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn validate_trusted_executable(path: &Path) -> Result<ExecutableIdentity> {
    let metadata = std::fs::metadata(path).map_err(|err| {
        Error::Config(format!(
            "failed to inspect command executable {}: {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::Config(format!(
            "command executable is not a regular file: {}",
            path.display()
        )));
    }
    Ok(ExecutableIdentity {
        canonical: path.to_owned(),
    })
}

#[cfg(unix)]
struct ProcessGroupGuard {
    pgid: Option<nix::unistd::Pid>,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: &tokio::process::Child) -> Self {
        let pgid = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .map(nix::unistd::Pid::from_raw);
        Self { pgid }
    }

    fn kill_now(&self) {
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::killpg(pgid, nix::sys::signal::Signal::SIGKILL);
        }
    }

    fn disarm(&mut self) {
        self.pgid = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill_now();
    }
}

#[cfg(not(unix))]
struct ProcessGroupGuard;

#[cfg(not(unix))]
impl ProcessGroupGuard {
    fn new(_child: &tokio::process::Child) -> Self {
        Self
    }

    fn kill_now(&self) {}

    fn disarm(&mut self) {}
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
