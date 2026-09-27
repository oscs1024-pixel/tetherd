use std::collections::BTreeMap;
use std::path::PathBuf;
use tetherd::config::{CommandConfig, ExecConfig};
use tetherd::join::executor::Executor;
use tetherd::protocol::message::Message;
use uuid::Uuid;

fn profile(
    program: &str,
    fixed_args: &[&str],
    allow_extra_args: bool,
    max_extra_args: usize,
) -> CommandConfig {
    CommandConfig {
        program: PathBuf::from(program),
        fixed_args: fixed_args.iter().map(|value| (*value).to_owned()).collect(),
        allow_extra_args,
        max_extra_args,
        timeout_secs: None,
    }
}

fn config(commands: Vec<(&str, CommandConfig)>) -> ExecConfig {
    ExecConfig {
        commands: commands
            .into_iter()
            .map(|(name, command)| (name.to_owned(), command))
            .collect(),
        max_timeout_secs: 2,
        max_output_bytes: 4096,
        max_concurrent: 2,
        output_drain_timeout_secs: 1,
        work_dir: None,
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn executor_denies_unknown_command_profile() {
    let executor =
        Executor::new(config(vec![("echo", profile("/bin/echo", &[], true, 4))])).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "shell".into(),
            vec!["-c".into(), "true".into()],
            1,
        )
        .await;
    match result {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("unknown command profile")),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn command_profile_denies_extra_args_by_default() {
    let executor = Executor::new(config(vec![(
        "echo-fixed",
        profile("/bin/echo", &["fixed"], false, 0),
    )]))
    .unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "echo-fixed".into(),
            vec!["unexpected".into()],
            1,
        )
        .await;
    match result {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("does not allow extra arguments")),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_runs_allowed_args_without_shell() {
    let executor = Executor::new(config(vec![(
        "echo",
        profile("/bin/echo", &[], true, 4),
    )]))
    .unwrap();
    let result = executor
        .execute(Uuid::new_v4(), "echo".into(), vec!["hello;uname".into()], 1)
        .await;
    match result {
        Message::ExecResponse {
            stdout,
            error: None,
            ..
        } => assert_eq!(stdout, "hello;uname\n"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_clears_parent_environment_and_uses_only_explicit_env() {
    let mut cfg = config(vec![("env", profile("/usr/bin/env", &[], false, 0))]);
    cfg.env.insert("SAFE_TEST".into(), "ok".into());
    let executor = Executor::new(cfg).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), "env".into(), Vec::new(), 1)
        .await;
    match result {
        Message::ExecResponse {
            stdout,
            error: None,
            ..
        } => assert_eq!(stdout, "SAFE_TEST=ok\n"),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_truncates_but_drains_output() {
    let mut cfg = config(vec![("printf", profile("/usr/bin/printf", &[], true, 1))]);
    cfg.max_output_bytes = 32;
    let executor = Executor::new(cfg).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "printf".into(),
            vec!["abcdefghijklmnopqrstuvwxyz0123456789".into()],
            1,
        )
        .await;
    match result {
        Message::ExecResponse {
            stdout,
            truncated: true,
            error: None,
            ..
        } => assert_eq!(stdout.len(), 32),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_kills_on_timeout() {
    let executor =
        Executor::new(config(vec![("sleep", profile("/bin/sleep", &[], true, 1))])).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), "sleep".into(), vec!["5".into()], 1)
        .await;
    match result {
        Message::ExecResponse {
            timed_out: true, ..
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn executor_bounds_pipe_drain_when_descendant_keeps_stdout_open() {
    let executor = Executor::new(config(vec![(
        "escaped-child",
        profile("/bin/sh", &["-c", "sleep 30 & exit 0"], false, 0),
    )]))
    .unwrap();
    let started = std::time::Instant::now();
    let result = executor
        .execute(Uuid::new_v4(), "escaped-child".into(), Vec::new(), 2)
        .await;

    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    match result {
        Message::ExecResponse {
            timed_out: true,
            error: Some(_),
            ..
        } => {}
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_returns_busy_instead_of_queueing_unbounded_work() {
    let mut cfg = config(vec![
        ("sleep", profile("/bin/sleep", &[], true, 1)),
        ("echo", profile("/bin/echo", &[], true, 4)),
    ]);
    cfg.max_concurrent = 1;
    let executor = Executor::new(cfg).unwrap();
    let permit = executor.try_reserve().unwrap();

    let second = executor
        .execute(Uuid::new_v4(), "echo".into(), vec!["busy".into()], 1)
        .await;
    match second {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("busy") || error.contains("saturated")),
        other => panic!("unexpected response: {other:?}"),
    }
    drop(permit);
}

#[cfg(unix)]
#[tokio::test]
async fn executor_rejects_command_symlink_after_target_changes() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("tool");
    symlink("/bin/echo", &link).unwrap();
    let executor = Executor::new(config(vec![(
        "tool",
        CommandConfig {
            program: link.clone(),
            fixed_args: Vec::new(),
            allow_extra_args: true,
            max_extra_args: 1,
            timeout_secs: None,
        },
    )]))
    .unwrap();

    std::fs::remove_file(&link).unwrap();
    symlink("/bin/sleep", &link).unwrap();

    let result = executor
        .execute(Uuid::new_v4(), "tool".into(), vec!["0".into()], 1)
        .await;
    match result {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(
            error.contains("identity changed")
                || error.contains("not available")
                || error.contains("not trusted")
        ),
        other => panic!("unexpected response: {other:?}"),
    }
}
