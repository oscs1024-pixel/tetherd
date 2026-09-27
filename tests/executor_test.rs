use std::collections::BTreeMap;
use std::path::PathBuf;
use tetherd::config::ExecConfig;
use tetherd::join::executor::Executor;
use tetherd::protocol::message::Message;
use uuid::Uuid;

fn config(programs: Vec<PathBuf>) -> ExecConfig {
    ExecConfig {
        allow_exec: programs,
        max_timeout_secs: 2,
        max_output_bytes: 4096,
        max_concurrent: 2,
        output_drain_timeout_secs: 1,
        work_dir: None,
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn executor_denies_non_allowlisted_program() {
    let executor = Executor::new(config(vec![PathBuf::from("/bin/echo")])).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            vec!["/bin/sh".into(), "-c".into(), "true".into()],
            1,
        )
        .await;
    match result {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("not allowlisted")),
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn executor_runs_argv_without_shell() {
    let executor = Executor::new(config(vec![PathBuf::from("/bin/echo")])).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            vec!["/bin/echo".into(), "hello;uname".into()],
            1,
        )
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
    let mut cfg = config(vec![PathBuf::from("/usr/bin/env")]);
    cfg.env.insert("SAFE_TEST".into(), "ok".into());
    let executor = Executor::new(cfg).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), vec!["/usr/bin/env".into()], 1)
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
    let mut cfg = config(vec![PathBuf::from("/usr/bin/printf")]);
    cfg.max_output_bytes = 32;
    let executor = Executor::new(cfg).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            vec![
                "/usr/bin/printf".into(),
                "abcdefghijklmnopqrstuvwxyz0123456789".into(),
            ],
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
    let executor = Executor::new(config(vec![PathBuf::from("/bin/sleep")])).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), vec!["/bin/sleep".into(), "5".into()], 1)
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
    let executor = Executor::new(config(vec![PathBuf::from("/bin/sh")])).unwrap();
    let started = std::time::Instant::now();
    let result = executor
        .execute(
            Uuid::new_v4(),
            vec!["/bin/sh".into(), "-c".into(), "sleep 30 & exit 0".into()],
            2,
        )
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
        PathBuf::from("/bin/sleep"),
        PathBuf::from("/bin/echo"),
    ]);
    cfg.max_concurrent = 1;
    let executor = Executor::new(cfg).unwrap();
    let permit = executor.try_reserve().unwrap();

    let second = executor
        .execute(Uuid::new_v4(), vec!["/bin/echo".into(), "busy".into()], 1)
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
async fn executor_rejects_allowlisted_symlink_after_target_changes() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("tool");
    symlink("/bin/echo", &link).unwrap();
    let executor = Executor::new(config(vec![link.clone()])).unwrap();
    std::fs::remove_file(&link).unwrap();
    symlink("/bin/sleep", &link).unwrap();

    let result = executor
        .execute(
            Uuid::new_v4(),
            vec![link.display().to_string(), "0".into()],
            1,
        )
        .await;
    match result {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("not allowlisted")),
        other => panic!("unexpected response: {other:?}"),
    }
}
