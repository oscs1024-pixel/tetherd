use std::path::PathBuf;
use tetherd::config::ExecConfig;
use tetherd::join::executor::Executor;
use tetherd::protocol::message::Message;
use uuid::Uuid;

fn config(programs: Vec<PathBuf>) -> ExecConfig {
    ExecConfig {
        allow_exec: programs,
        max_timeout_secs: 2,
        max_output_bytes: 32,
        max_concurrent: 2,
        work_dir: None,
        inherit_env: false,
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
async fn executor_truncates_but_drains_output() {
    let executor = Executor::new(config(vec![PathBuf::from("/usr/bin/printf")])).unwrap();
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
        } => {
            assert_eq!(stdout.len(), 32)
        }
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

#[tokio::test]
async fn executor_returns_busy_instead_of_queueing_unbounded_work() {
    let mut cfg = config(vec![
        PathBuf::from("/bin/sleep"),
        PathBuf::from("/bin/echo"),
    ]);
    cfg.max_concurrent = 1;
    let executor = Executor::new(cfg).unwrap();
    let running = {
        let executor = executor.clone();
        tokio::spawn(async move {
            executor
                .execute(Uuid::new_v4(), vec!["/bin/sleep".into(), "1".into()], 2)
                .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let second = executor
        .execute(Uuid::new_v4(), vec!["/bin/echo".into(), "busy".into()], 1)
        .await;
    match second {
        Message::ExecResponse {
            error: Some(error), ..
        } => assert!(error.contains("busy")),
        other => panic!("unexpected response: {other:?}"),
    }
    let _ = running.await.unwrap();
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
