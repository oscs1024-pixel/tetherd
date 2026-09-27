use std::path::PathBuf;
use tetherd::config::ExecConfig;
use tetherd::join::executor::Executor;
use uuid::Uuid;

fn config(programs: Vec<PathBuf>) -> ExecConfig {
    ExecConfig {
        allow_exec: programs,
        max_timeout_secs: 2,
        max_output_bytes: 32,
        max_concurrent: 2,
        work_dir: None,
        inherit_env: false,
        drain_grace_secs: 1,
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
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("not allowlisted")),
        "unexpected result: {result:?}"
    );
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
    assert_eq!(result.error, None);
    assert_eq!(result.stdout, b"hello;uname\n");
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
    assert_eq!(result.error, None);
    assert!(result.truncated);
    assert_eq!(result.stdout.len(), 32);
}

#[tokio::test]
async fn executor_kills_on_timeout() {
    let executor = Executor::new(config(vec![PathBuf::from("/bin/sleep")])).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), vec!["/bin/sleep".into(), "5".into()], 1)
        .await;
    assert!(result.timed_out);
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
    assert!(
        second
            .error
            .as_deref()
            .is_some_and(|error| error.contains("busy") || error.contains("capacity")),
        "unexpected result: {second:?}"
    );
    let _ = running.await.unwrap();
}

#[tokio::test]
async fn executor_never_inherits_parent_environment() {
    let executor = Executor::new(config(vec![PathBuf::from("/usr/bin/env")])).unwrap();
    std::env::set_var("TETHERD_TEST_SECRET_DO_NOT_LEAK", "secret-value");
    let result = executor
        .execute(Uuid::new_v4(), vec!["/usr/bin/env".into()], 1)
        .await;
    std::env::remove_var("TETHERD_TEST_SECRET_DO_NOT_LEAK");
    assert_eq!(result.error, None);
    let output = String::from_utf8_lossy(&result.stdout);
    assert!(!output.contains("TETHERD_TEST_SECRET_DO_NOT_LEAK"));
    assert!(!output.contains("secret-value"));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn executor_drain_has_deadline_when_descendant_escapes_process_group() {
    let mut cfg = config(vec![PathBuf::from("/bin/sh")]);
    cfg.max_output_bytes = 4096;
    cfg.drain_grace_secs = 1;
    let executor = Executor::new(cfg).unwrap();
    let started = std::time::Instant::now();
    let result = executor
        .execute(
            Uuid::new_v4(),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "/usr/bin/setsid /bin/sh -c 'sleep 3' & exit 0".into(),
            ],
            2,
        )
        .await;
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert!(result.timed_out || result.error.is_some());
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
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("not allowlisted")),
        "unexpected result: {result:?}"
    );
}
