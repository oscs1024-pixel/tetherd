use std::collections::HashMap;
use std::path::PathBuf;
use tetherd::config::{CommandProfile, ExecConfig};
use tetherd::join::executor::Executor;
use uuid::Uuid;

fn config(programs: Vec<(&str, PathBuf, bool)>) -> ExecConfig {
    let commands = programs
        .into_iter()
        .map(|(name, program, allow_user_args)| {
            (
                name.to_owned(),
                CommandProfile {
                    program,
                    fixed_args: Vec::new(),
                    allow_user_args,
                    max_user_args: 16,
                    max_user_arg_bytes: 16 * 1024,
                },
            )
        })
        .collect::<HashMap<_, _>>();
    ExecConfig {
        commands,
        allow_exec: Vec::new(),
        max_timeout_secs: 2,
        max_output_bytes: 32,
        max_concurrent: 2,
        work_dir: None,
        inherit_env: false,
        drain_grace_secs: 1,
    }
}

#[tokio::test]
async fn executor_denies_unknown_profile() {
    let executor = Executor::new(config(vec![("echo", PathBuf::from("/bin/echo"), true)])).unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "shell".into(),
            vec!["-c".into(), "true".into()],
            1,
        )
        .await;
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unknown command profile")),
        "unexpected result: {result:?}"
    );
}

#[tokio::test]
async fn executor_rejects_user_args_when_profile_does_not_allow_them() {
    let executor = Executor::new(config(vec![(
        "uptime",
        PathBuf::from("/usr/bin/uptime"),
        false,
    )]))
    .unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "uptime".into(),
            vec!["unexpected".into()],
            1,
        )
        .await;
    assert!(
        result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("does not accept user arguments")),
        "unexpected result: {result:?}"
    );
}

#[tokio::test]
async fn executor_runs_arguments_without_shell_interpretation() {
    let executor = Executor::new(config(vec![("echo", PathBuf::from("/bin/echo"), true)])).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), "echo".into(), vec!["hello;uname".into()], 1)
        .await;
    assert_eq!(result.error, None);
    assert_eq!(result.stdout, b"hello;uname\n");
}

#[tokio::test]
async fn executor_truncates_but_drains_output() {
    let executor = Executor::new(config(vec![(
        "printf",
        PathBuf::from("/usr/bin/printf"),
        true,
    )]))
    .unwrap();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "printf".into(),
            vec!["abcdefghijklmnopqrstuvwxyz0123456789".into()],
            1,
        )
        .await;
    assert_eq!(result.error, None);
    assert!(result.truncated);
    assert_eq!(result.stdout.len(), 32);
}

#[tokio::test]
async fn executor_kills_on_timeout() {
    let executor =
        Executor::new(config(vec![("sleep", PathBuf::from("/bin/sleep"), true)])).unwrap();
    let result = executor
        .execute(Uuid::new_v4(), "sleep".into(), vec!["5".into()], 1)
        .await;
    assert!(result.timed_out);
}

#[tokio::test]
async fn executor_returns_busy_instead_of_queueing_unbounded_work() {
    let mut cfg = config(vec![
        ("sleep", PathBuf::from("/bin/sleep"), true),
        ("echo", PathBuf::from("/bin/echo"), true),
    ]);
    cfg.max_concurrent = 1;
    let executor = Executor::new(cfg).unwrap();
    let running = {
        let executor = executor.clone();
        tokio::spawn(async move {
            executor
                .execute(Uuid::new_v4(), "sleep".into(), vec!["1".into()], 2)
                .await
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let second = executor
        .execute(Uuid::new_v4(), "echo".into(), vec!["busy".into()], 1)
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
    let executor =
        Executor::new(config(vec![("env", PathBuf::from("/usr/bin/env"), false)])).unwrap();
    std::env::set_var("TETHERD_TEST_SECRET_DO_NOT_LEAK", "secret-value");
    let result = executor
        .execute(Uuid::new_v4(), "env".into(), Vec::new(), 1)
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
    let mut cfg = config(vec![("shell", PathBuf::from("/bin/sh"), true)]);
    cfg.max_output_bytes = 4096;
    cfg.drain_grace_secs = 1;
    let executor = Executor::new(cfg).unwrap();
    let started = std::time::Instant::now();
    let result = executor
        .execute(
            Uuid::new_v4(),
            "shell".into(),
            vec![
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
async fn executor_pins_symlink_target_at_startup() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("tool");
    symlink("/bin/echo", &link).unwrap();
    let executor = Executor::new(config(vec![("tool", link.clone(), true)])).unwrap();
    std::fs::remove_file(&link).unwrap();
    symlink("/bin/sleep", &link).unwrap();

    let result = executor
        .execute(Uuid::new_v4(), "tool".into(), vec!["0".into()], 1)
        .await;
    assert_eq!(result.error, None);
    assert_eq!(result.stdout, b"0\n");
}
