use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use tetherd::config::Config;

fn base_config(psk_line: &str) -> String {
    format!(
        r#"
[auth]
credential = "pair"
{psk_line}

[daemon]
listen = "127.0.0.1:1234"
control_socket = "/tmp/tetherd-test.sock"

[join]
server = "127.0.0.1:1234"
heartbeat_secs = 1
heartbeat_timeout_secs = 3
reconnect_secs = 1

[exec]
allow_exec = ["/bin/echo"]
"#
    )
}

#[test]
fn config_requires_exactly_one_psk_source() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, base_config("")).unwrap();
    assert!(Config::load(&path).is_err());

    fs::write(
        &path,
        base_config("psk_file = \"/tmp/key\"\npsk_env = \"TETHERD_PSK\""),
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_unknown_fields() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("allow_exec = [\"/bin/echo\"]", "allow_exec = [\"/bin/echo\"]\ninherit_env = true");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_excessive_resource_limits() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("control_socket = \"/tmp/tetherd-test.sock\"", "control_socket = \"/tmp/tetherd-test.sock\"\nmax_connections = 999999");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_file_rejects_group_or_world_write() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    fs::write(&path, base_config("psk_env = \"TETHERD_TEST_PSK\"")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn secret_file_rejects_group_or_other_access() {
    let dir = tempdir().unwrap();
    let psk = dir.path().join("psk");
    fs::write(&psk, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    fs::set_permissions(&psk, fs::Permissions::from_mode(0o644)).unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, base_config(&format!("psk_file = {:?}", psk))).unwrap();
    let config = Config::load(&config_path).unwrap();
    assert!(config.auth.load_psk().is_err());
}

#[cfg(unix)]
#[test]
fn secret_file_rejects_symlink() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let target = dir.path().join("real-psk");
    fs::write(&target, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("psk");
    symlink(&target, &link).unwrap();
    let config_path = dir.path().join("config.toml");
    fs::write(&config_path, base_config(&format!("psk_file = {:?}", link))).unwrap();
    let config = Config::load(&config_path).unwrap();
    assert!(config.auth.load_psk().is_err());
}

#[test]
fn config_rejects_psk_env_export_to_child() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"").replace(
        "allow_exec = [\"/bin/echo\"]",
        "allow_exec = [\"/bin/echo\"]\n[exec.env]\nTETHERD_TEST_PSK = \"must-not-leak\"",
    );
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_log_injection_identifiers() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("credential = \"pair\"", "credential = \"pair\\nforged\"");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_relative_control_socket() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("/tmp/tetherd-test.sock", "relative.sock");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}
