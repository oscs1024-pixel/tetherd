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

#[test]
fn config_rejects_unknown_security_relevant_fields() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("max_concurrent = 4", "max_concurent = 4");
    // The fixture does not contain max_concurrent by default, so insert a typo.
    let raw = raw.replace("[exec]\n", "[exec]\nmax_concurent = 4\n");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_inherited_child_environment() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("[exec]\n", "[exec]\ninherit_env = true\n");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn config_rejects_resource_limits_above_safety_ceiling() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("config.toml");
    let raw = base_config("psk_env = \"TETHERD_TEST_PSK\"")
        .replace("[exec]\n", "[exec]\nmax_concurrent = 65\n");
    fs::write(&path, raw).unwrap();
    assert!(Config::load(&path).is_err());
}
