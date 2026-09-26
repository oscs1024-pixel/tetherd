# tetherd

`tetherd` is a Unix-oriented Rust daemon for an authenticated outbound control link: an internal host (`tetherd join`) initiates and maintains a TCP connection to a public host (`tetherd daemon`), while local operators talk to the daemon through a mode-`0600` Unix domain socket (`tetherd ctl`). The packaged default is `/run/tetherd/tetherd.sock`, so an unprivileged systemd service can own its runtime directory without needing write access to `/run` itself.

The protocol uses ephemeral X25519 key agreement, HMAC-SHA256 PSK authentication, HKDF-SHA256 session-key derivation, and ChaCha20-Poly1305 authenticated encryption. Client-to-server and server-to-client keys are separated, every encrypted frame carries a monotonically increasing sequence number, replay/out-of-order frames are rejected, and all-zero X25519 shared secrets are rejected.

## Security model

`tetherd` is **not a remote shell**. `ctl exec` sends an argv vector and the join side invokes the executable directly without `sh -c`. The executable must be an absolute path explicitly present in `exec.allow_exec`. The child receives no stdin, inherits no environment by default, has a bounded concurrency limit, a hard timeout, and bounded captured stdout/stderr. Output beyond the configured limit is discarded while the pipes continue to be drained to avoid deadlocks.

The PSK is never accepted as an inline TOML value. Configure exactly one of `auth.psk_file` or `auth.psk_env`; PSK files must not grant group/other permissions on Unix and are opened with `O_NOFOLLOW` to reject symlink substitution. Logs intentionally avoid PSKs, session keys, environment values, and full command lines.

## Build

Requirements: Rust 1.82+ on Linux or macOS.

```bash
cargo build --release
cargo test --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

## Quick start

Generate a 256-bit PSK and install it with owner-only permissions:

```bash
install -d -m 700 /etc/tetherd
tetherd keygen | install -m 600 /dev/stdin /etc/tetherd/psk
cp tetherd.example.toml /etc/tetherd/tetherd.toml
```

On Bob (public host):

```bash
tetherd --config /etc/tetherd/tetherd.toml daemon
```

On Alice (internal host), use a config with the same credential/PSK and `join.server` pointing at Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml join
```

On Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml ctl list
tetherd --config /etc/tetherd/tetherd.toml ctl exec --credential pair -- /bin/echo hello
```

Use `--json` with `ctl list` or `ctl exec` for machine-readable responses.

## Configuration

See [`tetherd.example.toml`](tetherd.example.toml). Important defaults:

- daemon TCP listener: `0.0.0.0:1234`
- local control socket: `/run/tetherd/tetherd.sock`
- join heartbeat: 60 seconds
- heartbeat timeout: 180 seconds
- reconnect base delay: 5 seconds with ±20% jitter
- command timeout ceiling: 30 seconds
- output ceiling: 1 MiB per stdout/stderr stream
- concurrent commands: 4
- unauthenticated/authenticated TCP connection ceiling: 128
- handshake/registration timeout: 10 seconds
- local control request timeout: 5 seconds
- local control connection ceiling: 64

CLI log settings override environment/config. `NO_COLOR` disables level coloring and `FORCE_COLOR` enables it. Logs are written to stderr in `YYYY-MM-DD HH:MM:SS [LEVEL] message` form.

## Protocol lifecycle

1. Client sends protocol version, ephemeral X25519 public key, and nonce.
2. Server replies with its ephemeral key/nonce and a PSK-authenticated transcript tag.
3. Client validates the server and returns its own transcript tag.
4. Both sides derive independent `c2s` and `s2c` keys using HKDF-SHA256.
5. The client registers its credential/name over the encrypted channel.
6. Heartbeats and command request/response frames use ChaCha20-Poly1305 with direction-separated nonces and strict sequence checking.

The protocol version is currently `1`. Incompatible versions fail closed.

## Tests

The automated suite covers:

- encryption round-trip, tamper detection, and replay rejection;
- successful and wrong-PSK handshakes;
- PSK source/permission/symlink validation;
- executable allowlist denial and canonical-path pinning;
- argv execution without shell interpolation;
- output truncation while draining pipes;
- child timeout/process-group termination and executor backpressure;
- reconnect session isolation (stale sessions cannot remove replacement state);
- daemon → join → UDS ctl → exec end-to-end behavior.

GitHub Actions runs formatting, Clippy with `-D warnings`, all tests, release builds on Linux/macOS, an MSRV check, and RustSec dependency audit. Dependabot is enabled for Cargo and Actions updates.

## systemd

Hardened example units are provided in `deploy/tetherd-daemon.service` and `deploy/tetherd-join.service`. Install the binary/config first, create a dedicated `tetherd` service account, then enable the appropriate unit. Adjust `ReadWritePaths`, network policy, and the command allowlist for the deployment.

## Operational notes

- Bind the public TCP port only on interfaces/firewalls that need it. Authentication does not replace network policy.
- Treat the allowlist as privileged configuration. Prefer narrow wrapper executables over general-purpose interpreters or shells.
- Run `daemon` and `join` as dedicated unprivileged service users whenever possible.
- Do not expose the Unix control socket through a shared directory; its mode is forced to `0600`, and the daemon verifies the connecting UID.
- A command in flight when the peer disconnects is reported as timeout/disconnect; the daemon does not guess whether it completed remotely. Reconnects are session-scoped so stale-session cleanup cannot invalidate requests belonging to the replacement connection.
