# tetherd

`tetherd` is a Unix-oriented Rust service for an authenticated outbound control link. An internal host (`tetherd join`) maintains an outbound TCP session to a public host (`tetherd daemon`), while local operators control the daemon through a mode-`0600` Unix domain socket (`tetherd ctl`).

The default control socket is `/run/tetherd/tetherd.sock`. The packaged systemd unit uses `RuntimeDirectory=tetherd`, so the unprivileged service owns only its runtime directory rather than all of `/run`.

## Security model

The peer protocol uses:

- ephemeral X25519 key agreement;
- HMAC-SHA256 PSK authentication;
- HKDF-SHA256 with protocol/version-bound transcript data;
- independent client→server and server→client keys;
- ChaCha20-Poly1305 authenticated encryption;
- monotonically increasing per-direction sequence numbers;
- all-zero X25519 shared-secret rejection.

After registration, TCP read and write halves are owned by dedicated tasks. The reader is never recreated inside a business `select!` loop, so partial `read_exact` progress cannot be lost through cancellation. Writes have hard deadlines and all inter-task queues are bounded.

`tetherd` is **not a raw remote shell**. Remote callers cannot choose executable paths. The join side exposes named `exec.commands.<id>` profiles:

```toml
[exec.commands.echo]
program = "/bin/echo"
allow_user_args = true
max_user_args = 8
max_user_arg_bytes = 4096

[exec.commands.uptime]
program = "/usr/bin/uptime"
allow_user_args = false
```

Each profile pins the canonical executable identity at startup, verifies executable/parent ownership and mutability on Unix, supports fixed arguments, and disables user-supplied arguments unless explicitly enabled. Legacy non-empty `exec.allow_exec` is rejected.

Child processes:

- never run through `sh -c`;
- receive no stdin;
- always start with an empty inherited environment;
- are admission-controlled before spawning;
- run with bounded concurrency and timeout;
- run in their own Unix process group;
- have bounded stdout/stderr capture;
- have a bounded post-exit pipe-drain grace period.

The PSK is never accepted inline in TOML. Configure exactly one of `auth.psk_file` or `auth.psk_env`. Unix PSK files are opened with `O_NOFOLLOW|O_CLOEXEC`, must be regular files owned by root or the service UID, and must not grant group/other access. Configuration files use the same single-descriptor pattern: open once with `O_NOFOLLOW|O_CLOEXEC`, validate that opened descriptor, then parse bytes from the same descriptor. This removes the validation/read pathname TOCTOU window.

## Build

Requirements: Rust 1.82+ on Linux or macOS.

```bash
cargo build --locked --release
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Quick start

Generate a 256-bit PSK:

```bash
install -d -m 700 /etc/tetherd
tetherd keygen | install -m 600 /dev/stdin /etc/tetherd/psk
cp tetherd.example.toml /etc/tetherd/tetherd.toml
chmod 600 /etc/tetherd/tetherd.toml
```

On Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml daemon
```

On Alice, point `join.server` at Bob and run:

```bash
tetherd --config /etc/tetherd/tetherd.toml join
```

On Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml ctl list
tetherd --config /etc/tetherd/tetherd.toml ctl exec \
  --credential pair \
  --command echo \
  -- hello
```

Use `--json` for machine-readable output.

## Configuration behavior

Configuration parsing is fail-closed with `deny_unknown_fields`. Misspelled security settings therefore fail startup instead of silently reverting to defaults.

Important defaults:

- daemon listener: `0.0.0.0:1234`
- control socket: `/run/tetherd/tetherd.sock`
- heartbeat: 60 seconds
- peer heartbeat timeout: 180 seconds
- handshake timeout: 10 seconds
- peer write timeout: 10 seconds
- connection ceiling: 128
- local control connection ceiling: 64
- global handshake ceiling: 600/minute
- per-IP handshake ceiling: 120/minute
- command timeout ceiling: 30 seconds
- output ceiling: 1 MiB per stdout/stderr stream
- command concurrency: 4
- pipe-drain grace period: 2 seconds

Join reconnects use capped exponential jitter. Authentication/protocol failures receive a substantially longer delay than transient network failures.

## Command output protocol

Remote command output is kept as raw bytes by the executor. It is split into 64 KiB chunks, Base64-encoded inside encrypted protocol messages, strictly sequenced, and independently bounded for stdout/stderr. The daemon aggregates only validated chunks. Local `ctl` decodes the final result and writes the original bytes directly to stdout/stderr.

Executor admission is held until the final result frame is accepted by the bounded outbound queue, so a slow writer cannot release execution capacity while completed multi-megabyte results accumulate in detached tasks. Command execution and result transport use separate deadlines: the remote command gets its configured runtime budget, then output chunks refresh a dedicated inactivity timer, with a separate absolute transfer ceiling.

Frame sizes are constrained by trust surface rather than one global maximum: handshake frames are limited to 4 KiB, authenticated peer frames to 256 KiB, local UDS requests to 512 KiB, and local UDS responses to 4 MiB.

This prevents a large single response frame from monopolizing the encrypted writer, bounds pre-decryption allocations, and preserves non-UTF-8 command output exactly.

## Protocol lifecycle

1. Client sends protocol version, ephemeral X25519 public key, and nonce.
2. Server replies with its ephemeral key/nonce and PSK-authenticated transcript tag.
3. Client validates the server and returns its transcript tag.
4. Both sides derive independent `c2s` and `s2c` keys using HKDF-SHA256.
5. Client registers credential/name over the encrypted channel.
6. Dedicated reader/writer actors handle encrypted heartbeats and command messages.
7. Command output is streamed as sequenced chunks followed by `exec_finished`.

The protocol version is currently `1`. Incompatible versions fail closed.

## Tests and CI

The suite covers:

- encryption round-trip, tamper and replay rejection;
- malformed authenticated payloads;
- oversized/truncated frames and trust-surface-specific frame ceilings;
- successful and wrong-PSK handshakes;
- fragmented encrypted frames spanning multiple watchdog ticks;
- PSK source, permission and symlink validation;
- fail-closed unknown configuration fields and resource ceilings;
- legacy raw executable-policy rejection;
- command-profile capability boundaries;
- no shell interpolation and no inherited secret environment;
- executor admission backpressure, including permit retention during result delivery;
- process timeout/process-group termination;
- bounded drain when descendants retain stdout/stderr;
- chunk ordering, aggregate output limits, and command/output inactivity deadline separation;
- binary output preservation end to end;
- stale-session isolation;
- peer outbound queue saturation;
- daemon → join → UDS → command-profile execution E2E.

CI runs on Linux and macOS with `rustfmt`, Clippy `-D warnings`, tests and release builds, plus Rust 1.82 MSRV and `cargo audit --deny warnings`. It also runs a scheduled weekly security validation. Third-party GitHub Actions are pinned to immutable commit SHAs.

## Release

Tag/dispatch release workflows rerun fmt, Clippy, tests, MSRV and RustSec before building artifacts. Release archives contain the binary, configuration example, security documentation, `Cargo.lock`, and Cargo dependency metadata. Archives receive SHA-256 files and GitHub build-provenance attestations before publication.

## systemd

Hardened units live in:

- `deploy/tetherd-daemon.service`
- `deploy/tetherd-join.service`

They include `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, empty capability sets, `PrivateDevices`, `LimitCORE=0`, `UMask=0077` and additional kernel/host hardening.

Run daemon and join as dedicated unprivileged users. Review sandbox settings if a command profile intentionally needs devices or other restricted system resources.

## Operational notes

- Authentication does not replace firewall/network policy.
- Keep command profiles narrow. Prefer dedicated wrapper binaries with fixed arguments over interpreters, shells, package managers, downloaders or general-purpose file readers.
- Do not place the UDS in a group/world-writable directory. The daemon validates its parent directory and connecting UID.
- A command in flight during disconnect has an unknown remote completion state; the daemon never fabricates a success/failure result.
- Reconnect cleanup is session-scoped, so a stale connection cannot clear state owned by its replacement.
- Repository branch/tag protection should require the CI jobs before merge/release; this is a repository-administration setting, not an application runtime feature.
