# tetherd

`tetherd` is a Unix-oriented Rust daemon for an authenticated outbound control link. An internal host (`tetherd join`) initiates and maintains a TCP connection to a public host (`tetherd daemon`), while local operators talk to the daemon through a mode-`0600` Unix domain socket (`tetherd ctl`). The packaged default is `/run/tetherd/tetherd.sock`.

The wire protocol is currently **version 2**. It uses ephemeral X25519 key agreement, HMAC-SHA256 PSK authentication, HKDF-SHA256 session-key derivation, and ChaCha20-Poly1305 authenticated encryption. The authenticated transcript includes the protocol version and algorithm suite. Client-to-server and server-to-client keys are separated, encrypted frames have strict monotonic sequence numbers, replay/out-of-order frames are rejected, and all-zero X25519 shared secrets fail closed.

## Security model

`tetherd` is **not a remote shell**.

Remote execution is based on **named command profiles**, not arbitrary executable paths. Each profile fixes an executable and optional fixed arguments. Extra arguments are rejected unless that profile explicitly enables them and sets a maximum count. The join side also:

- canonicalizes every configured executable at startup;
- requires the executable and all parent directories to be root-owned and not group/world writable on Unix;
- pins the executable `(dev, ino)` identity and rechecks it before each execution;
- invokes the program directly without `sh -c`;
- always starts children with an empty environment and adds only literal `exec.env` values;
- gives children no stdin;
- bounds concurrent commands, runtime, stdout/stderr capture, and post-exit pipe draining;
- runs each child in a separate process group and kills that group on timeout, disconnect, cancellation, or stuck output pipes.

The PSK is never accepted as inline TOML. Configure exactly one of `auth.psk_file` or `auth.psk_env`. On Unix, config and PSK files are opened with `O_NOFOLLOW`; their owner and permission bits are checked on the opened file descriptor. PSK files must not grant any group/other permissions. Config files must not be group/world writable.

The local control socket requires a private parent directory, mode `0600`, and the same effective UID on both ends.

## Build

Requirements: Rust 1.82+ on Linux or macOS.

```bash
cargo build --locked --release
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Quick start

Create a dedicated service account and protected configuration directory. The PSK file must be readable by the account running tetherd and must be owned by root or that account.

```bash
sudo install -d -o tetherd -g tetherd -m 700 /etc/tetherd
tetherd keygen | sudo install -o tetherd -g tetherd -m 600 /dev/stdin /etc/tetherd/psk
sudo install -o tetherd -g tetherd -m 600 tetherd.example.toml /etc/tetherd/tetherd.toml
```

On Bob (public host):

```bash
tetherd --config /etc/tetherd/tetherd.toml daemon
```

On Alice (internal host), use the same credential/PSK and point `join.server` at Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml join
```

On Bob:

```bash
tetherd --config /etc/tetherd/tetherd.toml ctl list
tetherd --config /etc/tetherd/tetherd.toml \
  ctl exec --credential pair --command echo -- hello
tetherd --config /etc/tetherd/tetherd.toml \
  ctl exec --credential pair --command uptime
```

Use `--json` with `ctl list` or `ctl exec` for machine-readable responses.

## Command profiles

Example:

```toml
[exec]
max_timeout_secs = 30
max_output_bytes = 1048576
max_concurrent = 4
output_drain_timeout_secs = 2

[exec.env]
LANG = "C"

[exec.commands.echo]
program = "/bin/echo"
allow_extra_args = true
max_extra_args = 8
timeout_secs = 5

[exec.commands.uptime]
program = "/usr/bin/uptime"
allow_extra_args = false
max_extra_args = 0
timeout_secs = 5
```

Prefer small purpose-built wrapper binaries with fixed arguments. Do not expose shells, language interpreters, general-purpose file readers, package managers, or other tools whose argument language effectively recreates arbitrary code/file access.

## Resource limits and connection behavior

Important defaults:

- daemon TCP listener: `0.0.0.0:1234`
- control socket: `/run/tetherd/tetherd.sock`
- heartbeat interval: 60 seconds
- heartbeat timeout: 180 seconds
- handshake timeout: 10 seconds
- encrypted write timeout: 10 seconds
- reconnect base: 5 seconds
- reconnect cap: 300 seconds
- authentication/protocol failure backoff: 60 seconds
- command timeout ceiling: 30 seconds
- stdout/stderr ceiling: 1 MiB per stream
- post-exit output drain ceiling: 2 seconds
- concurrent commands: 4
- TCP connection ceiling: 128
- local control connection ceiling: 64
- handshake ceiling: 1200/minute globally, 120/minute per source IP

Network reconnects use capped exponential full jitter. Authentication/protocol errors use the longer configured failure backoff.

## Connection architecture

After the authenticated registration phase, each TCP connection has independent reader and writer tasks:

```text
TCP read half -> dedicated frame reader -> bounded message queue -> session actor
session actor -> bounded message queue -> dedicated writer + deadline -> TCP write half
```

The frame reader exclusively owns the read half and receive cipher. Business timers, heartbeat events, control requests, and session cancellation therefore cannot cancel a partially consumed `read_exact` and corrupt frame boundaries.

Both directions are bounded. A saturated outbound queue returns a busy/disconnect condition instead of waiting indefinitely.

## Protocol lifecycle

1. Client sends protocol version, ephemeral X25519 public key, and nonce.
2. Server replies with its ephemeral key/nonce and PSK-authenticated transcript tag.
3. Client validates the server and returns its own transcript tag.
4. Both sides derive independent `c2s` and `s2c` keys using HKDF-SHA256.
5. The client registers its credential/name over the encrypted channel.
6. Heartbeats and command profile request/response frames use ChaCha20-Poly1305 with direction-separated nonces and strict sequence checking.

Version 2 intentionally fails closed against older version-1 peers.

## Tests and security automation

The suite includes:

- AEAD round-trip, tamper, replay, and wrong-PSK tests;
- all-zero X25519 shared-secret rejection;
- fragmented TCP frame regression under bidirectional traffic;
- PSK/config permission and symlink validation;
- unknown/oversized config rejection;
- command-profile argument policy;
- child environment isolation;
- executable identity and trusted-path checks;
- output truncation and stuck-pipe drain timeout;
- process-group timeout cleanup;
- executor and peer queue backpressure;
- reconnect session isolation;
- handshake rate limiting;
- daemon → join → UDS ctl → command-profile E2E.

CI runs format, strict Clippy, tests, documentation tests, release builds on Linux/macOS, Rust 1.82 MSRV, and RustSec with warnings denied. A scheduled fuzz workflow exercises encrypted frame parsing and protocol JSON.

## Releases

Tag releases repeat the quality, MSRV, and RustSec gates before building. Linux/macOS artifacts include:

- release binary;
- example config and security documentation;
- SHA-256 checksum;
- CycloneDX JSON SBOM;
- GitHub build provenance attestation.

GitHub Actions are pinned to immutable commit SHAs.

## systemd

Hardened example units are in `deploy/tetherd-daemon.service` and `deploy/tetherd-join.service`. They add, among other controls:

- `NoNewPrivileges=yes`;
- empty capability bounding/ambient sets;
- `LimitCORE=0`;
- `UMask=0077`;
- `PrivateTmp` and `PrivateDevices`;
- kernel/system protection options;
- namespace/address-family restrictions;
- `KillMode=control-group`;
- strict filesystem protection.

Review the sandbox against the exact command profiles you enable. If a command legitimately needs additional filesystem/device access, grant the smallest specific exception instead of weakening the entire unit.

## Operational notes

- Firewall the public TCP port even though the protocol authenticates peers.
- Keep command profiles narrow; configuration is part of the security boundary.
- Prefer `psk_file` over `psk_env` for managed services.
- Run daemon and join under dedicated unprivileged accounts.
- Protect `/etc/tetherd` and the control-socket parent from other local users.
- A command in flight when a peer disconnects is reported as unknown/failed; tetherd does not guess whether it completed remotely.
- Reconnect cleanup is scoped to a unique session ID, so stale connections cannot invalidate the replacement session.
