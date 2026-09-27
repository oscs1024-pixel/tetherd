# Security policy

## Supported version

Only the latest `main` branch and the most recent release are supported.

## Reporting

Do not open public issues for vulnerabilities involving authentication material, remote code execution, cryptographic bypasses, control-socket authorization, command-profile escape, or supply-chain compromise. Use the repository owner's private security reporting channel when available.

## Security invariants

Changes must preserve these invariants:

1. PSKs, session keys, inherited environments, full command arguments, stdout and stderr are never written to service logs.
2. Remote execution never inserts a shell.
3. Remote callers select a configured command profile ID; they cannot choose an executable path.
4. Command-profile executables are canonicalized, identity-pinned, ownership-checked, and rejected when their path hierarchy is writable by untrusted/service identities.
5. User arguments are disabled by default and bounded when explicitly enabled.
6. Child processes always start with an empty inherited environment.
7. Command admission, peer queues, control connections, handshakes, frames, output, timeouts and pipe draining are resource-bounded.
8. Encrypted-frame sequence checking is strict; replay, reordering and AEAD tampering fail closed.
9. Post-registration socket reads are owned by a dedicated task so partial frame reads are never cancelled by business timers.
10. Socket writes have deadlines and writer failure tears down the session.
11. The handshake transcript binds protocol identity/version, and X25519 all-zero shared secrets are rejected.
12. PSK loading rejects symbolic links and validates the opened file descriptor's type, owner and mode.
13. Configuration loading opens once with `O_NOFOLLOW|O_CLOEXEC`, validates that same file descriptor, and parses from it; configuration parsing rejects unknown fields and unsafe ownership/write permissions.
14. Unix control sockets use mode `0600`, same-UID peer verification and trusted parent directories.
15. Reconnect cleanup is scoped to a unique session ID; stale sessions cannot remove replacement state.
16. Remote command output is binary-safe, chunked, strictly sequenced and bounded before aggregation.
17. Executor admission remains held through result enqueue, and command runtime deadlines are distinct from output-inactivity deadlines with an absolute transfer ceiling.
18. Frame limits are explicit per trust surface: handshake, authenticated peer, UDS request and UDS response.
19. Authentication/protocol failures are rate-limited/slow-backed off; public handshakes have global and per-IP rate ceilings.
20. CI must pass formatting, Clippy `-D warnings`, tests, release build, Rust 1.82 MSRV and `cargo audit --deny warnings`.
21. Third-party Actions are pinned to immutable commit SHAs.
22. Release artifacts are produced only after release-source verification and include provenance attestation.

## Deployment assumptions

The application cannot compensate for an operator intentionally granting an unsafe command profile. Do not configure general-purpose shells, interpreters, downloaders, package managers or unrestricted file-reading tools unless their full capability is explicitly intended.

Use a dedicated unprivileged service account, root/service-owned configuration and PSK files, firewall policy around the public listener, and repository branch/tag protection requiring CI before merge/release.
