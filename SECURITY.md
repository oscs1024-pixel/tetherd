# Security policy

## Supported version

Only the latest `main` branch and the most recent release are supported.

## Reporting

Do not open public issues for vulnerabilities that expose authentication material, remote code execution, cryptographic bypasses, command-profile escapes, or control-socket authorization flaws. Use the repository owner's private security reporting channel when available.

## Required invariants

Changes must preserve these invariants:

1. PSKs, session keys, full command arguments, child environments, stdout, and stderr are never written to normal logs.
2. Remote execution is command-profile based; the peer cannot choose an executable path.
3. No shell is inserted by tetherd. Extra arguments are denied unless a command profile explicitly allows a bounded number of them.
4. Configured executables are canonicalized, root-owned on Unix, not group/world writable, located under root-owned non-writable parent directories, and pinned by filesystem identity.
5. Child environments are always cleared before explicit `exec.env` values are added. The PSK environment variable can never be exported to children.
6. Child stdin is closed; execution count, runtime, captured output, post-exit pipe draining, and process lifetime are bounded.
7. Child commands run in their own process group; timeout, task cancellation, and stuck output cleanup kill the group.
8. Authenticated transport reader/writer tasks own their socket half for the lifetime of a session. Business `select!` loops never cancel a partially consumed frame.
9. Every encrypted frame has strict sequence checking; tamper, replay, and out-of-order frames fail closed.
10. Handshake authentication is domain-separated by protocol version, role label, and algorithm suite.
11. X25519 all-zero shared secrets are rejected.
12. PSK/config loading rejects symlinks and validates ownership/permission bits on the opened descriptor.
13. The Unix control socket and parent directory are private, ownership-checked, and peer-UID checked.
14. Network, control, session, writer, executor, output, and handshake-rate resources have explicit bounds.
15. Reconnect cleanup is scoped to a unique session ID; stale sessions cannot clear replacement state.
16. Queue saturation returns a bounded busy/disconnect error instead of waiting indefinitely.
17. Authentication/protocol failures use long reconnect backoff; network failures use capped exponential full jitter.
18. GitHub Actions are pinned to immutable commit SHAs. CI and release builds deny RustSec vulnerabilities and informational warnings.
19. Release artifacts include checksums, a CycloneDX SBOM, and provenance attestation.

## Deployment guidance

- Use dedicated unprivileged accounts.
- Prefer a PSK file over a PSK environment variable.
- Keep command profiles narrowly scoped. Do not profile shells, interpreters, general-purpose file readers, or package managers unless their full capability is explicitly intended.
- Keep `/etc/tetherd` and the control-socket parent inaccessible to unrelated local users.
- Enforce host firewall/rate limiting in addition to tetherd's application-level handshake limits.
- Keep the provided systemd hardening unless a specific command profile requires a narrowly documented exception.
- Protect `main` and release tags with repository rules that require CI checks and disallow force pushes.
