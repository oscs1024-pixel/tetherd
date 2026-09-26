# Security policy

## Supported version

Only the latest `main` branch and the most recent release are supported.

## Reporting

Do not open public issues for vulnerabilities that expose authentication material, remote code execution, cryptographic bypasses, or control-socket authorization flaws. Use the repository owner's private security reporting channel when available.

## Invariants

Changes must preserve these invariants:

1. No plaintext PSK/session-key logging.
2. No shell insertion for remote execution.
3. Absolute-path executable allowlist enforcement on the join side.
4. Strict encrypted-frame sequence checking.
5. Authenticated handshake transcript before accepting registration.
6. Bounded frame, output, timeout, and concurrency resources.
7. Unix control socket mode `0600` plus same-UID peer verification.
8. Authentication/protocol failures fail closed.
9. X25519 all-zero shared secrets are rejected.
10. PSK file loading rejects symlinks and checks permissions on the opened file descriptor.
11. Reconnect cleanup is scoped to a unique session ID; stale sessions cannot clear replacement state.
12. Executor saturation returns a bounded busy error instead of accumulating an unbounded task queue.
