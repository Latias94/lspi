# ADR 0009: rust-analyzer adapter uses server status notifications for warmup and bounded waiting

## Status

Accepted

## Context

Language servers often need background time to index a workspace. Early requests can yield incomplete results (notably workspace-wide operations like references/rename/diagnostics).

rust-analyzer provides an extension:

- `experimental/serverStatus` notification (enabled via experimental client capability `serverStatusNotification`)
  - includes `quiescent: boolean` and `health: ok|warning|error`

This gives a more principled signal than a fixed sleep.

## Decision

- The rust-analyzer adapter MUST request `serverStatusNotification` capability during initialization.
- For operations that benefit from a “ready” server (references, rename, diagnostics), `lspi` SHOULD:
  - wait for `quiescent=true` with an upper bound (`warmup_timeout_ms`, default TBD)
  - proceed with a warning if the timeout elapses
- All LSP requests MUST have method-level timeouts (adapter-configurable).
- If the server does not support server status notifications, fall back to a small fixed delay after opening/syncing a document.

## Consequences

- More reliable early calls in rust-analyzer workspaces.
- Requires asynchronous notification handling and a per-server status cache.
- “Perfect readiness” is not guaranteed; we still need output warnings and bounded retries.

