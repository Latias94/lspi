# ADR 0012: Strict apply uses a stateless hash handshake (no preview_id)

## Status

Accepted

## Context

Applying `WorkspaceEdit` results on disk can conflict with local changes between preview and apply. A robust solution should:

- detect drift between preview and apply
- avoid maintaining server-side state (e.g., `preview_id`) that can expire or be lost on restart
- remain compatible with MCP’s stateless tool calls

cclsp mitigates this with validation and backups; we want an optional stronger precondition for automation without adding state.

## Decision

### Stateless strict mode

For edit-producing tools (rename), `dry_run` responses SHOULD include:

- per-file `before_sha256` (computed from the exact file content used for preview)

When applying edits, callers MAY supply:

- `expected_before_sha256` (map: file path -> sha256)

If provided, `lspi` MUST:

- refuse to apply edits when any file hash mismatches
- return a structured error explaining which files mismatched

### Non-strict mode (default)

If `expected_before_sha256` is not provided:

- apply still performs range validation, atomic writes, backups, and rollback (ADR 0010)
- return a warning that strict preconditions were not enforced

### Rationale: no preview_id

We intentionally avoid a `preview_id`:

- it introduces hidden state and lifecycle issues (restart, cache eviction)
- it complicates concurrency and makes tool calls less reproducible

## Consequences

- Strong safety is available for automated workflows without keeping server state.
- Preview/apply remain compatible across restarts and multiple clients.
- Requires hashing file content and defining stable file path keys in results.

