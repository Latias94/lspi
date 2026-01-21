# ADR 0010: Apply WorkspaceEdits safely (atomic writes, backups, and optional strict preconditions)

## Status

Accepted

## Context

Rename operations can touch many files. Risks:

- accidental edits triggered by an LLM
- applying edits on top of out-of-date local files (human edits between preview and apply)
- partial application leaving the workspace in a broken state

cclsp mitigates this with validation, backups, and atomic replace.

## Decision

- `lspi` MUST support `dry_run` preview for edits (default for rename tools).
- When applying edits, `lspi` MUST:
  - validate edit ranges against the current file content
  - apply edits per file in reverse order (bottom-to-top)
  - write atomically (temp file + rename)
  - optionally create backups (default enabled; suffix configurable)
  - rollback already-modified files on failure
- `lspi` SHOULD support an optional strict mode:
  - preview returns per-file content hashes
  - apply requires the caller to provide matching `expected_hashes`, otherwise abort

## Consequences

- Greatly reduced risk of corrupting a workspace during AI-driven refactors.
- Slightly more complexity and additional I/O.
- Strict mode enables “preview/apply handshake” for robust automation.

