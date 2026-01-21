# ADR 0004: Safe edits default to preview (no writes) unless explicitly applied

## Status

Accepted

## Context

Rename operations can modify many files. When driven by an LLM, accidental edits are a real risk. Users may also have local, uncommitted changes.

## Decision

- Rename tools default to **dry-run / preview**.
- Applying edits requires an explicit signal (e.g., `dry_run=false` or `apply=true`).
- Enforce workspace-root boundary for all writes.

## Consequences

- Safer default behavior for AI-driven refactors.
- Adds one extra step for users who want auto-apply.
- Requires a clear, consistent API surface across frontends.

