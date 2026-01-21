# ADR 0005: Normalize positions and use bounded fuzzing for robustness

## Status

Accepted

## Context

LLMs frequently provide incorrect line/column numbers due to:

- 0-based vs 1-based confusion
- UTF-16 vs Unicode scalar vs byte offset mismatch
- Off-by-one around whitespace, punctuation, or tabs

Naively passing positions to LSP leads to fragile tools and poor UX.

## Decision

- Treat incoming tool coordinates as **1-based** by default.
- Normalize to LSP coordinates internally (0-based, UTF-16 where required).
- When an operation fails, attempt a bounded set of nearby candidate positions and prefer results that return valid locations/edits.
- Emit warnings when fuzzing was used.

## Consequences

- Much more reliable UX for AI clients.
- Slightly more complexity and the need for careful bounds to avoid “random success”.
- Requires good test coverage around normalization behavior.

