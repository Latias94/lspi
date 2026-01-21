# ADR 0007: Prefer structuredContent for tool results (with bounded text fallback)

## Status

Accepted

## Context

MCP tool call results are typically returned as `content` blocks (often text), which is human-readable but not always ideal for:

- deterministic parsing by LLMs and other clients
- returning nested data (locations, edits) without fragile formatting

Codex's MCP implementation supports a first-class `structuredContent` field on tool results and prefers it when present.
Other MCP clients may ignore `structuredContent` and only display `content`.

We also need to keep tool outputs bounded to avoid token blowups, especially for operations like find-references.

## Decision

- `lspi` tool results MUST include:
  - `structuredContent` as the canonical machine-readable payload (JSON)
  - `content` as a short text summary and fallback for clients that ignore `structuredContent`
- The `structuredContent` payload MUST be size-bounded:
  - tools accept `max_results` (where applicable)
  - snippets are optional and strictly limited by configured caps
- When heuristics are used (position fuzzing, warmup waits, fallback methods), the result MUST include a `warnings` array in `structuredContent`.

## Consequences

- Codex and other clients that ingest `structuredContent` get deterministic, parseable results.
- Compatibility remains good for clients that only show text.
- We must design and version the JSON payload shape and enforce output caps.

