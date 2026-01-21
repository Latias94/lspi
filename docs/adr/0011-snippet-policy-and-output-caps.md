# ADR 0011: Snippet policy and output caps for MCP tools

## Status

Accepted

## Context

Tool responses can become very large, especially for workspace-wide operations like `find_references`. Large outputs are:

- expensive (tokens/time)
- harder for clients/LLMs to parse
- more likely to exceed client output limits

At the same time, short code snippets are very helpful for grounding results (e.g., for `find_definition`).

We also decided to prefer `structuredContent` for deterministic parsing (ADR 0007), so we need a consistent approach to including snippets and enforcing caps.

## Decision

### Defaults

- `find_definition`:
  - default `include_snippet=true`
  - default `snippet_context_lines=1` (1 line before/after)
- `find_references`:
  - default `include_snippet=false`

### Parameters (tool-level)

Tools that return lists of locations MUST support:

- `max_results` (default value TBD; hard max enforced by config)
- `include_snippet` (boolean)
- `snippet_context_lines` (integer; bounded)

### Output caps

- Each snippet is capped by:
  - `max_snippet_chars` (default ~400; hard max enforced by config)
- Each tool call is capped by:
  - `max_total_chars` (default TBD; enforced on both text and structured payload)

If a cap is hit:

- `structuredContent` MUST include:
  - `truncated=true`
  - `returned_results` and `total_estimate` when available
  - a warning explaining which cap was hit
- `content` MUST remain a short summary (no large dumps).

## Consequences

- `find_definition` stays convenient out of the box.
- `find_references` stays safe by default and avoids output explosions.
- Clients can opt in to snippets when needed, with predictable bounds.

