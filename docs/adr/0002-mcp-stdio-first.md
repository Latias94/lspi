# ADR 0002: Use MCP over stdio as the primary frontend

## Status

Accepted

## Context

The initial target clients are AI coding CLIs (e.g., Codex) that speak MCP and commonly launch tools as subprocesses over stdio.

## Decision

- Implement an MCP server frontend using stdio transport as the primary interface.
- Log to stderr; reserve stdout for protocol messages.
- Provide a CLI frontend later mainly for setup/doctor and debugging.

## Consequences

- Fast path to real-world usage with MCP clients.
- Requires careful separation of protocol output vs logs.
- CLI UX can be added without changing core semantics.

