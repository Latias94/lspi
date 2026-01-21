# ADR 0001: Adopt a layered architecture (Frontends/Core/Backends/Adapters)

## Status

Accepted

## Context

`lspi` needs to:

- Expose IDE-like capabilities to AI CLIs (starting with MCP clients)
- Support `rust-analyzer` first but expand to more language servers later
- Remain robust against imperfect positions and ambiguous symbols from LLMs

If MCP and LSP logic are tightly coupled, future frontends/backends become expensive to add and risky to change.

## Decision

Adopt a layered architecture:

- **Frontends**: MCP stdio (primary) and CLI (secondary)
- **Core**: tool semantics, normalization, safety, edit application
- **Backends**: LSP backend (initial), future backends possible
- **Adapters**: server-specific quirks and tuning

Implementation may start as a single crate with modules and later split into a Cargo workspace with crates mirroring these layers.

## Consequences

- Clear separation of concerns; easier to extend beyond rust-analyzer and MCP.
- Slight upfront complexity in defining shared types and boundaries.
- Enables targeted testing of core logic without spawning real language servers.

