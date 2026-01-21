# ADR 0003: Configuration uses TOML with explicit discovery order

## Status

Superseded by ADR 0008

## Context

`lspi` needs a stable way to configure:

- Which LSP servers to run (command/args)
- Which file extensions map to which server
- Workspace root directory
- Server-specific options and timeouts

The config must be easy for humans to edit and friendly to cross-platform environments.

## Decision

This ADR was superseded to support both TOML and JSON configuration formats.

## Consequences

- See ADR 0008.

