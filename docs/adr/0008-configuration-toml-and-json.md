# ADR 0008: Support both TOML and JSON configuration with a single typed schema

## Status

Accepted

## Context

Different ecosystems have different expectations:

- Codex configuration is TOML-centric and can pass environment variables to MCP servers.
- cclsp uses a JSON configuration file and an env var (`CCLSP_CONFIG_PATH`) pattern.

For `lspi`, we want:

- a single typed configuration schema in Rust
- easy manual editing
- easy generation and interop across MCP clients

## Decision

- `lspi` supports configuration files in **TOML** and **JSON**, parsed into the same Rust structs.
- Discovery order (highest priority first):
  1) `--config <path>` (CLI arg; MCP launchers can pass it)
  2) `LSPI_CONFIG_PATH` environment variable
  3) `<workspace>/.lspi/config.toml` or `<workspace>/.lspi/config.json`
  4) `<workspace>/lspi.toml` or `<workspace>/lspi.json`
- If both TOML and JSON exist at the same discovery level, TOML wins (deterministic and Rust-native).
- The config MUST include:
  - `workspace_root` (optional; auto-discover if omitted)
  - server definitions (command/args, extensions, optional rootDir)
  - per-server timeouts and adapter options (optional)

## Consequences

- Users can reuse existing patterns from both Codex (TOML) and cclsp (JSON).
- We must keep the config schema stable and document it clearly.
- More parsing surface area; requires tests for both formats.

