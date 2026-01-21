# lspi Roadmap

This roadmap is written to keep scope clear and progress trackable. Items are grouped as milestones with acceptance criteria.

For a living status snapshot, see `docs/PROGRESS.md`.

## Milestone P0: Project Definition (Docs)

- Architecture document exists (`docs/ARCHITECTURE.md`)
- ADR process established (`docs/adr/`)
- Roadmap established (this document)

## Milestone P1: MVP (rust-analyzer + MCP)

### Scope

- MCP stdio server (works with Codex-style MCP clients)
- LSP backend supports `rust-analyzer`
- Tools (MVP):
  - `find_definition`
  - `find_references`
  - `rename_symbol`
  - `rename_symbol_strict`
  - `get_diagnostics`
  - `restart_server`
- Config loading + workspace root resolution
- Position normalization and bounded fuzzing
- Safe edit preview by default
- Structured MCP results via `structuredContent` (with text fallback)
- Snippet defaults and output caps (safe by default)

### Acceptance criteria

- Running `lspi` as an MCP server starts and responds to tool calls.
- On a Rust project:
  - definition and references return correct file+range for common symbols
  - rename returns a WorkspaceEdit preview and can apply edits when explicitly requested
  - diagnostics returns current errors/warnings for a file
- Server restart works without leaving orphan processes.

## Milestone P2: Stability & UX

- Better “first request” reliability (warmup/index wait strategy via adapter)
- Smarter symbol disambiguation and better candidate presentation
- Improved error messages (missing server, missing config, unsupported method)
- Add `doctor` / `setup` CLI helpers (optional)
- Add tests around edit application and position normalization
- Optional strict apply with per-file hashes (preview/apply handshake)

## Milestone P3: Generalized LSP Support

- Support multiple LSP server kinds via config (by extension + rootDir match)
- Add adapters for a few common servers (TBD)
- Multi-root workspace (nested repos / Cargo workspace specifics)

## Milestone P4: More Frontends

- CLI subcommands for local scripting (non-MCP)
- Optional HTTP server (only if needed by future clients)

## Milestone P5: Packaging & Distribution

- Release binaries (Windows/macOS/Linux)
- Versioning and changelog discipline
- Minimal docs for install + client configuration
