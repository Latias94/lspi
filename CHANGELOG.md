# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight variant of "Keep a Changelog". Versions use semantic versioning where practical.

## [0.1.0] - Unreleased

Initial 0.1.0 milestone of `lspi` (Rust workspace), providing an MCP stdio server that bridges LSP features for AI coding CLIs (starting with Codex).

### Added

- MCP stdio server (`lspi mcp`) with structured `structuredContent` responses.
- Generic stdio LSP adapter (`kind = "generic"`) for any LSP server that speaks JSON-RPC over stdio.
- Core MCP tools:
  - `find_definition` / `find_definition_at`
  - `find_references` / `find_references_at`
  - `hover_at`
  - `find_implementation_at`
  - `find_type_definition_at`
  - `find_incoming_calls_at`
  - `find_outgoing_calls_at`
  - `find_incoming_calls`
  - `find_outgoing_calls`
  - `get_document_symbols`
  - `search_workspace_symbols`
  - `rename_symbol` / `rename_symbol_strict`
  - `get_diagnostics`
  - `restart_server`
  - `stop_server`
- Rust support via `rust-analyzer` adapter:
  - bounded warmup using `experimental/serverStatus` (best-effort)
  - retries for first-call flakiness (document symbols / definition / references)
- Early C# support via OmniSharp adapter (`omnisharp -lsp`).
- Multi-server configuration and routing (ADR 0006):
  - `[[servers]]` supports `extensions` + optional `root_dir` with longest-match tie-breaker
  - if `servers` is omitted or empty, a default Rust server is assumed (`extensions=["rs"]`)
- Safety-first edit application:
  - rename defaults to preview (`dry_run=true`)
  - optional `expected_before_sha256` precondition
  - backups and best-effort rollback
  - workspace-root boundary enforcement for writes
- Output caps and snippet policy to prevent oversized tool responses (`max_total_chars`).
- CLI helpers:
  - `lspi doctor` for environment/config checks (with install hints)
  - `lspi setup` for generating `.lspi/config.toml` (including `--wizard` best-effort detection)
- Docs:
  - architecture + ADRs
  - configuration schema
  - Codex integration guide
  - smoke test guides
- Validation helpers:
  - `scripts/mcp_smoke.ps1` (Rust)
  - `scripts/mcp_smoke_csharp.ps1` (C#, best-effort; skips if prerequisites missing)
  - `scripts/mcp_smoke_ts.ps1` (TypeScript via generic LSP, best-effort; skips if prerequisites missing)
  - `scripts/mcp_smoke_go.ps1` (Go via generic LSP, best-effort; skips if prerequisites missing)
  - minimal C# sample project under `samples/csharp/Hello/`
  - minimal TypeScript sample project under `samples/typescript/Hello/`
  - minimal Go sample project under `samples/go/Hello/`

### Changed

- `get_diagnostics` prefers pull-based `textDocument/diagnostic` when supported, and falls back to publishDiagnostics cache.

### Known limitations

- Only `rust_analyzer`, `omnisharp`, and `generic` server kinds are supported in 0.1.0.
- For `kind = "generic"`, `command` is required (no auto-resolve); `language_id` is recommended for reliable `didOpen`.
- Binaries are not distributed yet; installation is via `cargo install --path ...`.
- C# integration depends on the local OmniSharp installation and can vary by environment.
