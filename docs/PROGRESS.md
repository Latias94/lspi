# lspi Progress

This document tracks what is implemented vs planned, in a lightweight, append-only way.

## Current Focus

- Reach Milestone P1 parity for Rust projects (rust-analyzer + MCP).
- Prioritize reliability: position robustness, safe edits, predictable outputs.

## Status (2026-01-21)

### Implemented

- Cargo workspace layout (`crates/lspi`, `crates/lspi-mcp`, `crates/lspi-lsp`, `crates/lspi-core`)
- Basic user docs: `README.md`, `docs/CONFIG.md`
- Manual smoke test doc: `docs/SMOKE_TEST.md`
- Smoke test helper script: `scripts/mcp_smoke.ps1`
- TypeScript smoke test helper script: `scripts/mcp_smoke_ts.ps1` (generic LSP)
- Go smoke test helper script: `scripts/mcp_smoke_go.ps1` (generic LSP)
- Python smoke test helper script: `scripts/mcp_smoke_python.ps1` (generic LSP)
- Lua smoke test helper script: `scripts/mcp_smoke_lua.ps1` (generic LSP)
- Codex integration doc: `docs/CODEX.md`
- MCP stdio server entrypoint (`lspi mcp`)
- Windows smoke test: `scripts/mcp_smoke.ps1` passes with rust-analyzer 1.92.0 (2025-12-08)
- CLI helper: `lspi doctor` (checks config discovery and rust-analyzer availability)
- CLI helper: `lspi setup` (prints/writes starter `.lspi/config.toml`)
- Config loading (ADR 0008):
  - TOML/JSON supported with discovery order (CLI `--config`, `LSPI_CONFIG_PATH`, workspace files)
  - CLI supports `lspi mcp --config ... --workspace-root ...`
  - `servers[]` schema supported
  - if `servers` is omitted or empty, a default Rust server is assumed
- Multi-server routing by extension/rootDir (ADR 0006) for configured servers (multiple instances supported)
- LSP stdio JSON-RPC transport (minimal)
- LSP client capabilities:
  - requests hierarchical document symbols (improves selectionRange for name-based tools)
- Generic LSP integration:
  - `generic` stdio adapter with on-demand `didOpen`/`didChange` sync (full-content)
- rust-analyzer integration:
  - initialize + `experimental/serverStatus` notification handling (bounded warmup)
  - didOpen/didChange sync (full-content)
  - retries for document symbols / definition / references (reduces first-call flakiness)
- MCP tools:
  - `find_definition` (by name, using document symbols + definition)
  - `find_definition_at` (by position, with bounded position fuzzing)
  - `find_references` (by name, using document symbols + references; bounded max results)
  - `find_references_at` (by position, with bounded position fuzzing)
  - `hover_at` (by position, with bounded position fuzzing)
  - `find_implementation_at` (by position, with bounded position fuzzing; best-effort if not supported)
  - `find_type_definition_at` (by position, with bounded position fuzzing; best-effort if not supported)
  - `find_incoming_calls_at` (by position, with bounded position fuzzing; best-effort if not supported)
  - `find_outgoing_calls_at` (by position, with bounded position fuzzing; best-effort if not supported)
  - `find_incoming_calls` / `find_outgoing_calls` (by name; returns candidates when ambiguous)
  - `get_document_symbols` (flat list; includes 1-based ranges)
  - `search_workspace_symbols` (workspace-wide symbol search; requires disambiguation when multiple servers are configured)
  - `get_diagnostics` (from publishDiagnostics cache; best-effort wait)
  - `rename_symbol` (preview, and apply when `dry_run=false`)
  - `rename_symbol_strict` (position fuzzing + preview/apply)
  - `restart_server` (per configured server by extension match)
  - `stop_server` (stop language servers; respects lifecycle policies)
- Safe edit application (current state):
  - optional `expected_before_sha256` precondition
  - backups (suffix configurable)
  - best-effort atomic replace (temp file + rename fallback)
  - rollback on failure
- Position fuzzing (current state):
  - implemented in `lspi-core` and wired into `rename_symbol_strict`
- Tool UX (current state):
  - name-based tools include 1-based positions and document path/URI to help disambiguation
  - `rename_symbol` includes candidate snippets when disambiguation is required
- Snippet defaults (ADR 0011, current state):
  - `find_definition` supports snippets by default (bounded by `max_snippet_chars`)
  - `find_references` supports optional snippets (off by default)
- Output caps (ADR 0011, current state):
  - tools support `max_total_chars` and will drop snippets / truncate arrays to satisfy the cap
  - `max_total_chars` policy supports config-driven defaults/hard caps via `mcp.output.*`
- Tests (current state):
  - core: position fuzzing, UTF-16 edit application, snippet truncation
  - mcp: workspace boundary canonicalization, output caps behavior

### Partially implemented / needs refinement

- Output caps + snippet policy (ADR 0011):
  - consider config-driven defaults/hard caps and more deterministic truncation ordering
- Position fuzzing coverage:
  - applied to `rename_symbol_strict`; other tools may need strict variants or shared logic
- Restart semantics:
  - supports restarting multiple server instances (rust_analyzer, omnisharp)
- C# (current state):
  - `omnisharp` adapter supported (LSP mode via `-lsp`), routed by `extensions=["cs"]`
- Diagnostics (current state):
  - `get_diagnostics` tries `textDocument/diagnostic` (pull) when supported, falls back to publishDiagnostics cache

### Not implemented yet

- Tests for safe edit apply (backup/rollback/hash preconditions) and rename behavior (end-to-end integration)
