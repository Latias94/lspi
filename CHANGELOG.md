# Changelog

All notable changes to this project will be documented in this file.

This project follows a lightweight variant of "Keep a Changelog". Versions use semantic versioning where practical.

## [0.2.0] - Unreleased

### Fixed

- LSP client: avoid leaking pending requests when a request write fails or times out.
- LSP client: omit `params` for `shutdown`/`exit` when params is null (improves compatibility with strict servers).
- LSP client: send `$/cancelRequest` when a request times out (reduces wasted server work and follow-up latency).
- TS/Vue adapter: respond `null` to `tsserver/request` bridge calls (avoids hangs/crashes when no editor tsserver bridge is available).
- MCP: harden backup file path generation to prevent path traversal via `backup_suffix`.
- MCP: allow reads/writes within configured `servers[].workspace_folders` (multi-root workspaces) instead of limiting strictly to `workspace_root`.

### Changed

- MCP tool schemas: add clearer descriptions and default/maximum hints for common parameters (`max_results`, snippet controls).
- MCP internals: split large modules into smaller files for maintainability (no behavior change intended).
- MCP: convert tool handler failures into structured tool errors with actionable `next_steps` hints (instead of protocol-level MCP errors).
- LSP client: reply to common server-initiated requests (`workspace/configuration`, `workspace/workspaceFolders`, etc.) to improve generic LSP compatibility.
- LSP transport: send `Content-Type` header, accept case-insensitive `Content-Length`, and cap maximum frame size.
- `lspi doctor`: add Pyright preflight hints (`kind=pyright|basedpyright`).
- Build: relax dependency version specifiers and upgrade `rmcp` to `0.13`.
- Repo hygiene: ignore IntelliJ project files (`.idea/`, `*.iml`).
- Docs: improve MCP-first documentation (README FAQ/troubleshooting, minimal config example, and upstream inspirations).
- MCP: when multiple servers are configured, `search_workspace_symbols` returns a disambiguation payload (instead of a hard error) so clients can pick a server by providing `file_path`.
- MCP: standardize `structuredContent` tool responses with a versioned `schema_version` field and consistent common fields (`input`/`warnings`/`truncated`).
- TS/Vue adapter: apply sensible default per-method request timeouts for slow operations (overridable via `servers[].request_timeout_overrides_ms`).

### Added

- Server config: `servers[].workspace_configuration` for customizing responses to `workspace/configuration` requests (useful for TypeScript formatting options, etc.).
- Server config: `servers[].request_timeout_overrides_ms` for per-method request timeouts (useful for slow workspace-wide operations).
- Server config: `servers[].initialize_options` / `servers[].client_capabilities` for customizing LSP `initialize` payloads (helps generic servers that require non-default options/capabilities).
- Server config: `servers[].workspace_folders` for including additional `workspaceFolders` in LSP `initialize` (multi-root workspaces).
- Server config: `servers[].cwd` / `servers[].env` for setting the LSP process working directory and environment variables.
- Server config: `servers[].adapter` for server-specific quirks (initially: `tsserver` for TypeScript/Vue tooling).
- Server kind: `pyright` / `basedpyright` (auto-resolves commands, applies sensible default per-method timeouts).
- MCP: read-only mode via `mcp.read_only=true` or `lspi mcp --read-only`.
- MCP: `mcp.context` preset (and `lspi mcp --context`) for client-oriented defaults (e.g. Codex-safe read-only + smaller output).
- CLI: `lspi mcp --mode navigation|refactor` convenience presets (sugar for context + read-only/read-write defaults).
- MCP: introspection tools (`get_current_config`, `list_servers`, `get_server_status`) for debugging routing and server health.

## [0.1.0] - 2026-01-22

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
  - `scripts/mcp_smoke_python.ps1` (Python via generic LSP, best-effort; skips if prerequisites missing)
  - `scripts/mcp_smoke_lua.ps1` (Lua via generic LSP, best-effort; skips if prerequisites missing)
  - `scripts/mcp_smoke_cpp.ps1` (C++ via generic LSP, best-effort; skips if prerequisites missing)
  - minimal C# sample project under `samples/csharp/Hello/`
  - minimal TypeScript sample project under `samples/typescript/Hello/`
  - minimal Go sample project under `samples/go/Hello/`
  - minimal Python sample project under `samples/python/Hello/`
  - minimal Lua sample project under `samples/lua/Hello/`
  - minimal C++ sample project under `samples/cpp/Hello/`

### Changed

- `get_diagnostics` prefers pull-based `textDocument/diagnostic` when supported, and falls back to publishDiagnostics cache.

### Known limitations

- Only `rust_analyzer`, `omnisharp`, and `generic` server kinds are supported in 0.1.0.
- For `kind = "generic"`, `command` is required (no auto-resolve); `language_id` is recommended for reliable `didOpen`.
- Binaries are not distributed yet; installation is via `cargo install --path ...`.
- C# integration depends on the local OmniSharp installation and can vary by environment.
