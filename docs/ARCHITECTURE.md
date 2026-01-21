# lspi Architecture

## Summary

`lspi` is a Rust tool that bridges **Language Server Protocol (LSP)** capabilities to **AI coding CLIs** (starting with Codex) using an **MCP server frontend**.
The primary goal is to provide *IDE-like* symbol navigation and safe refactoring operations in an LLM-friendly, robust way.

## Goals

- Provide LLM-friendly tools for:
  - go-to-definition
  - find-references
  - rename (with preview / safe-apply)
  - diagnostics
  - server lifecycle (restart)
- Work reliably with imperfect positions from LLMs (line/column mismatches, 0/1-index confusion, UTF-16 vs Unicode).
- Support `rust-analyzer` first, then expand to more LSP servers.
- Be frontend-agnostic: MCP first, but keep the core reusable for future frontends.
- Be backend-agnostic: LSP first, leave room for alternative backends in the future.

## Non-goals (for MVP)

- Building a full IDE or language-specific semantic index outside LSP.
- Replacing language servers (we orchestrate them, not re-implement them).
- Remote multi-tenant service (initially local process, stdio).

## Layered Architecture

We split responsibilities into four layers:

1) **Frontends** (protocols / UI)
- MCP over stdio (primary)
- CLI (secondary; setup/doctor/debug)

2) **Core** (protocol- and backend-agnostic)
- Tool contracts (inputs/outputs) designed for LLMs
- Symbol resolution strategy (name+kind -> candidate positions -> LSP operations)
- Position normalization and fuzzing
- WorkspaceEdit preview and safe application
- Workspace boundary & safety policy

3) **Backends** (semantic providers)
- LSP backend (process management + JSON-RPC)
- Future: other sources (e.g., IDE plugin integration)

4) **Adapters** (per-server quirks)
- rust-analyzer tuning (init options, warmup waits, timeouts, capabilities)
- Generic LSP fallback behavior

## Proposed Workspace / Crate Layout

We will likely evolve into a Cargo workspace:

- `crates/lspi-core`: tool semantics, shared types, safety, edit application
- `crates/lspi-lsp`: LSP transport + server manager + document sync
- `crates/lspi-mcp`: MCP stdio server, tool exposure
- `crates/lspi-cli`: setup/doctor/config generation

For the first MVP we can start as a single crate with modules mirroring the structure above, and split into workspace crates once APIs stabilize.

## Data Flow (MCP -> LSP)

Example: `find_definition(file_path, symbol_name, symbol_kind?)`

1) MCP receives a tool call (stdin JSON).
2) Core resolves `file_path` to an absolute path, validates it stays within the workspace root.
3) Core finds candidate symbol positions:
   - use `textDocument/documentSymbol` (preferred when available)
   - fallback to `workspace/symbol` (if needed)
4) For each candidate position, core applies position normalization/fuzzing and calls LSP `textDocument/definition`.
5) Core normalizes results (URIs -> paths, ranges, optional snippets) and returns an LLM-friendly response.

## Tool Result Contract (MCP)

MCP tool call responses support both `content` (human-readable blocks) and `structuredContent` (machine-readable JSON).

`lspi` will:

- Treat `structuredContent` as the canonical payload for tool results (JSON).
- Include a short `content` text summary as a compatibility fallback.
- Enforce strict output caps (max results, max snippet size) to avoid large tool outputs.

See ADR 0007.

## LSP Backend Responsibilities

### Process & Lifecycle

- Start language server processes (stdio) based on config (command, args, rootDir).
- Initialize via `initialize` + `initialized`.
- Keep a per-server state:
  - initialized flag + init promise
  - open files set + version tracking
  - per-method timeouts
- Provide `restart` semantics (per extension or all).

### Document Synchronization Strategy (MVP)

To reduce “stale server state” issues caused by external edits (human or tooling), the MVP will prefer correctness over maximal performance:

- Before performing an LSP request requiring up-to-date content, ensure the file is opened.
- If already opened, re-read from disk and send a full-content `didChange` when content differs (version++).

Later we can optimize with file watching and incremental sync.

### Position Normalization & Fuzzing

LSP uses **0-based** line/character positions and typically counts characters as **UTF-16 code units**.
AI clients often provide:

- 1-based line/character
- “character” computed as Unicode scalar count or byte count
- off-by-one around whitespace or punctuation

We treat tool inputs as **1-based** by default (human/LLM-friendly), and normalize internally to LSP coordinates.
When the exact position fails, we try a bounded set of nearby candidates (line±N, character±M) and prefer results that produce valid locations.

## Configuration

`lspi` supports TOML and JSON configuration files parsed into a single typed schema.
This is designed to interoperate with TOML-centric clients (e.g., Codex config) while also supporting JSON-centric setups.

See ADR 0008.

## Safe Edit Application

Rename returns a `WorkspaceEdit` which may touch many files. Safety rules:

- Default behavior: **preview only** (`dry_run=true` by default).
- Apply edits only when explicitly requested (`apply=true` or `dry_run=false`, exact interface TBD).
- Enforce workspace-root boundary (never write outside).
- Apply per-file edits in descending range order; write atomically (temp file + rename) when possible.

See ADR 0010.

## rust-analyzer Adapter Notes

For `rust-analyzer`, `lspi` will enable and consume `experimental/serverStatus` notifications (when available) to improve the reliability of early requests by waiting (bounded) for quiescence.

See ADR 0009.

## Observability

- Protocol output goes to stdout (MCP), logs go to stderr.
- Use structured logging (`tracing`) with selectable verbosity.
- Include warnings in tool results when heuristics were used (e.g., “position fuzzing applied”).

## Open Questions / To Decide

- Multi-root workspace handling (Cargo workspace, nested projects).
- Caching strategy for symbols/diagnostics (speed vs staleness).

Snippet defaults and strict apply preconditions are defined in ADR 0011 and ADR 0012.
