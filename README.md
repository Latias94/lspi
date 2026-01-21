# lspi

`lspi` bridges **Language Server Protocol (LSP)** capabilities to **AI coding CLIs** (starting with Codex) via an **MCP server** over stdio.

Current focus: Rust projects via `rust-analyzer` (plus early C# support via OmniSharp LSP mode).

## Status

See `docs/PROGRESS.md` and `docs/ROADMAP.md`.

## Run (dev)

```bash
cargo run -p lspi -- mcp --workspace-root /path/to/project
```

Optional config:

```bash
cargo run -p lspi -- mcp --config /path/to/lspi.toml --workspace-root /path/to/project
```

## Safety

- `rename_symbol` and `rename_symbol_strict` default to preview (`dry_run=true`).
- To apply edits, pass `dry_run=false`.
- Optional strict apply: provide `expected_before_sha256` (per-file SHA-256) and enable backups.

## Docs

- Architecture: `docs/ARCHITECTURE.md`
- ADRs: `docs/adr/README.md`
- Configuration: `docs/CONFIG.md`
- Manual smoke test: `docs/SMOKE_TEST.md`
- Codex integration: `docs/CODEX.md`

## Tools (MCP)

- `find_definition`, `find_definition_at`
- `find_references`, `find_references_at`
- `rename_symbol`, `rename_symbol_strict`
- `get_diagnostics`
- `restart_server`

## Doctor

```bash
cargo run -p lspi -- doctor --workspace-root /path/to/project
```

## Setup

Print a starter config (does not write by default):

```bash
cargo run -p lspi -- setup --workspace-root /path/to/project
```

Write `.lspi/config.toml`:

```bash
cargo run -p lspi -- setup --workspace-root /path/to/project --write
```
