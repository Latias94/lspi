# lspi

Giving AI the sight of LSP.

`lspi` bridges **Language Server Protocol (LSP)** capabilities to **AI coding CLIs** (starting with Codex) via an **MCP server** over stdio.

## What it does

- Instant symbol navigation (definition/references/hover)
- Safe rename with preview-first edits (`dry_run=true` by default)
- Language-server lifecycle controls (restart/stop)
- Multi-server routing by file extension + root directory

## Supported language servers

`lspi` does not bundle language servers. Install the servers you need and configure them in `lspi` config.
For any LSP that speaks JSON-RPC over stdio, use `kind = "generic"`.

Known-good setups (examples and smoke tests are included in this repo):

- Rust: `rust-analyzer`
- C#: OmniSharp in LSP mode (`omnisharp -lsp`)
- TypeScript: `typescript-language-server`
- Go: `gopls`
- Python: `pyright-langserver`
- Lua: `lua-language-server`
- C++: `clangd`

## Install

Prerequisites:

- Rust toolchain (stable)

Install `lspi` from source:

```bash
cargo install --path crates/lspi --locked
```

Verify:

```bash
lspi --version
```

## Quickstart (Codex)

1) Generate a project config (recommended):

```bash
cd /path/to/project
lspi setup --wizard --non-interactive --write
```

2) Check dependencies:

```bash
lspi doctor --workspace-root .
```

3) Configure Codex MCP (`~/.codex/config.toml`):

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

Notes:

- Codex uses a global config; run `codex` from the project root you want to work on.
- You can pass `--config /path/to/lspi.toml` in `args` if you keep config outside the workspace.
- Optional: add `--warmup` to start language servers eagerly (reduces first-tool-call latency).

## Configuration

See [`docs/CONFIG.md`](docs/CONFIG.md) for the full schema and discovery order.

Common environment variables:

- `LSPI_CONFIG_PATH`: explicit config file path
- `LSPI_RUST_ANALYZER_COMMAND`: override `rust-analyzer` command
- `LSPI_OMNISHARP_COMMAND`: override `omnisharp` command
- `LSPI_PYRIGHT_COMMAND`: override `pyright-langserver` command
- `LSPI_BASEDPYRIGHT_COMMAND`: override `basedpyright-langserver` command

## Optional: add agent instructions / skill metadata

- Agent prompt snippet (copy-paste): [`docs/AGENTS_SNIPPETS.md`](docs/AGENTS_SNIPPETS.md)
- Codex skill definition: [`.codex/skills/lspi/SKILL.md`](.codex/skills/lspi/SKILL.md)

## Safety

- `rename_symbol` and `rename_symbol_strict` default to preview (`dry_run=true`).
- To apply edits, pass `dry_run=false`.
- Optional strict apply: provide `expected_before_sha256` (per-file SHA-256) and enable backups.

## Optional: smoke tests

See [`docs/SMOKE_TEST.md`](docs/SMOKE_TEST.md) for end-to-end scripts (Rust/C#/TypeScript/Go/Python/Lua/C++).

## Tools (MCP)

- `find_definition`, `find_definition_at`
- `find_references`, `find_references_at`
- `hover_at`
- `find_implementation_at`
- `find_type_definition_at`
- `find_incoming_calls`, `find_incoming_calls_at`
- `find_outgoing_calls`, `find_outgoing_calls_at`
- `get_document_symbols`
- `search_workspace_symbols`
- `rename_symbol`, `rename_symbol_strict`
- `get_diagnostics`
- `restart_server`, `stop_server`

If you want a "least privilege" toolset (e.g. read-only navigation), use `mcp.tools` allow/exclude in your config. See [`docs/CONFIG.md`](docs/CONFIG.md).

## Development

Run MCP server without installing:

```bash
cargo run -p lspi -- mcp --workspace-root .
```

Run doctor:

```bash
cargo run -p lspi -- doctor --workspace-root .
```

Run tests (recommended):

```bash
cargo nextest run
```

Format:

```bash
cargo fmt
```
