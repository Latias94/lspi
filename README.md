# lspi

Giving AI the sight of LSP.

`lspi` is an **MCP server** that bridges **Language Server Protocol (LSP)** features (definition/references/rename/diagnostics, etc.)
to **AI coding CLIs** (starting with Codex) over **stdio**.

If your agent keeps doing grep-like searches or fragile string edits, `lspi` gives it IDE-grade, symbol-aware tooling.

## Why lspi

AI assistants are good at reasoning, but they usually lack reliable access to symbol relationships in a real codebase.
With `lspi`, your agent can:

- Jump to definitions, implementations, type definitions, and references
- Inspect hover/type information at a cursor position
- Use `*_at` tools with bounded position fuzzing (helps when the agent is off-by-one on line/column counting)
- Perform preview-first, workspace-wide renames safely
- Query call hierarchy (incoming/outgoing calls) when supported by the language server

## How it works

- You run `lspi mcp` as a stdio MCP server.
- `lspi` starts and manages one or more LSP servers (your choice) and routes requests by file path / extension.
- Tool results are returned as **structured** MCP responses, with output caps to keep results deterministic.

## Quickstart (Codex)

1) Install `lspi` (one-time):

```bash
cargo install --path crates/lspi --locked
```

2) Create a per-project `lspi` config (recommended):

```bash
cd /path/to/project
lspi setup --wizard --non-interactive --write
```

3) Verify language server availability:

```bash
lspi doctor --workspace-root .
```

4) Configure Codex MCP (`~/.codex/config.toml`):

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

Notes:

- Codex uses a global config; run `codex` from the project root you want to work on.
- If your `lspi` config is not inside the workspace, pass it explicitly:
  - `args = ["mcp", "--workspace-root", ".", "--config", "/path/to/lspi.toml"]`
- Optional: add `--warmup` to start language servers eagerly (reduces first-tool-call latency).

For more details, see `docs/CODEX.md`.

## Troubleshooting (common issues)

- “No server found for extension …”:
  - Add/verify `servers[].extensions`, and ensure `file_path` matches the intended language server.
- Language server not starting / command not found:
  - Install the language server, or set `servers[].command` / the corresponding `LSPI_*_COMMAND` env var.
  - Run `lspi doctor --workspace-root .` for actionable hints.
- Off-by-one line/column:
  - Prefer `*_at` tools (they use bounded position fuzzing).
- Large outputs / truncated results:
  - Set `max_results` / `max_total_chars`, and consider `include_snippet=false` for large reference sets.
- TypeScript/Vue returns empty/odd results:
  - Configure `servers[].workspace_configuration` and/or tune `initialize_options` / `client_capabilities`.
  - Consider `servers[].adapter = "tsserver"` when using TypeScript/Vue tooling.

## Language server support

`lspi` does not bundle language servers.
You install the servers you need and configure them in `lspi` config.

There are two layers of support:

- **First-class server kinds** (built-in defaults / extra compatibility):
  - Rust: `kind = "rust_analyzer"`
  - C#: `kind = "omnisharp"`
  - Python: `kind = "pyright"` / `kind = "basedpyright"`
- **Generic mode**: for any LSP server that speaks JSON-RPC over stdio, use `kind = "generic"` and set `command`.

In practice, most “standard” language servers work well in generic mode (Go `gopls`, C++ `clangd`, Lua `lua-language-server`, etc.).
TypeScript/Vue tooling tends to be more quirky; `lspi` includes a small adapter layer for server-specific behavior
(see `servers[].adapter`, currently `tsserver`).

## FAQ

### Do I need to install language servers?

Yes. `lspi` does not bundle any language servers. Install the servers you need and point `lspi` at them via config.
Use `lspi doctor --workspace-root .` to validate your setup.

### Are Go / TypeScript supported?

Yes, via `kind = "generic"` (provided the LSP server speaks JSON-RPC over stdio).
In practice:

- Go (`gopls`) usually works well in generic mode.
- TypeScript/Vue often needs extra tuning (runtime `workspace/configuration`, and sometimes `servers[].adapter = "tsserver"`).

### How does multi-root work?

Configure additional roots with `servers[].workspace_folders`. If you configure multiple LSP servers, tools like
`search_workspace_symbols` should include `file_path` so `lspi` can route to the right server.

### Will `lspi` modify my files automatically?

No. Rename tools default to preview mode (`dry_run=true`), and you must explicitly request applying edits (`dry_run=false`).

## Configuration (what you will actually tweak)

Full schema and discovery order:

- `docs/CONFIG.md`

### Minimal `.lspi/config.toml` example

```toml
[[servers]]
id = "rust-analyzer"
kind = "rust_analyzer"
extensions = ["rs"]

[[servers]]
id = "ts"
kind = "generic"
extensions = ["ts", "tsx", "js", "jsx", "vue"]
language_id = "typescript"
command = "typescript-language-server"
args = ["--stdio"]
adapter = "tsserver"

# Optional (sometimes needed for TypeScript tooling):
# [servers.workspace_configuration]
# formattingOptions = { tabSize = 2, insertSpaces = true }
```

Common knobs (per server):

- `servers[].root_dir` and `servers[].workspace_folders` (multi-root workspaces)
- `servers[].initialize_options` and `servers[].client_capabilities` (improve compatibility for “generic” servers)
- `servers[].workspace_configuration` (responses to `workspace/configuration`, e.g. formatting options)
- `servers[].request_timeout_overrides_ms` (workspace-wide operations can be slow)
- `servers[].adapter` (server quirks; currently `tsserver`)

Common environment variables:

- `LSPI_CONFIG_PATH`: explicit config file path
- `LSPI_RUST_ANALYZER_COMMAND`: override `rust-analyzer` command
- `LSPI_OMNISHARP_COMMAND`: override `omnisharp` command
- `LSPI_PYRIGHT_COMMAND`: override `pyright-langserver` command
- `LSPI_BASEDPYRIGHT_COMMAND`: override `basedpyright-langserver` command

## Safety model (rename / edits)

- `rename_symbol` and `rename_symbol_strict` default to preview (`dry_run=true`).
- To apply edits, pass `dry_run=false`.
- Optional strict apply: provide `expected_before_sha256` (per-file SHA-256) and enable backups.
- Writes are restricted to within the configured workspace root(s).

## MCP tools

Read-only navigation:

- `hover_at`
- `get_document_symbols`
- `search_workspace_symbols`
- `find_definition` / `find_definition_at`
- `find_references` / `find_references_at`
- `find_implementation_at`
- `find_type_definition_at`
- `find_incoming_calls` / `find_incoming_calls_at`
- `find_outgoing_calls` / `find_outgoing_calls_at`
- `get_diagnostics`

Write / control:

- `rename_symbol` / `rename_symbol_strict`
- `restart_server`
- `stop_server`

If you want a least-privilege toolset (e.g. read-only navigation), use `mcp.tools` allow/exclude in your config.

## Docs

- Codex integration: `docs/CODEX.md`
- Configuration: `docs/CONFIG.md`
- Agent prompt snippet (copy-paste): `docs/AGENTS_SNIPPETS.md`
- Smoke tests: `docs/SMOKE_TEST.md`
- Release notes: `CHANGELOG.md`

## Acknowledgements / inspiration

`lspi` is inspired by and references ideas from:

- `cclsp` (MCP ↔ LSP bridge): https://github.com/ktnyt/cclsp
- `serena` (agent tooling + MCP/LSP integration): https://github.com/oraios/serena
- `rust-analyzer` (Rust language server): https://github.com/rust-lang/rust-analyzer

## Development

Run MCP server without installing:

```bash
cargo run -p lspi -- mcp --workspace-root .
```

Run tests:

```bash
cargo nextest run
```
