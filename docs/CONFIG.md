# lspi Configuration

`lspi` reads configuration from either TOML or JSON.

Discovery order (first match wins):

1. CLI `--config`
2. `LSPI_CONFIG_PATH`
3. Workspace:
   - `.lspi/config.toml`
   - `.lspi/config.json`
   - `lspi.toml`
   - `lspi.json`

## Schema

### `workspace_root` (optional)

Overrides the workspace root used for safety checks and path resolution.

### `servers` (recommended)

```toml
[[servers]]
id = "rust-analyzer"               # optional but recommended
kind = "rust_analyzer"             # required (supported: rust_analyzer, omnisharp, generic)
extensions = ["rs"]                # required (no leading dots)
# root_dir = "."                   # optional; absolute or relative to workspace_root
# command = "rust-analyzer"        # optional; defaults to auto-resolve
# args = []                        # optional
# language_id = "rust"             # optional; used by kind="generic" (best-effort default from extension)
initialize_timeout_ms = 10000      # optional
request_timeout_ms = 30000         # optional
warmup_timeout_ms = 5000           # optional
# restart_interval_minutes = 30    # optional; auto-restart long-running servers
# idle_shutdown_ms = 300000        # optional; auto-stop after being idle
#
# Optional: responses for server-initiated workspace/configuration requests.
# This helps some servers (notably typescript-language-server) that expect configuration at runtime.
# [servers.workspace_configuration]
# formattingOptions = { tabSize = 4, insertSpaces = true }
```

Routing semantics (ADR 0006):

- A tool call is routed by the target file extension (`extensions`).
- If multiple servers match, `root_dir` is used as a tie-breaker: the most specific containing path wins (longest match).
- If no `root_dir` contains the file, the first matching server wins (config order).

If `command` is not set for a `rust_analyzer` server, `lspi` tries:

- `LSPI_RUST_ANALYZER_COMMAND`
- `rustup which rust-analyzer`
- `rust-analyzer` from `PATH`

### C# (OmniSharp) example

`lspi` supports C# via OmniSharp in LSP mode:

```toml
[[servers]]
id = "omnisharp"
kind = "omnisharp"
extensions = ["cs"]
# root_dir = "."
# command = "omnisharp"
args = ["-lsp"]
initialize_timeout_ms = 10000
request_timeout_ms = 30000
warmup_timeout_ms = 0
# restart_interval_minutes = 30
# idle_shutdown_ms = 300000
```

If `command` is not set for an `omnisharp` server, `lspi` tries:

- `LSPI_OMNISHARP_COMMAND`
- `omnisharp` from `PATH`

### Generic LSP example (TypeScript)

Use `kind = "generic"` for any stdio-based LSP server where `lspi` should not apply language-specific behavior.

```toml
[[servers]]
id = "ts"
kind = "generic"
extensions = ["ts", "tsx", "js", "jsx"]
language_id = "typescript"
command = "typescript-language-server"
args = ["--stdio"]
initialize_timeout_ms = 10000
request_timeout_ms = 30000
```

Notes:

- `language_id` controls the `textDocument/didOpen` languageId. If omitted, `lspi` guesses from the first extension.
- For `kind = "generic"`, `command` is required (no auto-resolve).

### Generic LSP example (Go / gopls)

```toml
[[servers]]
id = "go"
kind = "generic"
extensions = ["go"]
language_id = "go"
command = "gopls"
args = ["serve"]
initialize_timeout_ms = 20000
request_timeout_ms = 30000
```

### Generic LSP example (Python / pyright-langserver)

```toml
[[servers]]
id = "python"
kind = "generic"
extensions = ["py"]
language_id = "python"
command = "pyright-langserver"
args = ["--stdio"]
initialize_timeout_ms = 20000
request_timeout_ms = 30000
```

### Generic LSP example (Lua / lua-language-server)

```toml
[[servers]]
id = "lua"
kind = "generic"
extensions = ["lua"]
language_id = "lua"
command = "lua-language-server"
args = []
initialize_timeout_ms = 20000
request_timeout_ms = 30000
```

### Generic LSP example (C++ / clangd)

```toml
[[servers]]
id = "cpp"
kind = "generic"
extensions = ["cpp", "cc", "cxx", "h", "hpp"]
language_id = "cpp"
command = "clangd"
args = []
initialize_timeout_ms = 20000
request_timeout_ms = 30000
```

### Lifecycle options (optional)

These options control how `lspi` manages long-running language server processes:

- `restart_interval_minutes`: if set, `lspi` may restart the server after it has been running for this long (best-effort).
- `idle_shutdown_ms`: if set, `lspi` may stop the server after it has been idle for this long (best-effort).

### `mcp.output` (optional)

Global output size limits for tool responses.

```toml
[mcp.output]
max_total_chars_default = 120000   # optional
max_total_chars_hard = 2000000     # optional
```

Semantics:

- If a tool call omits `max_total_chars`, `max_total_chars_default` is used.
- If a tool call requests `max_total_chars` above the hard cap, it is clamped and a warning is returned.

### `mcp.tools` (optional)

Restrict which tools are exposed through MCP (useful for “least privilege” setups).

```toml
[mcp.tools]
# If set and non-empty: only these tools are exposed.
allow = [
  "find_definition_at",
  "find_references_at",
  "hover_at",
  "get_document_symbols",
  "search_workspace_symbols",
  "get_diagnostics"
]

# Tools to exclude (ignored when `allow` is set and non-empty).
# exclude = ["rename_symbol", "rename_symbol_strict"]
```

Semantics:

- Tool names are matched case-insensitively.
- `allow` (non-empty) takes precedence over `exclude`.

## CLI helper

Generate a starter config:

```bash
lspi setup --workspace-root /path/to/project --write

# Best-effort detection (Rust/C#) and tailored config:
lspi setup --workspace-root /path/to/project --wizard --write
```

## Defaults

If `servers` is omitted or empty, `lspi` uses a single implicit Rust server:

- `id = "rust-analyzer"`
- `kind = "rust_analyzer"`
- `extensions = ["rs"]`
- `root_dir = workspace_root`
