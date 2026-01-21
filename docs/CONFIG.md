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
kind = "rust_analyzer"             # required (currently only rust_analyzer is supported)
extensions = ["rs"]                # required (no leading dots)
# root_dir = "."                   # optional; absolute or relative to workspace_root
# command = "rust-analyzer"        # optional; defaults to auto-resolve
# args = []                        # optional
initialize_timeout_ms = 10000      # optional
request_timeout_ms = 30000         # optional
warmup_timeout_ms = 5000           # optional
```

Routing semantics (ADR 0006):

- A tool call is routed by the target file extension (`extensions`).
- If multiple servers match, `root_dir` is used as a tie-breaker: the most specific containing path wins (longest match).
- If no `root_dir` contains the file, the first matching server wins (config order).

If `command` is not set for a `rust_analyzer` server, `lspi` tries:

- `LSPI_RUST_ANALYZER_COMMAND`
- `rustup which rust-analyzer`
- `rust-analyzer` from `PATH`

### `rust_analyzer` (legacy / optional)

For backward compatibility, `lspi` still accepts:

```toml
[rust_analyzer]
command = "rust-analyzer"          # optional
args = ["--stdio"]                 # optional
initialize_timeout_ms = 10000      # optional
request_timeout_ms = 30000         # optional
warmup_timeout_ms = 5000           # optional
```

If `servers` is not set, this section is mapped to an implicit `[[servers]]` entry:

- `id = "rust-analyzer"`
- `kind = "rust_analyzer"`
- `extensions = ["rs"]`
- `root_dir = workspace_root` (or current directory)

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

## CLI helper

Generate a starter config:

```bash
lspi setup --workspace-root /path/to/project --write
```
