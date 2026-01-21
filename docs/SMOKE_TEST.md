# Smoke Test (Manual)

This is a quick end-to-end sanity check for the **MCP frontend + rust-analyzer backend**.

## Prerequisites

- `rust-analyzer` available on `PATH`, or set `LSPI_RUST_ANALYZER_COMMAND`.
  - If using rustup: `rustup component add rust-analyzer`

Optional (recommended): run a quick check first:

```powershell
cargo run -p lspi -- doctor --workspace-root .
```

## Run `tools/list`

From the repo root:

```powershell
$req = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"lspi-smoke","version":"0.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
'@

$req | cargo run -p lspi -- mcp --workspace-root .
```

Expected: the response includes `find_definition`, `find_definition_at`, `find_references`, `find_references_at`, `rename_symbol`, `rename_symbol_strict`, `get_diagnostics`, `restart_server`.

## Run `find_definition` / `find_references` (by name)

```powershell
$req = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"lspi-smoke","version":"0.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_definition","arguments":{"file_path":"crates/lspi-mcp/src/lib.rs","symbol_name":"run_stdio_with_options"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"find_references","arguments":{"file_path":"crates/lspi-mcp/src/lib.rs","symbol_name":"run_stdio_with_options","max_results":200}}}
'@

$req | cargo run -p lspi -- mcp --workspace-root .
```

Expected:

- `find_definition` returns at least 1 definition location for `run_stdio_with_options`.
- `find_references` returns references including `crates/lspi/src/main.rs`.

## Run `find_definition_at` / `find_references_at` (by position)

Pick a call site position from your editor (1-based line/character), then:

```powershell
$req = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"lspi-smoke","version":"0.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_definition_at","arguments":{"file_path":"crates/lspi/src/main.rs","line":1,"character":1}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"find_references_at","arguments":{"file_path":"crates/lspi-mcp/src/lib.rs","line":1,"character":1,"max_results":200}}}
'@

$req | cargo run -p lspi -- mcp --workspace-root .
```

Notes:

- If you provide an approximate position, `lspi` may apply bounded position fuzzing and report a `position_fuzzing` warning.

## Run `rename_symbol` (preview only)

```powershell
$req = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"lspi-smoke","version":"0.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rename_symbol","arguments":{"file_path":"crates/lspi-mcp/src/lib.rs","symbol_name":"run_stdio_with_options","new_name":"run_stdio_with_options_tmp","dry_run":true}}}
'@

$req | cargo run -p lspi -- mcp --workspace-root .
```

Expected: `edit.files` contains a non-empty preview; no files are modified.

If `rename_symbol` reports `needs_disambiguation=true`, use `rename_symbol_strict` with one of the returned candidate positions.

## Run `get_diagnostics`

```powershell
$req = @'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"lspi-smoke","version":"0.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_diagnostics","arguments":{"file_path":"crates/lspi/src/main.rs","max_results":200}}}
'@

$req | cargo run -p lspi -- mcp --workspace-root .
```

Notes:

- On the first run, rust-analyzer may not have published diagnostics yet; re-run if needed.

## Note about piping

If you see only the `initialize` response and the process exits, use `scripts/mcp_smoke.ps1` which keeps stdin open until expected responses are received:

```powershell
pwsh scripts/mcp_smoke.ps1 -WorkspaceRoot .
```

The script requires `rust-analyzer` to be installed; it runs `lspi doctor` first and fails fast if missing.

Note: `scripts/mcp_smoke.ps1` is tailored to this repository (it searches for `run_stdio_with_options` in `crates/lspi/src/main.rs`).
