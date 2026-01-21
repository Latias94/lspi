# Smoke Test (Manual)

This is a quick end-to-end sanity check for the **MCP frontend + rust-analyzer backend**.

For C# (OmniSharp), see the dedicated section below.

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

Expected: the response includes `find_definition`, `find_definition_at`, `find_references`, `find_references_at`, `hover_at`, `find_implementation_at`, `find_type_definition_at`, `find_incoming_calls`, `find_outgoing_calls`, `find_incoming_calls_at`, `find_outgoing_calls_at`, `get_document_symbols`, `search_workspace_symbols`, `rename_symbol`, `rename_symbol_strict`, `get_diagnostics`, `restart_server`, `stop_server`.

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

## C# (OmniSharp) smoke test

This repository includes a minimal C# project at `samples/csharp/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_csharp.ps1
```

Run against a real solution/project:

```powershell
pwsh scripts/mcp_smoke_csharp.ps1 -ProjectPath C:\path\to\MySolution.sln
pwsh scripts/mcp_smoke_csharp.ps1 -ProjectPath C:\path\to\MyProject.csproj
```

Note: when `-ProjectPath` is provided, the script passes it to OmniSharp best-effort (prefers `--solution`/`-s` or `--project`/`-p` if supported; otherwise passes it as a positional argument).

If you want to exercise position-based tools (definition/references/rename), provide a test file and a needle string:

```powershell
pwsh scripts/mcp_smoke_csharp.ps1 -ProjectPath C:\path\to\MySolution.sln -TestFile src/MyFile.cs -Needle "SomeSymbol"
```

Prerequisites:

- `dotnet` available on `PATH`
- `omnisharp` available on `PATH` (or set `LSPI_OMNISHARP_COMMAND`)

Notes:

- The script defaults to `-SkipIfMissing` so it does not fail if OmniSharp is not installed.
- To fail fast when prerequisites are missing, run:

```powershell
pwsh scripts/mcp_smoke_csharp.ps1 -SkipIfMissing:$false
```

## TypeScript (generic LSP) smoke test

This repository includes a minimal TypeScript project at `samples/typescript/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_ts.ps1
```

Run against a real TypeScript project:

```powershell
pwsh scripts/mcp_smoke_ts.ps1 -WorkspaceRoot C:\path\to\my-ts-project
```

Prerequisites (best-effort):

- `node` + `npm` available on `PATH`
- `typescript-language-server` available either:
  - locally under `<project>/node_modules/.bin/` (recommended), or
  - globally on `PATH`

Notes:

- The script defaults to `-SkipIfMissing` so it does not fail if prerequisites are missing.
- If your project has `package.json` but no `node_modules`, either run `npm install` first or pass `-InstallDeps`.

## Go (generic LSP) smoke test

This repository includes a minimal Go module at `samples/go/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_go.ps1
```

Run against a real Go module/repo:

```powershell
pwsh scripts/mcp_smoke_go.ps1 -WorkspaceRoot C:\path\to\my-go-project
```

Prerequisites (best-effort):

- `go` available on `PATH`
- `gopls` available on `PATH`

Notes:

- The script defaults to `-SkipIfMissing` so it does not fail if prerequisites are missing.
- If `gopls` is missing, you can install it with:
  - `go install golang.org/x/tools/gopls@latest`
  - or run the script with `-InstallGopls` (best-effort).

## Python (generic LSP) smoke test

This repository includes a minimal Python project at `samples/python/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_python.ps1
```

Run against a real Python project:

```powershell
pwsh scripts/mcp_smoke_python.ps1 -WorkspaceRoot C:\path\to\my-python-project
```

Prerequisites (best-effort):

- `node` + `npm` available on `PATH`
- `pyright-langserver` available either:
  - locally under `<project>/node_modules/.bin/` (recommended), or
  - globally on `PATH`

Notes:

- The script defaults to `-SkipIfMissing` so it does not fail if prerequisites are missing.
- If your project has `package.json` but no `node_modules`, either run `npm install` first or pass `-InstallDeps`.

## Lua (generic LSP) smoke test

This repository includes a minimal Lua project at `samples/lua/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_lua.ps1
```

Run against a real Lua project:

```powershell
pwsh scripts/mcp_smoke_lua.ps1 -WorkspaceRoot C:\path\to\my-lua-project
```

Prerequisites (best-effort):

- `lua-language-server` available on `PATH`

Notes:

- The script defaults to `-SkipIfMissing` so it does not fail if prerequisites are missing.

## C++ (generic LSP) smoke test

This repository includes a minimal C++ project at `samples/cpp/Hello/` and a smoke script:

```powershell
pwsh scripts/mcp_smoke_cpp.ps1
```

Run against a real C++ project:

```powershell
pwsh scripts/mcp_smoke_cpp.ps1 -WorkspaceRoot C:\path\to\my-cpp-project
```

Prerequisites (best-effort):

- `clangd` available on `PATH`

Notes:

- For best results on real projects, provide compilation flags via `compile_commands.json`, `.clangd`, or `compile_flags.txt`.
- The script defaults to `-SkipIfMissing` so it does not fail if prerequisites are missing.
