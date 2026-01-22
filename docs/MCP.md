# MCP Guide (for Codex and other AI CLIs)

This document focuses on how `lspi` behaves as an **MCP stdio server**, and how clients (humans or agents) should
consume results and debug failures.

If you only need setup steps for Codex, see `docs/CODEX.md`.

## What `lspi` provides over MCP

`lspi` exposes LSP-powered tools (definition/references/hover/rename/diagnostics, etc.) via MCP tool calls.
Compared to grep-style workflows, the key value is **symbol-aware navigation** and **preview-first refactoring**.

## Tool result contract

`lspi` returns results as an MCP `tools/call` response:

- `content`: short human-readable fallback (for clients that ignore structured results)
- `structuredContent`: canonical machine-readable JSON payload
- `isError`: set to `true` for tool-level failures

### `structuredContent` common fields

All tool payloads include:

- `schema_version` (integer): version of the structured payload shape
- `ok` (boolean): success flag
- `tool` (string): tool name
- `server_id` (string|null): resolved server id if known
- `input` (object|null): tool arguments (best-effort echo)
- `warnings` (array): non-fatal hints (e.g. position fuzzing, skipped snippets)
- `truncated` (boolean): whether output was cut due to caps

Tools may add additional tool-specific fields.

### Errors are returned as tool results

Whenever possible, `lspi` returns errors as **tool results** (instead of protocol-level JSON-RPC/MCP errors) so
clients still get structured diagnostics.

On error:

- `isError=true`
- `structuredContent.ok=false`
- `structuredContent.error`:
  - `kind` (string): error category (e.g. `invalid_params`, `internal_error`, `read_only`)
  - `message` (string): concise reason
  - `code` / `data` may be present when originating from a JSON-RPC/MCP error

### `next_steps` (actionable remediation hints)

On many errors, `lspi` includes `structuredContent.next_steps` to make failures actionable and predictable.

Shape:

```json
{
  "next_steps": [
    {
      "kind": "tool | config | command | doc",
      "message": "What to do next (human-friendly).",
      "tool": "list_servers",
      "arguments": {}
    }
  ]
}
```

Notes:

- `kind="tool"` steps are safe, machine-executable suggestions (usually introspection).
- `kind="config"` steps explain what config knob to change (human action).
- `kind="command"` steps suggest a CLI command to run (human action).
- Clients SHOULD show `next_steps` prominently when `ok=false`.

## Examples

The following examples are derived from real `lspi` responses, with absolute paths redacted for portability.

### Success example (`get_current_config`)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Loaded config for workspace root <WORKSPACE_ROOT> (1 servers)."
      }
    ],
    "structuredContent": {
      "allowed_roots": ["<WORKSPACE_ROOT>"],
      "input": { "include_env": false, "max_total_chars": 120000 },
      "mcp": null,
      "ok": true,
      "read_only": true,
      "schema_version": 1,
      "server_count": 1,
      "server_id": null,
      "servers": [
        {
          "adapter": null,
          "cwd": "<WORKSPACE_ROOT>",
          "env": null,
          "extensions": ["rs"],
          "id": "rust-analyzer",
          "initialize_timeout_ms": null,
          "kind": "rust_analyzer",
          "language_id": "rust",
          "request_timeout_ms": null,
          "request_timeout_overrides_ms": {},
          "root_dir": "<WORKSPACE_ROOT>",
          "workspace_folders": []
        }
      ],
      "tool": "get_current_config",
      "truncated": false,
      "warnings": [],
      "workspace_root": "<WORKSPACE_ROOT>"
    },
    "isError": false
  }
}
```

### Failure example (routing mismatch)

When `file_path` does not match any configured server extension:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      { "type": "text", "text": "no configured LSP server matches file extension: md" }
    ],
    "structuredContent": {
      "error": {
        "code": -32602,
        "data": { "lspi_error": { "extension": "md", "kind": "no_server_for_extension" } },
        "kind": "invalid_params",
        "message": "no configured LSP server matches file extension: md"
      },
      "input": { "file_path": "README.md", "symbol_name": "lspi" },
      "mcp_error_code": -32602,
      "message": "no configured LSP server matches file extension: md",
      "next_steps": [
        {
          "arguments": {},
          "kind": "tool",
          "message": "Confirm the effective MCP config (workspace_root, allowed_roots, read_only, output caps).",
          "tool": "get_current_config"
        },
        {
          "arguments": {},
          "kind": "tool",
          "message": "Confirm configured servers, extensions, and routing metadata.",
          "tool": "list_servers"
        },
        {
          "arguments": {},
          "kind": "tool",
          "message": "Confirm server lifecycle status (running, last error, warmup).",
          "tool": "get_server_status"
        },
        {
          "kind": "config",
          "message": "Add/verify `servers[].extensions` for this language, or pass a `file_path` with the expected extension so routing can pick the correct server."
        }
      ],
      "ok": false,
      "schema_version": 1,
      "server_id": null,
      "tool": "find_definition",
      "truncated": false,
      "warnings": []
    },
    "isError": true
  }
}
```

## Output caps, truncation, and determinism

Many tools accept:

- `max_results`: limit number of returned items
- `max_total_chars`: bound total response size
- snippet controls (`include_snippet`, `snippet_*`) to keep outputs small and stable

If results are truncated:

- `structuredContent.truncated=true`
- tools may add metadata such as:
  - `returned_results`: how many items were returned
  - `total_estimate`: best-effort estimate of total matches

Clients SHOULD treat truncation as “partial results” and optionally re-run with larger caps.

## Read-only and presets (`context` / `mode`)

There are two ways to keep `lspi` least-privilege:

- `mcp.read_only=true` or `lspi mcp --read-only`: hard disables rename and server-control tools
- `mcp.context` / `lspi mcp --context`: applies safe defaults (without overriding explicit config)
  - `codex` / `navigation` default to read-only unless explicitly overridden
- `lspi mcp --mode navigation|refactor`: sugar for common “safe defaults” combinations

If a write/control tool is called in read-only mode, the result is returned as a structured error with `next_steps`.

## Recommended debugging playbook

When a tool call fails:

1) Read `structuredContent.error.message` and follow `structuredContent.next_steps`.
2) Use introspection tools to confirm effective config and server health:
   - `get_current_config`
   - `list_servers`
   - `get_server_status`
3) If you can run CLI commands, prefer `lspi doctor --workspace-root . --json` for a machine-readable environment/config report.
4) Common root causes:
   - routing mismatch: `servers[].extensions` does not match the file
   - workspace boundary: `file_path` is outside `workspace_root` / `servers[].workspace_folders`
    - server missing: language server command not installed or not configured
    - timeouts: increase `request_timeout_ms` or use `request_timeout_overrides_ms` for slow methods

## References / inspiration

This project borrows ideas from:

- `cclsp`: https://github.com/ktnyt/cclsp
- `serena`: https://github.com/oraios/serena
