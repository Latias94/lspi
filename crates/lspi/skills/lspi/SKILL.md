---
name: lspi
description: |-
  Use lspi (an MCP server) to give Codex LSP-powered semantic navigation and safe refactoring.
  Use this when you need symbol-level understanding (hover/definition/references/implementation/typeDefinition),
  or when doing a rename across a real codebase and you want a preview-first workflow.
metadata:
  short-description: LSP semantic navigation via MCP
---

# lspi (Giving AI the sight of LSP)

`lspi` bridges Language Server Protocol (LSP) capabilities to Codex via an MCP server over stdio.

## When to use

- You need semantic navigation: definition / references / implementation / type definition.
- You need call graph insights: incoming calls / outgoing calls (call hierarchy).
- You need quick type/doc info at a cursor: hover.
- You want to list symbols in a file or search symbols across the workspace.
- You want a safe rename workflow (preview first, apply only when confirmed).

## Core rules

- All `*_at` tools use **1-based** `line` / `character`.
- Prefer `*_at` tools when you have a cursor position: they apply bounded position fuzzing.
- For multi-language workspaces: `search_workspace_symbols` MUST include `file_path` if multiple language servers are configured.
- `rename_symbol` / `rename_symbol_strict` defaults to preview (`dry_run=true`). Only apply edits when explicitly requested.

## Recommended workflow (read → verify → change)

1) Gather context:
   - `hover_at` (fast type/doc check)
   - `get_document_symbols` (what symbols exist in this file?)
   - `search_workspace_symbols` (find candidate symbols by name)
2) Verify target:
   - `find_definition_at` / `find_references_at`
   - optionally: `find_implementation_at` / `find_type_definition_at`
3) Change safely:
   - `rename_symbol_strict` (position-based) or `rename_symbol` (name-based)
   - start with `dry_run=true`, inspect the preview edit, then rerun with `dry_run=false`
4) Validate and recover:
   - `get_diagnostics`
   - `restart_server` or `stop_server` if the LSP process is stuck or needs to be released

## Tool cheat sheet

- Read-only:
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
- Control:
  - `restart_server`
  - `stop_server`
