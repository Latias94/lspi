# lspi

Giving AI the sight of LSP.

`lspi` bridges Language Server Protocol (LSP) capabilities to AI coding CLIs (starting with Codex) via an MCP server over stdio.

## What it does

- Symbol navigation (definition/references/hover)
- Safe rename with preview-first edits (`dry_run=true` by default)
- Multi-server routing by file extension + root directory
- Server lifecycle controls (restart/stop)

## Install

From source:

```bash
cargo install --path crates/lspi --locked
```

## Quickstart (Codex)

1) Generate a project config (recommended):

```bash
cd /path/to/project
lspi setup --wizard --non-interactive --write
```

2) Configure Codex MCP (`~/.codex/config.toml`):

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

## Docs

- Configuration: [`docs/CONFIG.md`](../../docs/CONFIG.md)
- Smoke tests: [`docs/SMOKE_TEST.md`](../../docs/SMOKE_TEST.md)
