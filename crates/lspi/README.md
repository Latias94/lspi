# lspi

`lspi` bridges Language Server Protocol (LSP) capabilities to AI coding CLIs (starting with Codex) via an MCP server over stdio.

## Install

From source (recommended for now):

```bash
cargo install --path crates/lspi
```

## Quickstart (Codex)

1) Generate a project config:

```bash
cd /path/to/project
lspi setup --wizard --write
```

2) Configure Codex MCP (`~/.codex/config.toml`):

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

## Docs

- Repository docs: `docs/CONFIG.md`, `docs/CODEX.md`, `docs/SMOKE_TEST.md`
