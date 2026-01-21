# Codex Integration

This document shows how to connect `lspi` to Codex as an MCP server.

## Recommended: Install `lspi` once

From the `lspi` repo root:

```bash
cargo install --path crates/lspi
```

Verify:

```bash
lspi --version
```

## Configure Codex

Codex reads MCP server configuration from `~/.codex/config.toml`.

Add:

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

Notes:

- `--workspace-root "."` means “use the current working directory”.
- Because Codex uses a global config, you should run `codex` from the project root you want to work on.

## Recommended: Generate a project config

From the project root you want to work on:

```bash
lspi setup --wizard --write
```

Then verify:

```bash
lspi doctor --workspace-root .
```

## Per-project configuration (optional)

If you want a project-specific `lspi` configuration, create one of:

- `.lspi/config.toml`
- `.lspi/config.json`
- `lspi.toml`
- `lspi.json`

See `docs/CONFIG.md` for the full schema and discovery order.

## Troubleshooting

- Check environment and rust-analyzer availability:

  ```bash
  lspi doctor --workspace-root .
  ```

- If rust-analyzer is missing:

  ```bash
  rustup component add rust-analyzer
  ```
