# Codex Integration

This document shows how to connect `lspi` to Codex as an MCP server.

## Recommended: Generate a project config first

From the project root you want to work on:

```bash
lspi setup --wizard --non-interactive --write
```

Then verify:

```bash
lspi doctor --workspace-root .
```

Notes:

- `--wizard` does a best-effort scan for Rust/C# projects and generates matching `[[servers]]`.
- By default, `--wizard` is interactive when stdin/stdout are TTYs. Use `--non-interactive` for CI/scripts.
- You can force prompts with `--interactive` or force-disable them with `--non-interactive`.
- If you prefer the minimal Rust-only template, use:
  - `lspi setup --write`

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

- `--workspace-root "."` means "use the current working directory".
- Because Codex uses a global config, you should run `codex` from the project root you want to work on.
- Optional: add `--warmup` to reduce first-tool-call latency by starting language servers eagerly.
- Optional: add `--read-only` (or set `mcp.read_only=true`) to expose a navigation-only toolset.
- Troubleshooting: use `get_current_config` / `get_server_status` to confirm routing/workspace roots and server health.
- If you keep `lspi` config outside the workspace, pass it explicitly:
  - `args = ["mcp", "--workspace-root", ".", "--config", "/path/to/lspi.toml"]`

## Recommended: Add agent instructions (two options)

### Option A: Add an `AGENTS.md` snippet (works for any agent)

For better tool usage and traceability, add an `lspi` snippet to your project's `AGENTS.md`:

- See `docs/AGENTS_SNIPPETS.md`

### Option B: Install a Codex Skill (Codex-specific)

Codex can load repo-scoped skills from `.codex/skills/**/SKILL.md` or user-scoped skills from `$CODEX_HOME/skills/**/SKILL.md` (usually `~/.codex/skills`).

This repository includes a ready-to-use skill at:

- `.codex/skills/lspi/SKILL.md`

To install it globally (so Codex can use it in any repo), copy (or symlink) this directory to:

- `~/.codex/skills/lspi/`

Or install it automatically:

```bash
lspi skill install --scope user
```

Then, in Codex, ask it to use the `lspi` skill (or select it in a UI that supports skills).

If you prefer repo-scoped installation (per project), copy the folder into your project repo:

- `<your-project>/.codex/skills/lspi/`

Or install it automatically:

```bash
lspi skill install --scope repo --workspace-root .
```

Example (macOS/Linux):

```bash
mkdir -p /path/to/your-project/.codex/skills
cp -R /path/to/lspi/.codex/skills/lspi /path/to/your-project/.codex/skills/
```

Example (PowerShell):

```powershell
New-Item -ItemType Directory -Force -Path "C:\\path\\to\\your-project\\.codex\\skills" | Out-Null
Copy-Item -Recurse -Force "C:\\path\\to\\lspi\\.codex\\skills\\lspi" "C:\\path\\to\\your-project\\.codex\\skills\\"
```

## Tool usage notes (important)

- All `*_at` tools use **1-based** `line` / `character`.
- Prefer `*_at` tools when you have a cursor/position: they apply bounded position fuzzing for robustness.
- For large result sets (especially references), set `max_results` / `max_total_chars` explicitly and consider `include_snippet=false`.
- `search_workspace_symbols`:
  - If multiple language servers are configured, provide `file_path` to disambiguate which server to use.
  - If only one server is configured, `file_path` is optional.

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
