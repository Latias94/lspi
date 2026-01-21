# lspi

Giving AI the sight of LSP.

`lspi` bridges **Language Server Protocol (LSP)** capabilities to **AI coding CLIs** (starting with Codex) via an **MCP server** over stdio.

Current focus:

- Rust via `rust-analyzer`
- C# via OmniSharp (`omnisharp -lsp`)

## Status

See `docs/PROGRESS.md` and `docs/ROADMAP.md`.

## Install

Prerequisites:

- Rust toolchain (stable)

Install `lspi` from source (recommended for now):

```bash
cargo install --path crates/lspi
```

Verify:

```bash
lspi --version
```

## Language Server Prerequisites

`lspi` does not bundle language servers. Install the ones you need:

### Rust (`rust-analyzer`)

```bash
rustup component add rust-analyzer
```

Or set `LSPI_RUST_ANALYZER_COMMAND` to a `rust-analyzer` binary path.

### C# (OmniSharp)

- Install .NET SDK and verify:

  ```bash
  dotnet --info
  ```

- Install OmniSharp (LSP mode) and ensure `omnisharp` is runnable, or set `LSPI_OMNISHARP_COMMAND`.

Run `lspi doctor --workspace-root .` for best-effort checks and hints.

## Quickstart (Codex)

1) Generate a project config (recommended):

```bash
cd /path/to/project
lspi setup --wizard --write
```

2) Check dependencies:

```bash
lspi doctor --workspace-root .
```

3) Configure Codex MCP (`~/.codex/config.toml`):

```toml
[mcp_servers.lspi]
command = "lspi"
args = ["mcp", "--workspace-root", "."]
```

Notes:

- Codex uses a global config; run `codex` from the project root you want to work on.
- You can pass `--config /path/to/lspi.toml` in `args` if you keep config outside the workspace.
- Optional: add `--warmup` to start language servers eagerly (reduces first-tool-call latency).

## Configuration

See `docs/CONFIG.md` for the full schema and discovery order.

Common environment variables:

- `LSPI_CONFIG_PATH`: explicit config file path
- `LSPI_RUST_ANALYZER_COMMAND`: override `rust-analyzer` command
- `LSPI_OMNISHARP_COMMAND`: override `omnisharp` command

## Safety

- `rename_symbol` and `rename_symbol_strict` default to preview (`dry_run=true`).
- To apply edits, pass `dry_run=false`.
- Optional strict apply: provide `expected_before_sha256` (per-file SHA-256) and enable backups.

## Docs

- Architecture: `docs/ARCHITECTURE.md`
- ADRs: `docs/adr/README.md`
- Configuration: `docs/CONFIG.md`
- Manual smoke test: `docs/SMOKE_TEST.md`
- Codex integration: `docs/CODEX.md`
- Agent prompt snippets: `docs/AGENTS_SNIPPETS.md`

## Tools (MCP)

- `find_definition`, `find_definition_at`
- `find_references`, `find_references_at`
- `rename_symbol`, `rename_symbol_strict`
- `get_diagnostics`
- `restart_server`, `stop_server`

## Development

Run MCP server without installing:

```bash
cargo run -p lspi -- mcp --workspace-root .
```

Run doctor:

```bash
cargo run -p lspi -- doctor --workspace-root .
```

Run tests (recommended):

```bash
cargo nextest run
```

Format:

```bash
cargo fmt
```

## CI / Release

- CI runs on GitHub Actions (`.github/workflows/ci.yml`) with `cargo fmt --check`, `cargo clippy -D warnings`, and `cargo nextest`.
- Release automation is based on `cargo-dist` (`dist-workspace.toml`, `.github/workflows/release.yml`) and is triggered by version tags (e.g. `v0.1.0`).
