use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::process::Command as TokioCommand;

fn is_rust_analyzer_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "rust_analyzer" || normalized == "rust"
}

#[derive(Debug, Parser)]
#[command(name = "lspi")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run MCP server over stdio (for Codex/Claude Code/etc.)
    Mcp {
        /// Optional path to `lspi` config file (.toml or .json)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override workspace root (defaults to config or current directory)
        #[arg(long)]
        workspace_root: Option<PathBuf>,
    },
    /// Print environment/config diagnostics for lspi
    Doctor {
        /// Optional path to `lspi` config file (.toml or .json)
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override workspace root (defaults to config or current directory)
        #[arg(long)]
        workspace_root: Option<PathBuf>,
    },
    /// Generate a starter `.lspi/config.toml` for this workspace (prints by default)
    Setup {
        /// Workspace root to generate config for (defaults to current directory)
        #[arg(long)]
        workspace_root: Option<PathBuf>,
        /// Output path (defaults to `<workspace_root>/.lspi/config.toml`)
        #[arg(long)]
        output: Option<PathBuf>,
        /// Write the config file (otherwise prints to stdout)
        #[arg(long)]
        write: bool,
        /// Overwrite existing config file when `--write` is set
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    match args.command {
        Command::Mcp {
            config,
            workspace_root,
        } => {
            lspi_mcp::run_stdio_with_options(lspi_mcp::McpOptions {
                config_path: config,
                workspace_root,
            })
            .await
        }
        Command::Doctor {
            config,
            workspace_root,
        } => {
            let loaded =
                lspi_core::config::load_config(config.as_deref(), workspace_root.as_deref())?;

            println!("config_source: {:?}", loaded.source);
            println!("workspace_root: {}", loaded.workspace_root.display());

            let servers =
                lspi_core::config::resolved_servers(&loaded.config, &loaded.workspace_root);
            println!("servers.count: {}", servers.len());
            for (idx, s) in servers.iter().enumerate() {
                println!("server[{idx}].id: {}", s.id);
                println!("server[{idx}].kind: {}", s.kind);
                println!("server[{idx}].root_dir: {}", s.root_dir.display());
                println!("server[{idx}].extensions: {:?}", s.extensions);
                println!("server[{idx}].command: {:?}", s.command);
                println!("server[{idx}].args: {:?}", s.args);
                println!(
                    "server[{idx}].timeouts_ms: initialize={:?} request={:?} warmup={:?}",
                    s.initialize_timeout_ms, s.request_timeout_ms, s.warmup_timeout_ms
                );
            }

            if let Some(mcp) = loaded.config.mcp.as_ref().and_then(|m| m.output.as_ref()) {
                println!(
                    "mcp.output.max_total_chars: default={:?} hard={:?}",
                    mcp.max_total_chars_default, mcp.max_total_chars_hard
                );
            } else {
                println!("mcp.output: <not configured>");
            }

            for s in servers {
                if !is_rust_analyzer_kind(&s.kind) {
                    println!(
                        "server_preflight: id={} kind={} <unsupported>",
                        s.id, s.kind
                    );
                    continue;
                }

                let command = match s.command.as_deref() {
                    Some(c) if !c.trim().is_empty() => c.to_string(),
                    _ => lspi_lsp::resolve_rust_analyzer_command().await?,
                };

                println!(
                    "server_preflight: id={} kind={} command={}",
                    s.id, s.kind, command
                );
                lspi_lsp::preflight_rust_analyzer(&command).await?;

                let output = TokioCommand::new(&command)
                    .arg("--version")
                    .output()
                    .await?;
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if !stdout.is_empty() {
                    println!("server_version: id={} {stdout}", s.id);
                } else if !stderr.is_empty() {
                    println!("server_version: id={} {stderr}", s.id);
                } else {
                    println!("server_version: id={} <unknown>", s.id);
                }
            }

            Ok(())
        }
        Command::Setup {
            workspace_root,
            output,
            write,
            force,
        } => {
            let workspace_root = workspace_root
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
            let workspace_root = workspace_root.canonicalize().unwrap_or(workspace_root);

            let output_path =
                output.unwrap_or_else(|| workspace_root.join(".lspi").join("config.toml"));
            let output_path = if output_path.is_absolute() {
                output_path
            } else {
                workspace_root.join(output_path)
            };

            let template = format!(
                r#"# lspi config (TOML)
#
# This file is discovered by lspi when present in:
# - .lspi/config.toml (recommended)
# - lspi.toml
#
# For full schema, see docs/CONFIG.md.

[[servers]]
id = "rust-analyzer"
kind = "rust_analyzer"
extensions = ["rs"]
# root_dir = "."
# command = "rust-analyzer"
# args = []
initialize_timeout_ms = 10000
request_timeout_ms = 30000
warmup_timeout_ms = 5000

[mcp.output]
max_total_chars_default = 120000
max_total_chars_hard = 2000000
"#
            );

            if !write {
                println!("# Would write to: {}", output_path.display());
                println!();
                print!("{template}");
                println!();
                println!("# Next steps:");
                println!("# 1) Verify rust-analyzer: lspi doctor --workspace-root .");
                println!("# 2) Configure Codex MCP (paste into ~/.codex/config.toml):");
                println!("#");
                println!("# [mcp_servers.lspi]");
                println!("# command = \"lspi\"");
                println!("# args = [\"mcp\", \"--workspace-root\", \".\"]");
                println!("#");
                println!("# 3) More details: docs/CODEX.md");
                return Ok(());
            }

            if output_path.exists() && !force {
                anyhow::bail!(
                    "refusing to overwrite existing file: {} (use --force)",
                    output_path.display()
                );
            }

            if let Some(parent) = output_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&output_path, template.as_bytes()).await?;

            println!("wrote: {}", output_path.display());
            println!(
                "next: lspi doctor --workspace-root {}",
                workspace_root.display()
            );
            println!("codex: paste into ~/.codex/config.toml:");
            println!("[mcp_servers.lspi]");
            println!("command = \"lspi\"");
            println!("args = [\"mcp\", \"--workspace-root\", \".\"]");
            println!("details: docs/CODEX.md");
            Ok(())
        }
    }
}
