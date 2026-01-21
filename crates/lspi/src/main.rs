use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use tokio::process::Command as TokioCommand;

fn is_rust_analyzer_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "rust_analyzer" || normalized == "rust"
}

fn is_omnisharp_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "omnisharp" || normalized == "csharp"
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
        /// Detect Rust/C# projects and generate a tailored config (best-effort)
        #[arg(long)]
        wizard: bool,
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

            let mut failures = Vec::<String>::new();
            for s in servers {
                if !is_rust_analyzer_kind(&s.kind) {
                    if is_omnisharp_kind(&s.kind) {
                        let command = match s.command.as_deref() {
                            Some(c) if !c.trim().is_empty() => c.to_string(),
                            _ => lspi_lsp::resolve_omnisharp_command().await?,
                        };

                        println!(
                            "server_preflight: id={} kind={} command={}",
                            s.id, s.kind, command
                        );

                        if let Err(err) = lspi_lsp::preflight_omnisharp(&command).await {
                            eprintln!("doctor_error: id={} kind={} error={:#}", s.id, s.kind, err);
                            eprintln!(
                                "doctor_hint: Install OmniSharp and ensure `omnisharp` is on PATH, or set LSPI_OMNISHARP_COMMAND."
                            );
                            eprintln!(
                                "doctor_hint: On Windows, OmniSharp often ships with editor extensions (e.g. VS Code C#). You may need to expose the OmniSharp binary as `omnisharp`."
                            );
                            eprintln!(
                                "doctor_hint: Also ensure `dotnet` is installed (OmniSharp depends on a .NET runtime/SDK)."
                            );
                            eprintln!("doctor_hint: Check: `dotnet --info`");
                            failures
                                .push(format!("omnisharp preflight failed for server id={}", s.id));
                            continue;
                        }

                        let output = TokioCommand::new(&command).arg("--version").output().await;
                        if let Ok(output) = output {
                            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                            if !stdout.is_empty() {
                                println!("server_version: id={} {stdout}", s.id);
                            } else if !stderr.is_empty() {
                                println!("server_version: id={} {stderr}", s.id);
                            } else {
                                println!("server_version: id={} <unknown>", s.id);
                            }
                        } else {
                            println!("server_version: id={} <unknown>", s.id);
                        }

                        let dotnet_ok = TokioCommand::new("dotnet")
                            .arg("--info")
                            .output()
                            .await
                            .is_ok();
                        if !dotnet_ok {
                            eprintln!(
                                "doctor_hint: `dotnet` was not found. Install .NET SDK and retry."
                            );
                        }

                        continue;
                    }

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
                if let Err(err) = lspi_lsp::preflight_rust_analyzer(&command).await {
                    eprintln!("doctor_error: id={} kind={} error={:#}", s.id, s.kind, err);
                    eprintln!(
                        "doctor_hint: Install rust-analyzer via `rustup component add rust-analyzer`, or set LSPI_RUST_ANALYZER_COMMAND."
                    );
                    failures.push(format!(
                        "rust-analyzer preflight failed for server id={}",
                        s.id
                    ));
                    continue;
                }

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

            if !failures.is_empty() {
                anyhow::bail!(
                    "doctor failed for {} server(s). See stderr for details.",
                    failures.len()
                );
            }

            Ok(())
        }
        Command::Setup {
            workspace_root,
            output,
            write,
            force,
            wizard,
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

            let servers_block = if wizard {
                generate_wizard_servers(&workspace_root)
            } else {
                default_servers_block()
            };

            let template = format!(
                r#"# lspi config (TOML)
#
# This file is discovered by lspi when present in:
# - .lspi/config.toml (recommended)
# - lspi.toml
#
# For full schema, see docs/CONFIG.md.

{servers_block}

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
                println!("# 1) Verify servers: lspi doctor --workspace-root .");
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

fn default_servers_block() -> String {
    r#"
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

## C# (OmniSharp) example:
# [[servers]]
# id = "omnisharp"
# kind = "omnisharp"
# extensions = ["cs"]
# # root_dir = "."
# # command = "omnisharp"
# args = ["-lsp"]
# initialize_timeout_ms = 10000
# request_timeout_ms = 30000
# warmup_timeout_ms = 0
"#
    .trim()
    .to_string()
}

#[derive(Debug, Default)]
struct DetectedProjects {
    rust_root: Option<PathBuf>,
    csharp_root: Option<PathBuf>,
    csharp_kind: Option<&'static str>, // "sln" or "csproj"
}

fn generate_wizard_servers(workspace_root: &Path) -> String {
    let detected = detect_projects(workspace_root, 4, 20_000);
    let mut blocks = Vec::new();

    if let Some(rust_root) = detected.rust_root.as_deref() {
        blocks.push(server_block_rust(workspace_root, rust_root));
    }

    if let Some(csharp_root) = detected.csharp_root.as_deref() {
        blocks.push(server_block_omnisharp(workspace_root, csharp_root));
    }

    if blocks.is_empty() {
        return default_servers_block();
    }

    let mut out = String::new();
    out.push_str("# Generated by `lspi setup --wizard`\n");
    if detected.rust_root.is_some() {
        out.push_str("# - Detected: Rust (Cargo)\n");
    }
    if detected.csharp_root.is_some() {
        let kind = detected.csharp_kind.unwrap_or("csharp");
        out.push_str(&format!("# - Detected: C# ({kind})\n"));
    }
    out.push('\n');
    out.push_str(&blocks.join("\n\n"));
    out
}

fn server_block_rust(workspace_root: &Path, root_dir: &Path) -> String {
    let root_dir_str = path_to_toml_relative(workspace_root, root_dir);
    format!(
        r#"[[servers]]
id = "rust-analyzer"
kind = "rust_analyzer"
extensions = ["rs"]
root_dir = "{root_dir_str}"
initialize_timeout_ms = 10000
request_timeout_ms = 30000
warmup_timeout_ms = 5000"#,
    )
}

fn server_block_omnisharp(workspace_root: &Path, root_dir: &Path) -> String {
    let root_dir_str = path_to_toml_relative(workspace_root, root_dir);
    format!(
        r#"[[servers]]
id = "omnisharp"
kind = "omnisharp"
extensions = ["cs"]
root_dir = "{root_dir_str}"
args = ["-lsp"]
initialize_timeout_ms = 10000
request_timeout_ms = 30000
warmup_timeout_ms = 0"#,
    )
}

fn path_to_toml_relative(workspace_root: &Path, dir: &Path) -> String {
    let root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());

    if dir == root {
        return ".".to_string();
    }

    let rel = dir.strip_prefix(&root).unwrap_or(&dir);
    let mut parts = Vec::new();
    for c in rel.components() {
        let s = c.as_os_str().to_string_lossy();
        if s.is_empty() {
            continue;
        }
        parts.push(s.to_string());
    }
    parts.join("/")
}

fn detect_projects(
    workspace_root: &Path,
    max_depth: usize,
    max_entries: usize,
) -> DetectedProjects {
    let mut detected = DetectedProjects::default();

    let mut q = VecDeque::new();
    q.push_back((workspace_root.to_path_buf(), 0usize));

    let mut scanned = 0usize;

    while let Some((dir, depth)) = q.pop_front() {
        if scanned >= max_entries {
            break;
        }
        if depth > max_depth {
            continue;
        }

        let base = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(
            base,
            ".git" | "target" | "node_modules" | "repo-ref" | ".lspi"
        ) {
            continue;
        }

        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            scanned += 1;
            if scanned >= max_entries {
                break;
            }

            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                q.push_back((path, depth + 1));
                continue;
            }

            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if name.eq_ignore_ascii_case("Cargo.toml") {
                detected.rust_root.get_or_insert(dir.clone());
            }

            let ext = path.extension().and_then(|s| s.to_str());
            if detected.csharp_root.is_none()
                && ext.map(|s| s.eq_ignore_ascii_case("sln")).unwrap_or(false)
            {
                detected.csharp_root = Some(dir.clone());
                detected.csharp_kind = Some("sln");
            } else if detected.csharp_root.is_none()
                && ext
                    .map(|s| s.eq_ignore_ascii_case("csproj"))
                    .unwrap_or(false)
            {
                detected.csharp_root = Some(dir.clone());
                detected.csharp_kind = Some("csproj");
            }

            if detected.rust_root.is_some() && detected.csharp_root.is_some() {
                return detected;
            }
        }
    }

    detected
}
