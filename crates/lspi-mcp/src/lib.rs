use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use rmcp::ErrorData as McpError;
use rmcp::ServiceExt;
use rmcp::handler::server::ServerHandler;
use rmcp::model::CallToolRequestParam;
use rmcp::model::CallToolResult;
use rmcp::model::Content;
use rmcp::model::JsonObject;
use rmcp::model::ListToolsResult;
use rmcp::model::PaginatedRequestParam;
use rmcp::model::ServerCapabilities;
use rmcp::model::ServerInfo;
use rmcp::model::Tool;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tracing::info;

mod handlers;
mod output;
mod routed_client;
mod routing;
mod tool_schemas;
mod tools;
mod workspace_edit;

use output::{effective_max_total_chars, enforce_global_output_caps};

pub async fn run_stdio() -> Result<()> {
    run_stdio_with_options(McpOptions::default()).await
}

#[derive(Debug, Clone, Default)]
pub struct McpOptions {
    pub config_path: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    pub warmup: bool,
    pub read_only: bool,
}

pub async fn run_stdio_with_options(options: McpOptions) -> Result<()> {
    let service = LspiMcpServer::new(options).await?;
    let running = service
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    running.waiting().await?;
    Ok(())
}

#[derive(Clone)]
struct LspiMcpServer {
    tools: Arc<Vec<Tool>>,
    state: Arc<LspiState>,
}

impl LspiMcpServer {
    async fn new(options: McpOptions) -> Result<Self> {
        let loaded = lspi_core::config::load_config(
            options.config_path.as_deref(),
            options.workspace_root.as_deref(),
        )?;
        let workspace_root = loaded.workspace_root;
        let servers = lspi_core::config::resolved_servers(&loaded.config, &workspace_root);
        let allowed_roots = compute_allowed_roots(&workspace_root, &servers);

        let all_tools = tools::all_tools();
        let cfg_read_only = loaded
            .config
            .mcp
            .as_ref()
            .and_then(|m| m.read_only)
            .unwrap_or(false);
        let read_only = options.read_only || cfg_read_only;

        let tools = tools::filter_tools_by_config(all_tools, loaded.config.mcp.as_ref());
        let tools = if read_only {
            tools::filter_tools_read_only(tools)
        } else {
            tools
        };

        let server = Self {
            tools: Arc::new(tools),
            state: Arc::new(LspiState {
                workspace_root,
                allowed_roots,
                read_only,
                config: loaded.config,
                servers,
                rust_analyzer: Mutex::new(HashMap::new()),
                omnisharp: Mutex::new(HashMap::new()),
                generic: Mutex::new(HashMap::new()),
            }),
        };

        if options.warmup {
            server.warmup_servers().await?;
        }

        server.start_idle_reaper_if_configured();

        Ok(server)
    }

    async fn warmup_servers(&self) -> Result<()> {
        for server in &self.state.servers {
            let kind = server.kind.trim().to_ascii_lowercase().replace('-', "_");
            if kind == "rust_analyzer" || kind == "rust" {
                info!(
                    "warmup: starting rust-analyzer server_id={} root_dir={}",
                    server.id,
                    server.root_dir.display()
                );
                let client = self
                    .rust_analyzer_for_server(server)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                let _ = client.wait_quiescent().await;
                continue;
            }

            if kind == "omnisharp" || kind == "csharp" {
                info!(
                    "warmup: starting omnisharp server_id={} root_dir={}",
                    server.id,
                    server.root_dir.display()
                );
                let _ = self
                    .omnisharp_for_server(server)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                if let Some(ms) = server.warmup_timeout_ms.filter(|ms| *ms > 0) {
                    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
                }
                continue;
            }

            if kind == "generic" {
                info!(
                    "warmup: starting generic server_id={} root_dir={}",
                    server.id,
                    server.root_dir.display()
                );
                let _ = self
                    .generic_for_server(server)
                    .await
                    .map_err(|e| anyhow!(e.to_string()))?;
                continue;
            }

            info!(
                "warmup: skipping unsupported server kind={} id={}",
                server.kind, server.id
            );
        }
        Ok(())
    }
}

impl ServerHandler for LspiMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
            ..ServerInfo::default()
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>> + Send + '_ {
        let tools = self.tools.clone();
        async move {
            Ok(ListToolsResult {
                tools: (*tools).clone(),
                next_cursor: None,
                meta: None,
            })
        }
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if self.state.read_only
            && matches!(
                request.name.as_ref(),
                "rename_symbol" | "rename_symbol_strict" | "restart_server" | "stop_server"
            )
        {
            let tool = request.name.as_ref();
            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Tool '{tool}' is disabled in read-only mode."
                ))],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": tool,
                    "message": "disabled in read-only mode",
                })),
                is_error: Some(true),
                meta: None,
            });
        }

        match request.name.as_ref() {
            "find_definition" => self.find_definition(request).await,
            "find_definition_at" => self.find_definition_at(request).await,
            "find_references" => self.find_references(request).await,
            "find_references_at" => self.find_references_at(request).await,
            "hover_at" => self.hover_at(request).await,
            "find_implementation_at" => self.find_implementation_at(request).await,
            "find_type_definition_at" => self.find_type_definition_at(request).await,
            "find_incoming_calls" => self.find_incoming_calls(request).await,
            "find_outgoing_calls" => self.find_outgoing_calls(request).await,
            "find_incoming_calls_at" => self.find_incoming_calls_at(request).await,
            "find_outgoing_calls_at" => self.find_outgoing_calls_at(request).await,
            "get_document_symbols" => self.get_document_symbols(request).await,
            "search_workspace_symbols" => self.search_workspace_symbols(request).await,
            "get_diagnostics" => self.get_diagnostics(request).await,
            "rename_symbol" => self.rename_symbol(request).await,
            "rename_symbol_strict" => self.rename_symbol_strict(request).await,
            "restart_server" => self.restart_server(request).await,
            "stop_server" => self.stop_server(request).await,
            other => Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Tool '{other}' is not implemented yet."
                ))],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": other,
                    "message": "not implemented yet"
                })),
                is_error: Some(true),
                meta: None,
            }),
        }
    }
}

struct ManagedClient<T> {
    client: Arc<T>,
    started_at: Instant,
    last_used: Instant,
}

impl<T> ManagedClient<T> {
    fn new(client: Arc<T>) -> Self {
        let now = Instant::now();
        Self {
            client,
            started_at: now,
            last_used: now,
        }
    }
}

struct LspiState {
    workspace_root: PathBuf,
    allowed_roots: Vec<PathBuf>,
    read_only: bool,
    config: lspi_core::config::LspiConfig,
    servers: Vec<lspi_core::config::ResolvedServerConfig>,
    rust_analyzer: Mutex<HashMap<String, ManagedClient<lspi_lsp::RustAnalyzerClient>>>,
    omnisharp: Mutex<HashMap<String, ManagedClient<lspi_lsp::OmniSharpClient>>>,
    generic: Mutex<HashMap<String, ManagedClient<lspi_lsp::GenericLspClient>>>,
}

fn compute_allowed_roots(
    workspace_root: &Path,
    servers: &[lspi_core::config::ResolvedServerConfig],
) -> Vec<PathBuf> {
    use std::collections::HashSet;

    let mut seen = HashSet::<PathBuf>::new();
    let mut out = Vec::<PathBuf>::new();

    let mut push = |p: PathBuf| {
        let canon = p.canonicalize().unwrap_or(p);
        if seen.insert(canon.clone()) {
            out.push(canon);
        }
    };

    push(workspace_root.to_path_buf());
    for s in servers {
        push(s.root_dir.clone());
        for wf in &s.workspace_folders {
            push(wf.clone());
        }
    }

    // Prefer the most specific roots first (useful for debugging and future tie-breaking).
    out.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    out
}

fn lsp_position_1based(pos: &lspi_lsp::LspPosition) -> Value {
    json!({
        "line": pos.line.saturating_add(1),
        "character": pos.character.saturating_add(1),
    })
}

fn lsp_range_1based(range: &lspi_lsp::LspRange) -> Value {
    json!({
        "start": lsp_position_1based(&range.start),
        "end": lsp_position_1based(&range.end),
    })
}

fn is_method_not_found_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("-32601") || msg.contains("method not found")
}

fn hover_to_text(value: &Value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }

    let contents = value.get("contents")?;
    match contents {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => {
            let mut parts = Vec::new();
            for item in arr {
                if let Some(s) = hover_content_item_to_text(item) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        parts.push(s);
                    }
                }
            }
            if parts.is_empty() {
                None
            } else {
                Some(parts.join("\n\n"))
            }
        }
        Value::Object(_) => hover_content_item_to_text(contents),
        _ => None,
    }
}

fn hover_content_item_to_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(obj) => {
            // MarkupContent: { kind: "markdown"|"plaintext", value: "..." }
            if let Some(v) = obj.get("value").and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            // MarkedString: { language: "...", value: "..." }
            if let Some(v) = obj.get("value").and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
            None
        }
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct FindDefinitionArgs {
    file_path: String,
    symbol_name: String,
    #[serde(default)]
    symbol_kind: Option<String>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    snippet_context_lines: Option<usize>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindDefinitionAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    snippet_context_lines: Option<usize>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindReferencesArgs {
    file_path: String,
    symbol_name: String,
    #[serde(default)]
    symbol_kind: Option<String>,
    #[serde(default)]
    include_declaration: Option<bool>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    snippet_context_lines: Option<usize>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindReferencesAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    include_declaration: Option<bool>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    snippet_context_lines: Option<usize>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct HoverAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindImplementationAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindTypeDefinitionAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindIncomingCallsArgs {
    file_path: String,
    symbol_name: String,
    #[serde(default)]
    symbol_kind: Option<String>,
    #[serde(default)]
    max_symbols: Option<usize>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindOutgoingCallsArgs {
    file_path: String,
    symbol_name: String,
    #[serde(default)]
    symbol_kind: Option<String>,
    #[serde(default)]
    max_symbols: Option<usize>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_snippet: Option<bool>,
    #[serde(default)]
    max_snippet_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindIncomingCallsAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct FindOutgoingCallsAtArgs {
    file_path: String,
    line: u32,
    character: u32,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GetDocumentSymbolsArgs {
    file_path: String,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct SearchWorkspaceSymbolsArgs {
    query: String,
    #[serde(default)]
    file_path: Option<String>,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct GetDiagnosticsArgs {
    file_path: String,
    #[serde(default)]
    max_results: Option<usize>,
    #[serde(default)]
    max_total_chars: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RenameSymbolArgs {
    file_path: String,
    symbol_name: String,
    #[serde(default)]
    symbol_kind: Option<String>,
    new_name: String,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    expected_before_sha256: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    create_backups: Option<bool>,
    #[serde(default)]
    backup_suffix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RenameSymbolStrictArgs {
    file_path: String,
    line: u32,
    character: u32,
    new_name: String,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    expected_before_sha256: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    create_backups: Option<bool>,
    #[serde(default)]
    backup_suffix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RestartServerArgs {
    #[serde(default)]
    extensions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct StopServerArgs {
    #[serde(default)]
    extensions: Option<Vec<String>>,
}

#[derive(Debug, serde::Serialize)]
struct LocationWithSnippet {
    file_path: String,
    uri: String,
    range: lspi_lsp::LspRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<lspi_core::snippet::Snippet>,
}

#[derive(Debug, serde::Serialize)]
struct DefinitionMatchOut {
    symbol: Value,
    definitions: Vec<LocationWithSnippet>,
}

#[derive(Debug, serde::Serialize)]
struct ReferenceMatchOut {
    symbol: Value,
    references: Vec<LocationWithSnippet>,
    truncated: bool,
}

async fn maybe_snippet_for_file_path(
    workspace_root: &Path,
    allowed_roots: &[PathBuf],
    file_path: &str,
    center_line: u32,
    context_lines: usize,
    max_chars: usize,
) -> anyhow::Result<Option<lspi_core::snippet::Snippet>> {
    let path = PathBuf::from(file_path);
    let abs = canonicalize_within(workspace_root, allowed_roots, &path).ok();
    let Some(abs) = abs else {
        return Ok(None);
    };

    let bytes = tokio::fs::read(&abs).await?;
    let text = String::from_utf8(bytes)?;
    Ok(Some(lspi_core::snippet::extract_snippet(
        &text,
        center_line,
        context_lines,
        max_chars,
    )?))
}

#[cfg(any())]
mod apply_workspace_edit_tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use url::Url;

    use crate::workspace_edit::apply_workspace_edit;

    fn file_uri(path: &Path) -> String {
        Url::from_file_path(path).unwrap().to_string()
    }

    fn expected_backup_path(path: &Path, suffix: &str) -> PathBuf {
        let file_name = path.file_name().unwrap().to_string_lossy();
        path.with_file_name(format!("{file_name}{suffix}"))
    }

    #[tokio::test]
    async fn apply_workspace_edit_happy_path_creates_backup_and_writes_file() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();
        let key = canonical.to_string_lossy().to_string();
        let original_bytes = tokio::fs::read(&canonical).await.unwrap();
        let before_sha256 = lspi_core::hashing::sha256_hex(&original_bytes);

        let mut expected = HashMap::new();
        expected.insert(key, before_sha256);

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let result = apply_workspace_edit(root, &changes, Some(&expected), true, ".bak")
            .await
            .unwrap();

        assert_eq!(result.files_modified.len(), 1);
        assert_eq!(result.backup_files.len(), 1);

        let new_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(new_text, "world\n");

        let backup_path = PathBuf::from(&result.backup_files[0]);
        let backup_text = tokio::fs::read_to_string(&backup_path).await.unwrap();
        assert_eq!(backup_text, "hello\n");
    }

    #[tokio::test]
    async fn apply_workspace_edit_rejects_sha256_mismatch_without_writing() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();
        let canonical = file_path.canonicalize().unwrap();

        let mut expected = HashMap::new();
        expected.insert(
            canonical.to_string_lossy().to_string(),
            "deadbeef".to_string(),
        );

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let err = apply_workspace_edit(root, &changes, Some(&expected), true, ".bak")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, ".bak");
        assert!(!backup_path.exists());
    }

    #[tokio::test]
    async fn apply_workspace_edit_rolls_back_and_removes_backup_on_apply_error() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 100,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 100,
                    character: 1,
                },
            },
            new_text: "x".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let _err = apply_workspace_edit(root, &changes, None, true, ".bak")
            .await
            .unwrap_err();

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, ".bak");
        assert!(!backup_path.exists());
    }

    #[tokio::test]
    async fn apply_workspace_edit_refuses_writes_outside_workspace_root() {
        let root_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();

        let root = root_dir.path();
        let outside_file = outside_dir.path().join("a.rs");
        tokio::fs::write(&outside_file, "hello\n").await.unwrap();

        let canonical_outside = outside_file.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical_outside), vec![edit]);

        let err = apply_workspace_edit(root, &changes, None, true, ".bak")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace root"));
    }

    #[tokio::test]
    async fn apply_workspace_edit_rejects_backup_suffix_with_path_separator() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();
        let canonical = file_path.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let err = apply_workspace_edit(root, &changes, None, true, "/../evil")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("backup_suffix"));

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, "/../evil");
        assert!(!backup_path.exists());
    }
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Option<JsonObject>,
) -> Result<T, McpError> {
    let Some(arguments) = arguments else {
        return Err(McpError::invalid_params("missing tool arguments", None));
    };
    serde_json::from_value::<T>(Value::Object(arguments.into_iter().collect()))
        .map_err(|e| McpError::invalid_params(e.to_string(), None))
}

fn canonicalize_within(
    workspace_root: &Path,
    allowed_roots: &[PathBuf],
    file_path: &Path,
) -> anyhow::Result<PathBuf> {
    let combined = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        workspace_root.join(file_path)
    };

    let file = combined
        .canonicalize()
        .with_context(|| format!("failed to canonicalize file path: {combined:?}"))?;

    if !allowed_roots.iter().any(|root| file.starts_with(root)) {
        return Err(anyhow::anyhow!(
            "file_path is outside allowed roots (workspace_root={:?}, file_path={:?})",
            workspace_root,
            file,
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn canonicalize_within_rejects_paths_outside_root() {
        let root_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();

        let root = root_dir.path();
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let allowed_roots = vec![root_canon];
        let outside_file = outside_dir.path().join("x.rs");
        std::fs::write(&outside_file, "fn main() {}\n").unwrap();

        let err = canonicalize_within(root, &allowed_roots, &outside_file).unwrap_err();
        assert!(err.to_string().contains("outside allowed roots"));
    }

    #[test]
    fn canonicalize_within_accepts_paths_inside_additional_root() {
        let root_dir = tempdir().unwrap();
        let extra_dir = tempdir().unwrap();

        let root = root_dir.path();
        let extra = extra_dir.path();
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let extra_canon = extra.canonicalize().unwrap_or_else(|_| extra.to_path_buf());
        let allowed_roots = vec![root_canon, extra_canon.clone()];

        let extra_file = extra.join("x.rs");
        std::fs::write(&extra_file, "fn main() {}\n").unwrap();

        let abs = canonicalize_within(root, &allowed_roots, &extra_file).unwrap();
        assert!(abs.starts_with(&extra_canon));
    }
}
