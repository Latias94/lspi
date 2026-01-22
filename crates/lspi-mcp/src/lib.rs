use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        let servers = lspi_core::config::resolved_servers(&loaded.config, &loaded.workspace_root);

        let all_tools = tools::all_tools();
        let tools = tools::filter_tools_by_config(all_tools, loaded.config.mcp.as_ref());

        let server = Self {
            tools: Arc::new(tools),
            state: Arc::new(LspiState {
                workspace_root: loaded.workspace_root,
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

    fn start_idle_reaper_if_configured(&self) {
        let mut idle_policies = HashMap::<String, (String, Duration)>::new();
        for s in &self.state.servers {
            let Some(ms) = s.idle_shutdown_ms.filter(|ms| *ms > 0) else {
                continue;
            };
            idle_policies.insert(s.id.clone(), (s.kind.clone(), Duration::from_millis(ms)));
        }

        if idle_policies.is_empty() {
            return;
        }

        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;

                let now = Instant::now();
                let mut to_shutdown_ra: Vec<(String, ManagedClient<lspi_lsp::RustAnalyzerClient>)> =
                    Vec::new();
                let mut to_shutdown_os: Vec<(String, ManagedClient<lspi_lsp::OmniSharpClient>)> =
                    Vec::new();
                let mut to_shutdown_generic: Vec<(
                    String,
                    ManagedClient<lspi_lsp::GenericLspClient>,
                )> = Vec::new();

                for (id, (kind, idle)) in idle_policies.iter() {
                    if is_rust_analyzer_kind(kind) {
                        let removed = {
                            let mut guard = state.rust_analyzer.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_ra.push(r);
                        }
                        continue;
                    }

                    if is_omnisharp_kind(kind) {
                        let removed = {
                            let mut guard = state.omnisharp.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_os.push(r);
                        }
                        continue;
                    }

                    if is_generic_kind(kind) || is_pyright_kind(kind) {
                        let removed = {
                            let mut guard = state.generic.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_generic.push(r);
                        }
                        continue;
                    }
                }

                for (id, entry) in to_shutdown_ra {
                    if let Err(entry) = shutdown_rust_analyzer_managed(entry).await {
                        let mut guard = state.rust_analyzer.lock().await;
                        guard.insert(id, entry);
                    }
                }

                for (id, entry) in to_shutdown_os {
                    if let Err(entry) = shutdown_omnisharp_managed(entry).await {
                        let mut guard = state.omnisharp.lock().await;
                        guard.insert(id, entry);
                    }
                }

                for (id, entry) in to_shutdown_generic {
                    if let Err(entry) = shutdown_generic_managed(entry).await {
                        let mut guard = state.generic.lock().await;
                        guard.insert(id, entry);
                    }
                }
            }
        });
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
    config: lspi_core::config::LspiConfig,
    servers: Vec<lspi_core::config::ResolvedServerConfig>,
    rust_analyzer: Mutex<HashMap<String, ManagedClient<lspi_lsp::RustAnalyzerClient>>>,
    omnisharp: Mutex<HashMap<String, ManagedClient<lspi_lsp::OmniSharpClient>>>,
    generic: Mutex<HashMap<String, ManagedClient<lspi_lsp::GenericLspClient>>>,
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

enum RoutedClient {
    Rust {
        server_id: String,
        client: Arc<lspi_lsp::RustAnalyzerClient>,
    },
    OmniSharp {
        server_id: String,
        client: Arc<lspi_lsp::OmniSharpClient>,
    },
    Generic {
        server_id: String,
        client: Arc<lspi_lsp::GenericLspClient>,
    },
}

impl RoutedClient {
    fn server_id(&self) -> &str {
        match self {
            RoutedClient::Rust { server_id, .. } => server_id,
            RoutedClient::OmniSharp { server_id, .. } => server_id,
            RoutedClient::Generic { server_id, .. } => server_id,
        }
    }

    async fn find_definition_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::DefinitionMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
        }
    }

    async fn definition_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_definitions: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
        }
    }

    async fn find_references_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        include_declaration: bool,
        max_symbols: usize,
        max_references: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ReferenceMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
        }
    }

    async fn references_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        include_declaration: bool,
        max_references: usize,
    ) -> anyhow::Result<(Vec<lspi_lsp::ResolvedLocation>, bool)> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
        }
    }

    async fn implementation_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
        }
    }

    async fn type_definition_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
        }
    }

    async fn incoming_calls_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<lspi_lsp::CallHierarchyIncomingResult> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
        }
    }

    async fn outgoing_calls_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<lspi_lsp::CallHierarchyOutgoingResult> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
        }
    }

    async fn hover_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
    ) -> anyhow::Result<Value> {
        match self {
            RoutedClient::Rust { client, .. } => client.hover_at(file_path, position).await,
            RoutedClient::OmniSharp { client, .. } => client.hover_at(file_path, position).await,
            RoutedClient::Generic { client, .. } => client.hover_at(file_path, position).await,
        }
    }

    async fn document_symbols(
        &self,
        file_path: &Path,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedSymbol>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
            RoutedClient::Generic { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
        }
    }

    async fn workspace_symbols(
        &self,
        query: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::WorkspaceSymbolMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => client.workspace_symbols(query, max_results).await,
            RoutedClient::OmniSharp { client, .. } => {
                client.workspace_symbols(query, max_results).await
            }
            RoutedClient::Generic { client, .. } => {
                client.workspace_symbols(query, max_results).await
            }
        }
    }

    async fn get_diagnostics(
        &self,
        file_path: &Path,
        max_wait: std::time::Duration,
    ) -> anyhow::Result<Vec<lspi_lsp::LspDiagnostic>> {
        match self {
            RoutedClient::Rust { client, .. } => client.get_diagnostics(file_path, max_wait).await,
            RoutedClient::OmniSharp { client, .. } => {
                client.get_diagnostics(file_path, max_wait).await
            }
            RoutedClient::Generic { client, .. } => {
                client.get_diagnostics(file_path, max_wait).await
            }
        }
    }

    async fn list_symbol_candidates(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::RenameCandidate>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
        }
    }

    async fn rename_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        new_name: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
            RoutedClient::Generic { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
        }
    }

    async fn rename_at_prepared(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        new_name: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
        }
    }
}

impl LspiMcpServer {
    async fn client_for_file(&self, abs_file: &Path) -> Result<RoutedClient, McpError> {
        let Some(server) = lspi_core::config::route_server_by_path(abs_file, &self.state.servers)
        else {
            let ext = abs_file
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("<none>");
            return Err(McpError::invalid_params(
                format!("no configured LSP server matches file extension: {ext}"),
                None,
            ));
        };

        self.client_for_server(server).await
    }

    async fn client_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<RoutedClient, McpError> {
        if is_rust_analyzer_kind(&server.kind) {
            let client = self.rust_analyzer_for_server(server).await?;
            return Ok(RoutedClient::Rust {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_omnisharp_kind(&server.kind) {
            let client = self.omnisharp_for_server(server).await?;
            return Ok(RoutedClient::OmniSharp {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_pyright_kind(&server.kind) {
            let client = self.pyright_for_server(server).await?;
            return Ok(RoutedClient::Generic {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_generic_kind(&server.kind) {
            let client = self.generic_for_server(server).await?;
            return Ok(RoutedClient::Generic {
                server_id: server.id.clone(),
                client,
            });
        }

        Err(McpError::invalid_params(
            format!(
                "server kind is not supported yet: id={} kind={}",
                server.id, server.kind
            ),
            None,
        ))
    }

    async fn rust_analyzer_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::RustAnalyzerClient>, McpError> {
        let now = Instant::now();

        // Fast path: reuse running server unless restart policy triggers.
        let restart_old = {
            let mut guard = self.state.rust_analyzer.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_rust_analyzer_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    // Server is busy; keep the existing instance to avoid leaking a subprocess.
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.rust_analyzer.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = match server.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => lspi_lsp::resolve_rust_analyzer_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };
        lspi_lsp::preflight_rust_analyzer(&command)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let request_timeout = server
            .request_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);
        let warmup_timeout = server
            .warmup_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(5));

        let client = lspi_lsp::RustAnalyzerClient::start(lspi_lsp::RustAnalyzerClientOptions {
            command,
            args: server.args.clone(),
            cwd: server.root_dir.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            warmup_timeout,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.rust_analyzer.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_rust_analyzer_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    async fn omnisharp_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::OmniSharpClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.omnisharp.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_omnisharp_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.omnisharp.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = match server.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => lspi_lsp::resolve_omnisharp_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };
        lspi_lsp::preflight_omnisharp(&command)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let request_timeout = server
            .request_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);

        // OmniSharp does not implement rust-analyzer's serverStatus notifications, so a
        // long per-request warmup wait would be counterproductive. Use a small optional delay
        // after didOpen instead.
        let warmup_delay = server
            .warmup_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_millis(0));

        let args = if server.args.is_empty() {
            vec!["-lsp".to_string()]
        } else {
            server.args.clone()
        };

        let client = lspi_lsp::OmniSharpClient::start(lspi_lsp::OmniSharpClientOptions {
            command,
            args,
            cwd: server.root_dir.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.omnisharp.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_omnisharp_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    async fn generic_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::GenericLspClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.generic.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_generic_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.generic.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = match server.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => {
                return Err(McpError::invalid_params(
                    format!(
                        "generic server requires an explicit command: id={} kind={}",
                        server.id, server.kind
                    ),
                    None,
                ));
            }
        };

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(10));
        let request_timeout = server
            .request_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);
        let warmup_delay = server
            .warmup_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_millis(0));

        let language_id = server
            .language_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| guess_language_id_from_extensions(&server.extensions));

        let client = lspi_lsp::GenericLspClient::start(lspi_lsp::GenericLspClientOptions {
            command,
            args: server.args.clone(),
            cwd: server.root_dir.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            language_id,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.generic.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_generic_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    async fn pyright_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::GenericLspClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.generic.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_generic_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.generic.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let normalized_kind = server.kind.trim().to_ascii_lowercase().replace('-', "_");
        let command = match server.command.as_deref().filter(|c| !c.trim().is_empty()) {
            Some(c) => c.to_string(),
            None if normalized_kind == "basedpyright" => lspi_lsp::resolve_basedpyright_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            None => lspi_lsp::resolve_pyright_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };

        if let Err(err) = lspi_lsp::preflight_pyright(&command).await {
            return Err(McpError::invalid_params(
                format!("pyright preflight failed for command={command}: {err:#}"),
                None,
            ));
        }

        let args = if server.args.is_empty() {
            vec!["--stdio".to_string()]
        } else {
            server.args.clone()
        };

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(20));
        let request_timeout = server
            .request_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_secs(30));

        let mut overrides_ms = pyright_default_request_timeout_overrides_ms();
        overrides_ms.extend(server.request_timeout_overrides_ms.clone());
        let request_timeout_overrides = request_timeout_overrides_to_durations(&overrides_ms);

        let warmup_delay = server
            .warmup_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or_else(|| std::time::Duration::from_millis(0));

        let language_id = server
            .language_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "python".to_string());

        let client = lspi_lsp::GenericLspClient::start(lspi_lsp::GenericLspClientOptions {
            command,
            args,
            cwd: server.root_dir.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            language_id,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.generic.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_generic_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }
}

fn is_rust_analyzer_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "rust_analyzer" || normalized == "rust"
}

fn is_omnisharp_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "omnisharp" || normalized == "csharp"
}

fn is_generic_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "generic" || normalized == "lsp"
}

fn is_pyright_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "pyright" || normalized == "basedpyright"
}

fn guess_language_id_from_extensions(extensions: &[String]) -> String {
    let Some(first) = extensions.first() else {
        return "plaintext".to_string();
    };

    let ext = first.trim().trim_start_matches('.').to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "cs" => "csharp",
        "ts" => "typescript",
        "tsx" => "typescriptreact",
        "js" => "javascript",
        "jsx" => "javascriptreact",
        "py" => "python",
        "go" => "go",
        "c" => "c",
        "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" => "cpp",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "json" => "json",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        _ => "plaintext",
    }
    .to_string()
}

fn pyright_default_request_timeout_overrides_ms() -> std::collections::HashMap<String, u64> {
    [
        ("textDocument/definition", 45_000),
        ("textDocument/references", 60_000),
        ("textDocument/rename", 60_000),
        ("textDocument/documentSymbol", 45_000),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

fn request_timeout_overrides_to_durations(
    overrides_ms: &std::collections::HashMap<String, u64>,
) -> std::collections::HashMap<String, std::time::Duration> {
    overrides_ms
        .iter()
        .filter_map(|(k, v)| {
            let key = k.trim();
            if key.is_empty() || *v == 0 {
                return None;
            }
            Some((key.to_string(), std::time::Duration::from_millis(*v)))
        })
        .collect()
}

fn should_restart(
    now: Instant,
    started_at: Instant,
    restart_interval_minutes: Option<u64>,
) -> bool {
    let Some(minutes) = restart_interval_minutes.filter(|m| *m > 0) else {
        return false;
    };
    now.duration_since(started_at) >= Duration::from_secs(minutes.saturating_mul(60))
}

async fn shutdown_rust_analyzer_arc(
    mut arc: Arc<lspi_lsp::RustAnalyzerClient>,
) -> Result<(), Arc<lspi_lsp::RustAnalyzerClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_omnisharp_arc(
    mut arc: Arc<lspi_lsp::OmniSharpClient>,
) -> Result<(), Arc<lspi_lsp::OmniSharpClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_generic_arc(
    mut arc: Arc<lspi_lsp::GenericLspClient>,
) -> Result<(), Arc<lspi_lsp::GenericLspClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_rust_analyzer_managed(
    entry: ManagedClient<lspi_lsp::RustAnalyzerClient>,
) -> Result<(), ManagedClient<lspi_lsp::RustAnalyzerClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_rust_analyzer_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
}

async fn shutdown_omnisharp_managed(
    entry: ManagedClient<lspi_lsp::OmniSharpClient>,
) -> Result<(), ManagedClient<lspi_lsp::OmniSharpClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_omnisharp_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
}

async fn shutdown_generic_managed(
    entry: ManagedClient<lspi_lsp::GenericLspClient>,
) -> Result<(), ManagedClient<lspi_lsp::GenericLspClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_generic_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
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
    file_path: &str,
    center_line: u32,
    context_lines: usize,
    max_chars: usize,
) -> anyhow::Result<Option<lspi_core::snippet::Snippet>> {
    let path = PathBuf::from(file_path);
    let abs = canonicalize_within(workspace_root, &path).ok();
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

fn canonicalize_within(workspace_root: &Path, file_path: &Path) -> anyhow::Result<PathBuf> {
    let root = workspace_root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize workspace root: {workspace_root:?}"))?;

    let combined = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        root.join(file_path)
    };

    let file = combined
        .canonicalize()
        .with_context(|| format!("failed to canonicalize file path: {combined:?}"))?;

    if !file.starts_with(&root) {
        return Err(anyhow::anyhow!(
            "file_path is outside workspace_root (workspace_root={:?}, file_path={:?})",
            root,
            file
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
        let outside_file = outside_dir.path().join("x.rs");
        std::fs::write(&outside_file, "fn main() {}\n").unwrap();

        let err = canonicalize_within(root, &outside_file).unwrap_err();
        assert!(err.to_string().contains("outside workspace_root"));
    }
}
