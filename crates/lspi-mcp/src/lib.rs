use std::borrow::Cow;
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
use tracing::{info, warn};
use url::Url;

mod output;
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

    async fn find_definition(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindDefinitionArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(20).clamp(1, 200);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(true);
        let snippet_context_lines = args.snippet_context_lines.unwrap_or(1).min(10);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(400).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let matches = routed
            .find_definition_by_name(&abs_file, &args.symbol_name, kind_num, max_results)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let root = self
            .state
            .workspace_root
            .canonicalize()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut results = Vec::new();
        let abs_uri = Url::from_file_path(&abs_file)
            .ok()
            .map(|u| u.to_string())
            .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));
        for m in matches {
            let mut defs = Vec::new();
            for d in m.definitions {
                let snippet = if include_snippet {
                    match maybe_snippet_for_file_path(
                        &root,
                        &d.file_path,
                        d.range.start.line,
                        snippet_context_lines,
                        max_snippet_chars,
                    )
                    .await
                    {
                        Ok(Some(s)) => {
                            snippet_truncated |= s.truncated;
                            Some(s)
                        }
                        Ok(None) => {
                            snippet_skipped += 1;
                            None
                        }
                        Err(_) => {
                            snippet_skipped += 1;
                            None
                        }
                    }
                } else {
                    None
                };
                defs.push(LocationWithSnippet {
                    file_path: d.file_path,
                    uri: d.uri,
                    range: d.range,
                    snippet,
                });
            }
            let mut symbol_value = serde_json::to_value(&m.symbol).unwrap_or(Value::Null);
            if let Some(obj) = symbol_value.as_object_mut() {
                obj.insert(
                    "document_file_path".to_string(),
                    Value::String(abs_file.to_string_lossy().to_string()),
                );
                obj.insert("document_uri".to_string(), Value::String(abs_uri.clone()));
                obj.insert(
                    "range_1based".to_string(),
                    lsp_range_1based(&m.symbol.range),
                );
                obj.insert(
                    "selection_range_1based".to_string(),
                    lsp_range_1based(&m.symbol.selection_range),
                );
                obj.insert(
                    "selection_start_1based".to_string(),
                    lsp_position_1based(&m.symbol.selection_range.start),
                );
            }
            results.push(DefinitionMatchOut {
                symbol: symbol_value,
                definitions: defs,
            });
        }

        let definitions_count: usize = results.iter().map(|m| m.definitions.len()).sum();
        if results.is_empty() {
            warn!(
                "no symbol matches for '{}' in {:?}",
                args.symbol_name, abs_file
            );
        }

        let mut warnings = Vec::<Value>::new();
        if results.len() > 1 {
            warnings.push(json!({
                "kind": "multiple_symbol_matches",
                "message": "Multiple symbols matched; consider using find_definition_at for disambiguation.",
                "count": results.len()
            }));
        }
        if include_snippet && snippet_skipped > 0 {
            warnings.push(json!({
                "kind": "snippet_skipped",
                "message": "Some snippets were skipped (non-file URIs or outside workspace).",
                "count": snippet_skipped
            }));
        }
        if include_snippet && snippet_truncated {
            warnings.push(json!({
                "kind": "snippet_truncated",
                "message": "Some snippets were truncated due to max_snippet_chars."
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_definition",
            "server_id": server_id,
            "needs_disambiguation": results.len() > 1,
            "input": {
                "file_path": args.file_path,
                "symbol_name": args.symbol_name,
                "symbol_kind": args.symbol_kind,
                "max_results": max_results,
                "max_total_chars": max_total_chars,
                "include_snippet": include_snippet,
                "snippet_context_lines": snippet_context_lines,
                "max_snippet_chars": max_snippet_chars
            },
            "symbol_matches": results.len(),
            "definition_locations": definitions_count,
            "results": results,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} matching symbols and {} definition locations.",
                results.len(),
                definitions_count
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_definition_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindDefinitionAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(50).clamp(1, 500);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(true);
        let snippet_context_lines = args.snippet_context_lines.unwrap_or(1).min(10);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(400).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut definitions: Option<Vec<lspi_lsp::ResolvedLocation>> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .definition_at(&abs_file, pos.clone(), max_results)
                .await
            {
                Ok(d) => {
                    used_pos = Some(pos);
                    if !d.is_empty() {
                        definitions = Some(d);
                        break;
                    }
                    definitions = Some(d);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(definitions) = definitions else {
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Definition lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_definition_at",
                    "message": "definition lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let root = self
            .state
            .workspace_root
            .canonicalize()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut defs = Vec::new();
        for d in definitions {
            let snippet = if include_snippet {
                match maybe_snippet_for_file_path(
                    &root,
                    &d.file_path,
                    d.range.start.line,
                    snippet_context_lines,
                    max_snippet_chars,
                )
                .await
                {
                    Ok(Some(s)) => {
                        snippet_truncated |= s.truncated;
                        Some(s)
                    }
                    Ok(None) => {
                        snippet_skipped += 1;
                        None
                    }
                    Err(_) => {
                        snippet_skipped += 1;
                        None
                    }
                }
            } else {
                None
            };
            defs.push(LocationWithSnippet {
                file_path: d.file_path,
                uri: d.uri,
                range: d.range,
                snippet,
            });
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if include_snippet && snippet_skipped > 0 {
            warnings.push(json!({
                "kind": "snippet_skipped",
                "message": "Some snippets were skipped (non-file URIs or outside workspace).",
                "count": snippet_skipped
            }));
        }
        if include_snippet && snippet_truncated {
            warnings.push(json!({
                "kind": "snippet_truncated",
                "message": "Some snippets were truncated due to max_snippet_chars."
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_definition_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_results": max_results,
                "max_total_chars": max_total_chars,
                "include_snippet": include_snippet,
                "snippet_context_lines": snippet_context_lines,
                "max_snippet_chars": max_snippet_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "definition_locations": defs.len(),
            "definitions": defs,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} definition locations.",
                structured_content["definition_locations"]
                    .as_u64()
                    .unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_references_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindReferencesAtArgs = parse_arguments(request.arguments)?;

        let include_declaration = args.include_declaration.unwrap_or(true);
        let max_results = args.max_results.unwrap_or(200).clamp(1, 5000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(false);
        let snippet_context_lines = args.snippet_context_lines.unwrap_or(0).min(10);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(400).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut references: Option<Vec<lspi_lsp::ResolvedLocation>> = None;
        let mut limited_by_max_results = false;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .references_at(&abs_file, pos.clone(), include_declaration, max_results)
                .await
            {
                Ok((refs, truncated)) => {
                    used_pos = Some(pos);
                    limited_by_max_results = truncated;
                    if !refs.is_empty() {
                        references = Some(refs);
                        break;
                    }
                    references = Some(refs);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(references) = references else {
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Reference lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_references_at",
                    "message": "reference lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let root = self
            .state
            .workspace_root
            .canonicalize()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut refs = Vec::new();
        for r in references {
            let snippet = if include_snippet {
                match maybe_snippet_for_file_path(
                    &root,
                    &r.file_path,
                    r.range.start.line,
                    snippet_context_lines,
                    max_snippet_chars,
                )
                .await
                {
                    Ok(Some(s)) => {
                        snippet_truncated |= s.truncated;
                        Some(s)
                    }
                    Ok(None) => {
                        snippet_skipped += 1;
                        None
                    }
                    Err(_) => {
                        snippet_skipped += 1;
                        None
                    }
                }
            } else {
                None
            };
            refs.push(LocationWithSnippet {
                file_path: r.file_path,
                uri: r.uri,
                range: r.range,
                snippet,
            });
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if limited_by_max_results {
            warnings.push(json!({
                "kind": "limited_by_max_results",
                "message": "References were truncated due to max_results.",
                "max_results": max_results
            }));
        }
        if include_snippet && snippet_skipped > 0 {
            warnings.push(json!({
                "kind": "snippet_skipped",
                "message": "Some snippets were skipped (non-file URIs or outside workspace).",
                "count": snippet_skipped
            }));
        }
        if include_snippet && snippet_truncated {
            warnings.push(json!({
                "kind": "snippet_truncated",
                "message": "Some snippets were truncated due to max_snippet_chars."
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_references_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "include_declaration": include_declaration,
                "max_results": max_results,
                "max_total_chars": max_total_chars,
                "include_snippet": include_snippet,
                "snippet_context_lines": snippet_context_lines,
                "max_snippet_chars": max_snippet_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "reference_locations": refs.len(),
            "references": refs,
            "limited_by_max_results": limited_by_max_results,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} reference locations.",
                structured_content["reference_locations"]
                    .as_u64()
                    .unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn hover_at(&self, request: CallToolRequestParam) -> Result<CallToolResult, McpError> {
        let args: HoverAtArgs = parse_arguments(request.arguments)?;

        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut hover_value: Option<Value> = None;
        let mut hover_text: Option<String> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed.hover_at(&abs_file, pos.clone()).await {
                Ok(v) => {
                    used_pos = Some(pos);
                    hover_text = hover_to_text(&v).filter(|t| !t.trim().is_empty());
                    hover_value = Some(v);
                    if hover_text.is_some() {
                        break;
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(hover_value) = hover_value else {
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Hover lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "hover_at",
                    "message": "hover lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "hover_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_total_chars": max_total_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "hover": hover_text,
            "hover_raw": hover_value,
            "warnings": warnings,
            "truncated": false
        });

        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(
                if structured_content["hover"]
                    .as_str()
                    .unwrap_or("")
                    .is_empty()
                {
                    "No hover information."
                } else {
                    "Got hover information."
                },
            )],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_implementation_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindImplementationAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(50).clamp(1, 500);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut locations: Option<Vec<lspi_lsp::ResolvedLocation>> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .implementation_at(&abs_file, pos.clone(), max_results)
                .await
            {
                Ok(locs) => {
                    used_pos = Some(pos);
                    if !locs.is_empty() {
                        locations = Some(locs);
                        break;
                    }
                    locations = Some(locs);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(locations) = locations else {
            let method_not_supported = last_err
                .as_ref()
                .map(is_method_not_found_error)
                .unwrap_or(false);
            if method_not_supported {
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Implementation lookup is not supported by this language server.",
                    )],
                    structured_content: Some(json!({
                        "ok": true,
                        "tool": "find_implementation_at",
                        "server_id": server_id,
                        "input": { "file_path": args.file_path, "line": args.line, "character": args.character, "max_results": max_results, "max_total_chars": max_total_chars },
                        "implementation_locations": 0,
                        "implementations": [],
                        "warnings": [{
                            "kind": "method_not_supported",
                            "message": "textDocument/implementation is not supported by this server."
                        }],
                        "truncated": false
                    })),
                    is_error: Some(false),
                    meta: None,
                });
            }

            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Implementation lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_implementation_at",
                    "message": "implementation lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let mut implementations = Vec::new();
        for loc in locations.into_iter().take(max_results.max(1)) {
            implementations.push(LocationWithSnippet {
                file_path: loc.file_path,
                uri: loc.uri,
                range: loc.range,
                snippet: None,
            });
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_implementation_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "implementation_locations": implementations.len(),
            "implementations": implementations,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} implementation locations.",
                structured_content["implementation_locations"]
                    .as_u64()
                    .unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_type_definition_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindTypeDefinitionAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(50).clamp(1, 500);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut locations: Option<Vec<lspi_lsp::ResolvedLocation>> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .type_definition_at(&abs_file, pos.clone(), max_results)
                .await
            {
                Ok(locs) => {
                    used_pos = Some(pos);
                    if !locs.is_empty() {
                        locations = Some(locs);
                        break;
                    }
                    locations = Some(locs);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(locations) = locations else {
            let method_not_supported = last_err
                .as_ref()
                .map(is_method_not_found_error)
                .unwrap_or(false);
            if method_not_supported {
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Type definition lookup is not supported by this language server.",
                    )],
                    structured_content: Some(json!({
                        "ok": true,
                        "tool": "find_type_definition_at",
                        "server_id": server_id,
                        "input": { "file_path": args.file_path, "line": args.line, "character": args.character, "max_results": max_results, "max_total_chars": max_total_chars },
                        "type_definition_locations": 0,
                        "type_definitions": [],
                        "warnings": [{
                            "kind": "method_not_supported",
                            "message": "textDocument/typeDefinition is not supported by this server."
                        }],
                        "truncated": false
                    })),
                    is_error: Some(false),
                    meta: None,
                });
            }

            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Type definition lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_type_definition_at",
                    "message": "type definition lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let mut type_definitions = Vec::new();
        for loc in locations.into_iter().take(max_results.max(1)) {
            type_definitions.push(LocationWithSnippet {
                file_path: loc.file_path,
                uri: loc.uri,
                range: loc.range,
                snippet: None,
            });
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_type_definition_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "type_definition_locations": type_definitions.len(),
            "type_definitions": type_definitions,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} type definition locations.",
                structured_content["type_definition_locations"]
                    .as_u64()
                    .unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_incoming_calls(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindIncomingCallsArgs = parse_arguments(request.arguments)?;

        let max_symbols = args.max_symbols.unwrap_or(50).clamp(1, 200);
        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(true);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(200).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let candidates = routed
            .list_symbol_candidates(&abs_file, &args.symbol_name, kind_num, max_symbols)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if candidates.is_empty() {
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_incoming_calls",
                    "server_id": server_id,
                    "message": "no matching symbols found",
                    "candidates": [],
                })),
                is_error: Some(true),
                meta: None,
            });
        }

        if candidates.len() > 1 {
            let root = self
                .state
                .workspace_root
                .canonicalize()
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            let abs_uri = Url::from_file_path(&abs_file)
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));

            let mut snippet_truncated = false;
            let mut snippet_skipped = 0usize;

            let mut candidates_out = Vec::with_capacity(candidates.len());
            for c in candidates {
                let snippet = if include_snippet {
                    match maybe_snippet_for_file_path(
                        &root,
                        &abs_file.to_string_lossy(),
                        c.selection_range.start.line,
                        0,
                        max_snippet_chars,
                    )
                    .await
                    {
                        Ok(Some(s)) => {
                            snippet_truncated |= s.truncated;
                            Some(s)
                        }
                        Ok(None) => {
                            snippet_skipped += 1;
                            None
                        }
                        Err(_) => {
                            snippet_skipped += 1;
                            None
                        }
                    }
                } else {
                    None
                };

                candidates_out.push(json!({
                    "name": c.name,
                    "kind": c.kind,
                    "file_path": abs_file.to_string_lossy().to_string(),
                    "uri": abs_uri.clone(),
                    "line": c.line,
                    "character": c.character,
                    "selection_range": c.selection_range,
                    "selection_range_1based": lsp_range_1based(&c.selection_range),
                    "selection_start_1based": { "line": c.line, "character": c.character },
                    "snippet": snippet
                }));
            }

            let mut warnings = Vec::<Value>::new();
            if include_snippet && snippet_skipped > 0 {
                warnings.push(json!({
                    "kind": "snippet_skipped",
                    "message": "Some candidate snippets were skipped (non-file URIs or outside workspace).",
                    "count": snippet_skipped
                }));
            }
            if include_snippet && snippet_truncated {
                warnings.push(json!({
                    "kind": "snippet_truncated",
                    "message": "Some candidate snippets were truncated."
                }));
            }
            if let Some(w) = max_total_chars_warning {
                warnings.push(w);
            }

            let mut structured_content = json!({
                "ok": true,
                "tool": "find_incoming_calls",
                "server_id": server_id,
                "needs_disambiguation": true,
                "input": {
                    "file_path": args.file_path,
                    "symbol_name": args.symbol_name,
                    "symbol_kind": args.symbol_kind,
                    "max_symbols": max_symbols,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "max_snippet_chars": max_snippet_chars
                },
                "candidates": candidates_out,
                "warnings": warnings,
                "truncated": false
            });
            enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Multiple symbols match '{}'. Use find_incoming_calls_at with one of the returned positions.",
                    args.symbol_name
                ))],
                structured_content: Some(structured_content),
                is_error: Some(false),
                meta: None,
            });
        }

        let candidate = &candidates[0];
        let pos = lspi_lsp::LspPosition {
            line: candidate.line.saturating_sub(1),
            character: candidate.character.saturating_sub(1),
        };

        let result = match routed.incoming_calls_at(&abs_file, pos, max_results).await {
            Ok(r) => r,
            Err(e) => {
                if is_method_not_found_error(&e) {
                    return Ok(CallToolResult {
                        content: vec![Content::text(
                            "Call hierarchy is not supported by this language server.",
                        )],
                        structured_content: Some(json!({
                            "ok": true,
                            "tool": "find_incoming_calls",
                            "server_id": server_id,
                            "input": { "file_path": args.file_path, "symbol_name": args.symbol_name, "symbol_kind": args.symbol_kind, "max_symbols": max_symbols, "max_results": max_results, "max_total_chars": max_total_chars },
                            "target": null,
                            "call_count": 0,
                            "calls": [],
                            "warnings": [{
                                "kind": "method_not_supported",
                                "message": "callHierarchy is not supported by this server."
                            }],
                            "truncated": false
                        })),
                        is_error: Some(false),
                        meta: None,
                    });
                }
                return Err(McpError::internal_error(e.to_string(), None));
            }
        };

        let item_to_json = |item: &lspi_lsp::CallHierarchyItemResolved| {
            json!({
                "name": &item.name,
                "kind": item.kind,
                "location": {
                    "file_path": &item.location.file_path,
                    "uri": &item.location.uri,
                    "range": &item.location.range,
                    "range_1based": lsp_range_1based(&item.location.range)
                },
                "range": &item.range,
                "range_1based": lsp_range_1based(&item.range),
                "selection_range": &item.selection_range,
                "selection_range_1based": lsp_range_1based(&item.selection_range),
                "selection_start_1based": lsp_position_1based(&item.selection_range.start)
            })
        };

        let mut calls = Vec::new();
        for c in result.calls.into_iter().take(max_results.max(1)) {
            let mut from_ranges = Vec::new();
            for r in c.from_ranges {
                let range_1based = lsp_range_1based(&r);
                from_ranges.push(json!({
                    "range": r,
                    "range_1based": range_1based
                }));
            }
            calls.push(json!({
                "from": item_to_json(&c.from),
                "from_ranges": from_ranges
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_incoming_calls",
            "server_id": server_id,
            "needs_disambiguation": false,
            "input": {
                "file_path": args.file_path,
                "symbol_name": args.symbol_name,
                "symbol_kind": args.symbol_kind,
                "max_symbols": max_symbols,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "selected_symbol": {
                "name": candidate.name,
                "kind": candidate.kind,
                "line": candidate.line,
                "character": candidate.character,
                "selection_range": candidate.selection_range,
                "selection_range_1based": lsp_range_1based(&candidate.selection_range),
                "selection_start_1based": { "line": candidate.line, "character": candidate.character }
            },
            "target": result.target.as_ref().map(item_to_json),
            "call_count": calls.len(),
            "calls": calls,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} incoming calls.",
                structured_content["call_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_outgoing_calls(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindOutgoingCallsArgs = parse_arguments(request.arguments)?;

        let max_symbols = args.max_symbols.unwrap_or(50).clamp(1, 200);
        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(true);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(200).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let candidates = routed
            .list_symbol_candidates(&abs_file, &args.symbol_name, kind_num, max_symbols)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if candidates.is_empty() {
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_outgoing_calls",
                    "server_id": server_id,
                    "message": "no matching symbols found",
                    "candidates": [],
                })),
                is_error: Some(true),
                meta: None,
            });
        }

        if candidates.len() > 1 {
            let root = self
                .state
                .workspace_root
                .canonicalize()
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            let abs_uri = Url::from_file_path(&abs_file)
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));

            let mut snippet_truncated = false;
            let mut snippet_skipped = 0usize;

            let mut candidates_out = Vec::with_capacity(candidates.len());
            for c in candidates {
                let snippet = if include_snippet {
                    match maybe_snippet_for_file_path(
                        &root,
                        &abs_file.to_string_lossy(),
                        c.selection_range.start.line,
                        0,
                        max_snippet_chars,
                    )
                    .await
                    {
                        Ok(Some(s)) => {
                            snippet_truncated |= s.truncated;
                            Some(s)
                        }
                        Ok(None) => {
                            snippet_skipped += 1;
                            None
                        }
                        Err(_) => {
                            snippet_skipped += 1;
                            None
                        }
                    }
                } else {
                    None
                };

                candidates_out.push(json!({
                    "name": c.name,
                    "kind": c.kind,
                    "file_path": abs_file.to_string_lossy().to_string(),
                    "uri": abs_uri.clone(),
                    "line": c.line,
                    "character": c.character,
                    "selection_range": c.selection_range,
                    "selection_range_1based": lsp_range_1based(&c.selection_range),
                    "selection_start_1based": { "line": c.line, "character": c.character },
                    "snippet": snippet
                }));
            }

            let mut warnings = Vec::<Value>::new();
            if include_snippet && snippet_skipped > 0 {
                warnings.push(json!({
                    "kind": "snippet_skipped",
                    "message": "Some candidate snippets were skipped (non-file URIs or outside workspace).",
                    "count": snippet_skipped
                }));
            }
            if include_snippet && snippet_truncated {
                warnings.push(json!({
                    "kind": "snippet_truncated",
                    "message": "Some candidate snippets were truncated."
                }));
            }
            if let Some(w) = max_total_chars_warning {
                warnings.push(w);
            }

            let mut structured_content = json!({
                "ok": true,
                "tool": "find_outgoing_calls",
                "server_id": server_id,
                "needs_disambiguation": true,
                "input": {
                    "file_path": args.file_path,
                    "symbol_name": args.symbol_name,
                    "symbol_kind": args.symbol_kind,
                    "max_symbols": max_symbols,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "max_snippet_chars": max_snippet_chars
                },
                "candidates": candidates_out,
                "warnings": warnings,
                "truncated": false
            });
            enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Multiple symbols match '{}'. Use find_outgoing_calls_at with one of the returned positions.",
                    args.symbol_name
                ))],
                structured_content: Some(structured_content),
                is_error: Some(false),
                meta: None,
            });
        }

        let candidate = &candidates[0];
        let pos = lspi_lsp::LspPosition {
            line: candidate.line.saturating_sub(1),
            character: candidate.character.saturating_sub(1),
        };

        let result = match routed.outgoing_calls_at(&abs_file, pos, max_results).await {
            Ok(r) => r,
            Err(e) => {
                if is_method_not_found_error(&e) {
                    return Ok(CallToolResult {
                        content: vec![Content::text(
                            "Call hierarchy is not supported by this language server.",
                        )],
                        structured_content: Some(json!({
                            "ok": true,
                            "tool": "find_outgoing_calls",
                            "server_id": server_id,
                            "input": { "file_path": args.file_path, "symbol_name": args.symbol_name, "symbol_kind": args.symbol_kind, "max_symbols": max_symbols, "max_results": max_results, "max_total_chars": max_total_chars },
                            "target": null,
                            "call_count": 0,
                            "calls": [],
                            "warnings": [{
                                "kind": "method_not_supported",
                                "message": "callHierarchy is not supported by this server."
                            }],
                            "truncated": false
                        })),
                        is_error: Some(false),
                        meta: None,
                    });
                }
                return Err(McpError::internal_error(e.to_string(), None));
            }
        };

        let item_to_json = |item: &lspi_lsp::CallHierarchyItemResolved| {
            json!({
                "name": &item.name,
                "kind": item.kind,
                "location": {
                    "file_path": &item.location.file_path,
                    "uri": &item.location.uri,
                    "range": &item.location.range,
                    "range_1based": lsp_range_1based(&item.location.range)
                },
                "range": &item.range,
                "range_1based": lsp_range_1based(&item.range),
                "selection_range": &item.selection_range,
                "selection_range_1based": lsp_range_1based(&item.selection_range),
                "selection_start_1based": lsp_position_1based(&item.selection_range.start)
            })
        };

        let mut calls = Vec::new();
        for c in result.calls.into_iter().take(max_results.max(1)) {
            let mut from_ranges = Vec::new();
            for r in c.from_ranges {
                let range_1based = lsp_range_1based(&r);
                from_ranges.push(json!({
                    "range": r,
                    "range_1based": range_1based
                }));
            }
            calls.push(json!({
                "to": item_to_json(&c.to),
                "from_ranges": from_ranges
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_outgoing_calls",
            "server_id": server_id,
            "needs_disambiguation": false,
            "input": {
                "file_path": args.file_path,
                "symbol_name": args.symbol_name,
                "symbol_kind": args.symbol_kind,
                "max_symbols": max_symbols,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "selected_symbol": {
                "name": candidate.name,
                "kind": candidate.kind,
                "line": candidate.line,
                "character": candidate.character,
                "selection_range": candidate.selection_range,
                "selection_range_1based": lsp_range_1based(&candidate.selection_range),
                "selection_start_1based": { "line": candidate.line, "character": candidate.character }
            },
            "target": result.target.as_ref().map(item_to_json),
            "call_count": calls.len(),
            "calls": calls,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} outgoing calls.",
                structured_content["call_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_incoming_calls_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindIncomingCallsAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut result: Option<lspi_lsp::CallHierarchyIncomingResult> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .incoming_calls_at(&abs_file, pos.clone(), max_results)
                .await
            {
                Ok(r) => {
                    used_pos = Some(pos);
                    if !r.calls.is_empty() {
                        result = Some(r);
                        break;
                    }
                    result = Some(r);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(result) = result else {
            let method_not_supported = last_err
                .as_ref()
                .map(is_method_not_found_error)
                .unwrap_or(false);
            if method_not_supported {
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Call hierarchy is not supported by this language server.",
                    )],
                    structured_content: Some(json!({
                        "ok": true,
                        "tool": "find_incoming_calls_at",
                        "server_id": server_id,
                        "input": { "file_path": args.file_path, "line": args.line, "character": args.character, "max_results": max_results, "max_total_chars": max_total_chars },
                        "target": null,
                        "call_count": 0,
                        "calls": [],
                        "warnings": [{
                            "kind": "method_not_supported",
                            "message": "callHierarchy is not supported by this server."
                        }],
                        "truncated": false
                    })),
                    is_error: Some(false),
                    meta: None,
                });
            }

            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Call hierarchy lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_incoming_calls_at",
                    "message": "call hierarchy lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let item_to_json = |item: &lspi_lsp::CallHierarchyItemResolved| {
            json!({
                "name": &item.name,
                "kind": item.kind,
                "location": {
                    "file_path": &item.location.file_path,
                    "uri": &item.location.uri,
                    "range": &item.location.range,
                    "range_1based": lsp_range_1based(&item.location.range)
                },
                "range": &item.range,
                "range_1based": lsp_range_1based(&item.range),
                "selection_range": &item.selection_range,
                "selection_range_1based": lsp_range_1based(&item.selection_range),
                "selection_start_1based": lsp_position_1based(&item.selection_range.start)
            })
        };

        let mut calls = Vec::new();
        for c in result.calls.into_iter().take(max_results.max(1)) {
            let mut from_ranges = Vec::new();
            for r in c.from_ranges {
                let range_1based = lsp_range_1based(&r);
                from_ranges.push(json!({
                    "range": r,
                    "range_1based": range_1based
                }));
            }
            calls.push(json!({
                "from": item_to_json(&c.from),
                "from_ranges": from_ranges
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_incoming_calls_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "target": result.target.as_ref().map(item_to_json),
            "call_count": calls.len(),
            "calls": calls,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} incoming calls.",
                structured_content["call_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_outgoing_calls_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindOutgoingCallsAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut used_pos: Option<lspi_lsp::LspPosition> = None;
        let mut result: Option<lspi_lsp::CallHierarchyOutgoingResult> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .outgoing_calls_at(&abs_file, pos.clone(), max_results)
                .await
            {
                Ok(r) => {
                    used_pos = Some(pos);
                    if !r.calls.is_empty() {
                        result = Some(r);
                        break;
                    }
                    result = Some(r);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(result) = result else {
            let method_not_supported = last_err
                .as_ref()
                .map(is_method_not_found_error)
                .unwrap_or(false);
            if method_not_supported {
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Call hierarchy is not supported by this language server.",
                    )],
                    structured_content: Some(json!({
                        "ok": true,
                        "tool": "find_outgoing_calls_at",
                        "server_id": server_id,
                        "input": { "file_path": args.file_path, "line": args.line, "character": args.character, "max_results": max_results, "max_total_chars": max_total_chars },
                        "target": null,
                        "call_count": 0,
                        "calls": [],
                        "warnings": [{
                            "kind": "method_not_supported",
                            "message": "callHierarchy is not supported by this server."
                        }],
                        "truncated": false
                    })),
                    is_error: Some(false),
                    meta: None,
                });
            }

            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Call hierarchy lookup failed at the provided position.",
                )],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "find_outgoing_calls_at",
                    "message": "call hierarchy lookup failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let item_to_json = |item: &lspi_lsp::CallHierarchyItemResolved| {
            json!({
                "name": &item.name,
                "kind": item.kind,
                "location": {
                    "file_path": &item.location.file_path,
                    "uri": &item.location.uri,
                    "range": &item.location.range,
                    "range_1based": lsp_range_1based(&item.location.range)
                },
                "range": &item.range,
                "range_1based": lsp_range_1based(&item.range),
                "selection_range": &item.selection_range,
                "selection_range_1based": lsp_range_1based(&item.selection_range),
                "selection_start_1based": lsp_position_1based(&item.selection_range.start)
            })
        };

        let mut calls = Vec::new();
        for c in result.calls.into_iter().take(max_results.max(1)) {
            let mut from_ranges = Vec::new();
            for r in c.from_ranges {
                let range_1based = lsp_range_1based(&r);
                from_ranges.push(json!({
                    "range": r,
                    "range_1based": range_1based
                }));
            }
            calls.push(json!({
                "to": item_to_json(&c.to),
                "from_ranges": from_ranges
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.clone()
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_outgoing_calls_at",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "used_lsp_position": used_pos.map(|p| json!({"line": p.line, "character": p.character})),
            "target": result.target.as_ref().map(item_to_json),
            "call_count": calls.len(),
            "calls": calls,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} outgoing calls.",
                structured_content["call_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn get_document_symbols(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetDocumentSymbolsArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(500).clamp(1, 5000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let symbols = routed
            .document_symbols(&abs_file, max_results)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let abs_uri = Url::from_file_path(&abs_file)
            .ok()
            .map(|u| u.to_string())
            .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));

        let mut out = Vec::new();
        for s in symbols {
            let mut value = serde_json::to_value(&s).unwrap_or(Value::Null);
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "document_file_path".to_string(),
                    Value::String(abs_file.to_string_lossy().to_string()),
                );
                obj.insert("document_uri".to_string(), Value::String(abs_uri.clone()));
                obj.insert("range_1based".to_string(), lsp_range_1based(&s.range));
                obj.insert(
                    "selection_range_1based".to_string(),
                    lsp_range_1based(&s.selection_range),
                );
                obj.insert(
                    "selection_start_1based".to_string(),
                    lsp_position_1based(&s.selection_range.start),
                );
            }
            out.push(value);
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "get_document_symbols",
            "server_id": server_id,
            "input": {
                "file_path": args.file_path,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "symbol_count": out.len(),
            "symbols": out,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} document symbols.",
                structured_content["symbol_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn search_workspace_symbols(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: SearchWorkspaceSymbolsArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(100).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let routed = if let Some(file_path) = args.file_path.as_deref() {
            let abs_file = canonicalize_within(&self.state.workspace_root, Path::new(file_path))
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
            self.client_for_file(&abs_file).await?
        } else if self.state.servers.len() == 1 {
            let server = self
                .state
                .servers
                .first()
                .ok_or_else(|| McpError::internal_error("no configured servers", None))?;
            self.client_for_server(server).await?
        } else {
            return Err(McpError::invalid_params(
                "multiple servers configured; provide file_path to pick a language server",
                None,
            ));
        };

        let server_id = routed.server_id().to_string();

        let matches = routed
            .workspace_symbols(&args.query, max_results)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut out = Vec::new();
        for m in matches {
            out.push(json!({
                "name": m.name,
                "kind": m.kind,
                "location": {
                    "file_path": m.location.file_path,
                    "uri": m.location.uri,
                    "range": m.location.range,
                    "range_1based": lsp_range_1based(&m.location.range)
                }
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "search_workspace_symbols",
            "server_id": server_id,
            "input": {
                "query": args.query,
                "file_path": args.file_path,
                "max_results": max_results,
                "max_total_chars": max_total_chars
            },
            "match_count": out.len(),
            "matches": out,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} workspace symbol matches.",
                structured_content["match_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn find_references(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindReferencesArgs = parse_arguments(request.arguments)?;

        let include_declaration = args.include_declaration.unwrap_or(true);
        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);
        let include_snippet = args.include_snippet.unwrap_or(false);
        let snippet_context_lines = args.snippet_context_lines.unwrap_or(0).min(10);
        let max_snippet_chars = args.max_snippet_chars.unwrap_or(400).clamp(40, 4000);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let matches = routed
            .find_references_by_name(
                &abs_file,
                &args.symbol_name,
                kind_num,
                include_declaration,
                20,
                max_results,
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let root = self
            .state
            .workspace_root
            .canonicalize()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut results = Vec::new();
        let abs_uri = Url::from_file_path(&abs_file)
            .ok()
            .map(|u| u.to_string())
            .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));
        for m in matches {
            let mut refs = Vec::new();
            for r in m.references {
                let snippet = if include_snippet {
                    match maybe_snippet_for_file_path(
                        &root,
                        &r.file_path,
                        r.range.start.line,
                        snippet_context_lines,
                        max_snippet_chars,
                    )
                    .await
                    {
                        Ok(Some(s)) => {
                            snippet_truncated |= s.truncated;
                            Some(s)
                        }
                        Ok(None) => {
                            snippet_skipped += 1;
                            None
                        }
                        Err(_) => {
                            snippet_skipped += 1;
                            None
                        }
                    }
                } else {
                    None
                };
                refs.push(LocationWithSnippet {
                    file_path: r.file_path,
                    uri: r.uri,
                    range: r.range,
                    snippet,
                });
            }
            let mut symbol_value = serde_json::to_value(&m.symbol).unwrap_or(Value::Null);
            if let Some(obj) = symbol_value.as_object_mut() {
                obj.insert(
                    "document_file_path".to_string(),
                    Value::String(abs_file.to_string_lossy().to_string()),
                );
                obj.insert("document_uri".to_string(), Value::String(abs_uri.clone()));
                obj.insert(
                    "range_1based".to_string(),
                    lsp_range_1based(&m.symbol.range),
                );
                obj.insert(
                    "selection_range_1based".to_string(),
                    lsp_range_1based(&m.symbol.selection_range),
                );
                obj.insert(
                    "selection_start_1based".to_string(),
                    lsp_position_1based(&m.symbol.selection_range.start),
                );
            }
            results.push(ReferenceMatchOut {
                symbol: symbol_value,
                references: refs,
                truncated: m.truncated,
            });
        }

        let references_count: usize = results.iter().map(|m| m.references.len()).sum();
        let truncated = results.iter().any(|m| m.truncated);

        let mut warnings = Vec::<Value>::new();
        if results.len() > 1 {
            warnings.push(json!({
                "kind": "multiple_symbol_matches",
                "message": "Multiple symbols matched; consider using find_references_at for disambiguation.",
                "count": results.len()
            }));
        }
        if include_snippet && snippet_skipped > 0 {
            warnings.push(json!({
                "kind": "snippet_skipped",
                "message": "Some snippets were skipped (non-file URIs or outside workspace).",
                "count": snippet_skipped
            }));
        }
        if include_snippet && snippet_truncated {
            warnings.push(json!({
                "kind": "snippet_truncated",
                "message": "Some snippets were truncated due to max_snippet_chars."
            }));
        }
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "find_references",
            "server_id": server_id,
            "needs_disambiguation": results.len() > 1,
            "input": {
                "file_path": args.file_path,
                "symbol_name": args.symbol_name,
                "symbol_kind": args.symbol_kind,
                "include_declaration": include_declaration,
                "max_results": max_results,
                "max_total_chars": max_total_chars,
                "include_snippet": include_snippet,
                "snippet_context_lines": snippet_context_lines,
                "max_snippet_chars": max_snippet_chars
            },
            "symbol_matches": results.len(),
            "reference_locations": references_count,
            "results": results,
            "warnings": warnings,
            "truncated": truncated
        });
        enforce_global_output_caps(max_total_chars, include_snippet, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} matching symbols and {} reference locations{}.",
                results.len(),
                references_count,
                if truncated { " (truncated)" } else { "" }
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn get_diagnostics(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetDiagnosticsArgs = parse_arguments(request.arguments)?;
        let max_results = args.max_results.unwrap_or(200).clamp(1, 5000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let mut diagnostics = routed
            .get_diagnostics(&abs_file, std::time::Duration::from_millis(800))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        if diagnostics.len() > max_results {
            diagnostics.truncate(max_results);
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = json!({
            "ok": true,
            "tool": "get_diagnostics",
            "server_id": server_id,
            "input": { "file_path": args.file_path, "max_results": max_results, "max_total_chars": max_total_chars },
            "count": diagnostics.len(),
            "diagnostics": diagnostics,
            "warnings": warnings,
            "truncated": false
        });
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} diagnostics.",
                diagnostics.len()
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn rename_symbol(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: RenameSymbolArgs = parse_arguments(request.arguments)?;
        let dry_run = args.dry_run.unwrap_or(true);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let candidates = routed
            .list_symbol_candidates(&abs_file, &args.symbol_name, kind_num, 50)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if candidates.is_empty() {
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "rename_symbol",
                    "server_id": server_id,
                    "message": "no matching symbols found",
                    "candidates": [],
                })),
                is_error: Some(true),
                meta: None,
            });
        }

        if candidates.len() > 1 {
            let root = self
                .state
                .workspace_root
                .canonicalize()
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            let abs_uri = Url::from_file_path(&abs_file)
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_else(|| format!("file://{}", abs_file.to_string_lossy()));

            let mut snippet_truncated = false;
            let mut snippet_skipped = 0usize;

            let mut candidates_out = Vec::with_capacity(candidates.len());
            for c in candidates {
                let selection_start_0based = lspi_lsp::LspPosition {
                    line: c.selection_range.start.line,
                    character: c.selection_range.start.character,
                };

                let snippet = match maybe_snippet_for_file_path(
                    &root,
                    &abs_file.to_string_lossy(),
                    selection_start_0based.line,
                    0,
                    200,
                )
                .await
                {
                    Ok(Some(s)) => {
                        snippet_truncated |= s.truncated;
                        Some(s)
                    }
                    Ok(None) => {
                        snippet_skipped += 1;
                        None
                    }
                    Err(_) => {
                        snippet_skipped += 1;
                        None
                    }
                };

                candidates_out.push(json!({
                    "name": c.name,
                    "kind": c.kind,
                    "file_path": abs_file.to_string_lossy().to_string(),
                    "uri": abs_uri.clone(),
                    "line": c.line,
                    "character": c.character,
                    "selection_range": c.selection_range,
                    "selection_start_1based": { "line": c.line, "character": c.character },
                    "snippet": snippet
                }));
            }

            let mut warnings = Vec::<Value>::new();
            if snippet_skipped > 0 {
                warnings.push(json!({
                    "kind": "snippet_skipped",
                    "message": "Some candidate snippets were skipped (non-file URIs or outside workspace).",
                    "count": snippet_skipped
                }));
            }
            if snippet_truncated {
                warnings.push(json!({
                    "kind": "snippet_truncated",
                    "message": "Some candidate snippets were truncated."
                }));
            }

            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Multiple symbols match '{}'. Use rename_symbol_strict with one of the returned positions.",
                    args.symbol_name
                ))],
                structured_content: Some(json!({
                    "ok": true,
                    "tool": "rename_symbol",
                    "server_id": server_id,
                    "needs_disambiguation": true,
                    "candidates": candidates_out,
                    "dry_run": true,
                    "warnings": warnings
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        let candidate = &candidates[0];
        let pos = lspi_lsp::LspPosition {
            line: candidate.line.saturating_sub(1),
            character: candidate.character.saturating_sub(1),
        };

        let changes = routed
            .rename_at(&abs_file, pos, &args.new_name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let preview = workspace_edit::workspace_edit_preview(&changes)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if !dry_run {
            let apply_result = workspace_edit::apply_workspace_edit(
                &self.state.workspace_root,
                &changes,
                args.expected_before_sha256.as_ref(),
                args.create_backups.unwrap_or(true),
                args.backup_suffix.as_deref().unwrap_or(".bak"),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Applied rename: {} files modified.",
                    apply_result.files_modified.len()
                ))],
                structured_content: Some(json!({
                    "ok": true,
                    "tool": "rename_symbol",
                    "server_id": server_id,
                    "dry_run": false,
                    "symbol": candidate,
                    "new_name": args.new_name,
                    "edit": preview,
                    "apply": apply_result,
                    "warnings": []
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Preview rename: {} files affected.",
                preview.files.len()
            ))],
            structured_content: Some(json!({
                "ok": true,
                "tool": "rename_symbol",
                "server_id": server_id,
                "dry_run": true,
                "symbol": candidate,
                "new_name": args.new_name,
                "edit": preview,
                "warnings": []
            })),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn rename_symbol_strict(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: RenameSymbolStrictArgs = parse_arguments(request.arguments)?;
        let dry_run = args.dry_run.unwrap_or(true);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(&self.state.workspace_root, &file_path)
            .map_err(|e| McpError::invalid_params(e.to_string(), None))?;

        let routed = self.client_for_file(&abs_file).await?;
        let server_id = routed.server_id().to_string();

        let file_bytes = tokio::fs::read(&abs_file)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let file_text = String::from_utf8(file_bytes)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut last_err: Option<anyhow::Error> = None;
        let mut changes: Option<std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>> =
            None;

        let best_guess = lspi_core::position_fuzz::LspPosition {
            line: args.line.saturating_sub(1),
            character: args.character.saturating_sub(1),
        };

        let limits = lspi_core::position_fuzz::CandidateLimits::default();
        let candidates = lspi_core::position_fuzz::candidate_lsp_positions(
            &file_text,
            args.line,
            args.character,
            limits,
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut used_pos: Option<lspi_lsp::LspPosition> = None;

        for c in candidates {
            let pos = lspi_lsp::LspPosition {
                line: c.line,
                character: c.character,
            };
            match routed
                .rename_at_prepared(&abs_file, pos.clone(), &args.new_name)
                .await
            {
                Ok(c) => {
                    used_pos = Some(pos);
                    if !c.is_empty() {
                        changes = Some(c);
                        break;
                    }
                    changes = Some(c);
                }
                Err(e) => last_err = Some(e),
            }
        }

        let Some(changes) = changes else {
            return Ok(CallToolResult {
                content: vec![Content::text("Rename failed at the provided position.")],
                structured_content: Some(json!({
                    "ok": false,
                    "tool": "rename_symbol_strict",
                    "server_id": server_id,
                    "message": "rename failed",
                    "error": last_err.map(|e| e.to_string()),
                })),
                is_error: Some(true),
                meta: None,
            });
        };

        let preview = workspace_edit::workspace_edit_preview(&changes)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos
            && (used.line != best_guess.line || used.character != best_guess.character)
        {
            warnings.push(json!({
                "kind": "position_fuzzing",
                "message": "Applied bounded position fuzzing to locate the symbol position.",
                "input": { "line": args.line, "character": args.character },
                "used_lsp_position": { "line": used.line, "character": used.character }
            }));
        }

        if !dry_run {
            let apply_result = workspace_edit::apply_workspace_edit(
                &self.state.workspace_root,
                &changes,
                args.expected_before_sha256.as_ref(),
                args.create_backups.unwrap_or(true),
                args.backup_suffix.as_deref().unwrap_or(".bak"),
            )
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Applied rename: {} files modified.",
                    apply_result.files_modified.len()
                ))],
                structured_content: Some(json!({
                    "ok": true,
                    "tool": "rename_symbol_strict",
                    "server_id": server_id,
                    "dry_run": false,
                    "input_position": { "line": args.line, "character": args.character },
                    "new_name": args.new_name,
                    "edit": preview,
                    "apply": apply_result,
                    "warnings": warnings
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Preview rename: {} files affected.",
                preview.files.len()
            ))],
            structured_content: Some(json!({
                "ok": true,
                "tool": "rename_symbol_strict",
                "server_id": server_id,
                "dry_run": true,
                "input_position": { "line": args.line, "character": args.character },
                "new_name": args.new_name,
                "edit": preview,
                "warnings": warnings
            })),
            is_error: Some(false),
            meta: None,
        })
    }

    async fn restart_server(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: RestartServerArgs = match request.arguments {
            Some(arguments) => parse_arguments(Some(arguments))?,
            None => RestartServerArgs { extensions: None },
        };

        let requested_extensions: Vec<String> = args
            .extensions
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
                if e.is_empty() { None } else { Some(e) }
            })
            .collect();

        let target_server_ids: Vec<String> =
            if args.extensions.is_none() || requested_extensions.is_empty() {
                self.state.servers.iter().map(|s| s.id.clone()).collect()
            } else {
                self.state
                    .servers
                    .iter()
                    .filter(|s| {
                        s.extensions
                            .iter()
                            .any(|e| requested_extensions.iter().any(|want| want == e))
                    })
                    .map(|s| s.id.clone())
                    .collect()
            };

        if target_server_ids.is_empty() {
            return Ok(CallToolResult {
                content: vec![Content::text("No matching servers to restart.")],
                structured_content: Some(json!({
                    "ok": true,
                    "tool": "restart_server",
                    "requested_extensions": requested_extensions,
                    "restarted": [],
                    "warnings": []
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        let mut restarted = Vec::new();
        let mut warnings = Vec::<Value>::new();
        let mut busy = Vec::<String>::new();

        let kind_by_id: std::collections::HashMap<String, String> = self
            .state
            .servers
            .iter()
            .map(|s| (s.id.clone(), s.kind.clone()))
            .collect();

        for id in target_server_ids {
            let kind = kind_by_id.get(&id).cloned().unwrap_or_default();

            if is_rust_analyzer_kind(&kind) {
                let ra_entry = {
                    let mut guard = self.state.rust_analyzer.lock().await;
                    guard.remove(&id)
                };

                let Some(ra_entry) = ra_entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_rust_analyzer_managed(ra_entry).await {
                    Ok(()) => restarted.push(id),
                    Err(entry) => {
                        let mut guard = self.state.rust_analyzer.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            if is_omnisharp_kind(&kind) {
                let os_entry = {
                    let mut guard = self.state.omnisharp.lock().await;
                    guard.remove(&id)
                };

                let Some(os_entry) = os_entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_omnisharp_managed(os_entry).await {
                    Ok(()) => restarted.push(id),
                    Err(entry) => {
                        let mut guard = self.state.omnisharp.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            if is_generic_kind(&kind) || is_pyright_kind(&kind) {
                let entry = {
                    let mut guard = self.state.generic.lock().await;
                    guard.remove(&id)
                };

                let Some(entry) = entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_generic_managed(entry).await {
                    Ok(()) => restarted.push(id),
                    Err(entry) => {
                        let mut guard = self.state.generic.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            warnings.push(json!({
                "kind": "server_unsupported",
                "server_id": id,
                "server_kind": kind,
                "message": "server kind is not supported yet"
            }));
        }

        for id in &busy {
            warnings.push(json!({
                "kind": "server_busy",
                "server_id": id,
                "message": "server is currently in use; cannot restart safely"
            }));
        }

        let ok = busy.is_empty();
        let is_error = restarted.is_empty() && !busy.is_empty();

        Ok(CallToolResult {
            content: vec![Content::text("Restarted servers.")],
            structured_content: Some(json!({
                "ok": ok,
                "tool": "restart_server",
                "requested_extensions": requested_extensions,
                "restarted": restarted,
                "busy": busy,
                "warnings": warnings
            })),
            is_error: Some(is_error),
            meta: None,
        })
    }

    async fn stop_server(&self, request: CallToolRequestParam) -> Result<CallToolResult, McpError> {
        let args: StopServerArgs = match request.arguments {
            Some(arguments) => parse_arguments(Some(arguments))?,
            None => StopServerArgs { extensions: None },
        };

        let requested_extensions: Vec<String> = args
            .extensions
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| {
                let e = e.trim().trim_start_matches('.').to_ascii_lowercase();
                if e.is_empty() { None } else { Some(e) }
            })
            .collect();

        let target_server_ids: Vec<String> =
            if args.extensions.is_none() || requested_extensions.is_empty() {
                self.state.servers.iter().map(|s| s.id.clone()).collect()
            } else {
                self.state
                    .servers
                    .iter()
                    .filter(|s| {
                        s.extensions
                            .iter()
                            .any(|e| requested_extensions.iter().any(|want| want == e))
                    })
                    .map(|s| s.id.clone())
                    .collect()
            };

        if target_server_ids.is_empty() {
            return Ok(CallToolResult {
                content: vec![Content::text("No matching servers to stop.")],
                structured_content: Some(json!({
                    "ok": true,
                    "tool": "stop_server",
                    "requested_extensions": requested_extensions,
                    "stopped": [],
                    "warnings": []
                })),
                is_error: Some(false),
                meta: None,
            });
        }

        let mut stopped = Vec::new();
        let mut warnings = Vec::<Value>::new();
        let mut busy = Vec::<String>::new();

        let kind_by_id: std::collections::HashMap<String, String> = self
            .state
            .servers
            .iter()
            .map(|s| (s.id.clone(), s.kind.clone()))
            .collect();

        for id in target_server_ids {
            let kind = kind_by_id.get(&id).cloned().unwrap_or_default();

            if is_rust_analyzer_kind(&kind) {
                let entry = {
                    let mut guard = self.state.rust_analyzer.lock().await;
                    guard.remove(&id)
                };

                let Some(entry) = entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_rust_analyzer_managed(entry).await {
                    Ok(()) => stopped.push(id),
                    Err(entry) => {
                        let mut guard = self.state.rust_analyzer.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            if is_omnisharp_kind(&kind) {
                let entry = {
                    let mut guard = self.state.omnisharp.lock().await;
                    guard.remove(&id)
                };

                let Some(entry) = entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_omnisharp_managed(entry).await {
                    Ok(()) => stopped.push(id),
                    Err(entry) => {
                        let mut guard = self.state.omnisharp.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            if is_generic_kind(&kind) || is_pyright_kind(&kind) {
                let entry = {
                    let mut guard = self.state.generic.lock().await;
                    guard.remove(&id)
                };

                let Some(entry) = entry else {
                    warnings.push(json!({
                        "kind": "server_not_running",
                        "server_id": id,
                        "message": "server is not running"
                    }));
                    continue;
                };

                match shutdown_generic_managed(entry).await {
                    Ok(()) => stopped.push(id),
                    Err(entry) => {
                        let mut guard = self.state.generic.lock().await;
                        guard.insert(id.clone(), entry);
                        busy.push(id);
                    }
                }
                continue;
            }

            warnings.push(json!({
                "kind": "server_unsupported",
                "server_id": id,
                "server_kind": kind,
                "message": "server kind is not supported yet"
            }));
        }

        for id in &busy {
            warnings.push(json!({
                "kind": "server_busy",
                "server_id": id,
                "message": "server is currently in use; cannot stop safely"
            }));
        }

        let ok = busy.is_empty();
        let is_error = stopped.is_empty() && !busy.is_empty();

        Ok(CallToolResult {
            content: vec![Content::text("Stopped servers.")],
            structured_content: Some(json!({
                "ok": ok,
                "tool": "stop_server",
                "requested_extensions": requested_extensions,
                "stopped": stopped,
                "busy": busy,
                "warnings": warnings
            })),
            is_error: Some(is_error),
            meta: None,
        })
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

fn tool_find_definition() -> Tool {
    Tool::new(
        Cow::Borrowed("find_definition"),
        Cow::Borrowed(
            "Find definition locations for a symbol in a file (name-based; may need disambiguation).",
        ),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "max_results": { "type": "integer", "minimum": 1, "default": 20, "maximum": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1, "maximum": 10 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400, "maximum": 4000 }
            },
            "required": ["file_path", "symbol_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_definition_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_definition_at"),
        Cow::Borrowed("Find definition locations at a specific 1-based position (line/character)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_results": { "type": "integer", "minimum": 1, "default": 50, "maximum": 500 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1, "maximum": 10 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400, "maximum": 4000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_references() -> Tool {
    Tool::new(
        Cow::Borrowed("find_references"),
        Cow::Borrowed(
            "Find references for a symbol across the workspace (name-based; may be truncated by max_results).",
        ),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "include_declaration": { "type": "boolean", "default": true },
                "max_results": { "type": "integer", "minimum": 1, "default": 200, "maximum": 5000 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": false },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1, "maximum": 10 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400, "maximum": 4000 }
            },
            "required": ["file_path", "symbol_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_references_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_references_at"),
        Cow::Borrowed("Find references at a specific 1-based position (line/character)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "include_declaration": { "type": "boolean", "default": true },
                "max_results": { "type": "integer", "minimum": 1, "default": 200, "maximum": 5000 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": false },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1, "maximum": 10 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400, "maximum": 4000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_hover_at() -> Tool {
    Tool::new(
        Cow::Borrowed("hover_at"),
        Cow::Borrowed("Get hover information at a specific 1-based position (line/character)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_implementation_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_implementation_at"),
        Cow::Borrowed(
            "Find implementation locations at a specific 1-based position (line/character).",
        ),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_results": { "type": "integer", "minimum": 1, "default": 50 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_type_definition_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_type_definition_at"),
        Cow::Borrowed(
            "Find type definition locations at a specific 1-based position (line/character).",
        ),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_results": { "type": "integer", "minimum": 1, "default": 50 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_incoming_calls() -> Tool {
    Tool::new(
        Cow::Borrowed("find_incoming_calls"),
        Cow::Borrowed("Find incoming calls (call hierarchy) for a symbol in a file."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "max_symbols": { "type": "integer", "minimum": 1, "default": 50 },
                "max_results": { "type": "integer", "minimum": 1, "default": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 200 }
            },
            "required": ["file_path", "symbol_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_outgoing_calls() -> Tool {
    Tool::new(
        Cow::Borrowed("find_outgoing_calls"),
        Cow::Borrowed("Find outgoing calls (call hierarchy) for a symbol in a file."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "max_symbols": { "type": "integer", "minimum": 1, "default": 50 },
                "max_results": { "type": "integer", "minimum": 1, "default": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 200 }
            },
            "required": ["file_path", "symbol_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_incoming_calls_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_incoming_calls_at"),
        Cow::Borrowed("Find incoming calls (call hierarchy) at a specific 1-based position."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_results": { "type": "integer", "minimum": 1, "default": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_outgoing_calls_at() -> Tool {
    Tool::new(
        Cow::Borrowed("find_outgoing_calls_at"),
        Cow::Borrowed("Find outgoing calls (call hierarchy) at a specific 1-based position."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "max_results": { "type": "integer", "minimum": 1, "default": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_get_document_symbols() -> Tool {
    Tool::new(
        Cow::Borrowed("get_document_symbols"),
        Cow::Borrowed("List document symbols for a file."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "max_results": { "type": "integer", "minimum": 1, "default": 500 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path"],
            "additionalProperties": false
        }))),
    )
}

fn tool_search_workspace_symbols() -> Tool {
    Tool::new(
        Cow::Borrowed("search_workspace_symbols"),
        Cow::Borrowed("Search workspace symbols via the language server."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "query": { "type": "string" },
                "file_path": { "type": "string" },
                "max_results": { "type": "integer", "minimum": 1, "default": 100 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["query"],
            "additionalProperties": false
        }))),
    )
}

fn tool_rename_symbol() -> Tool {
    Tool::new(
        Cow::Borrowed("rename_symbol"),
        Cow::Borrowed("Preview or apply a rename for a symbol in a file."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "new_name": { "type": "string" },
                "dry_run": { "type": "boolean", "default": true },
                "expected_before_sha256": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "create_backups": { "type": "boolean", "default": true },
                "backup_suffix": { "type": "string", "default": ".bak" }
            },
            "required": ["file_path", "symbol_name", "new_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_rename_symbol_strict() -> Tool {
    Tool::new(
        Cow::Borrowed("rename_symbol_strict"),
        Cow::Borrowed("Rename a symbol at a specific 1-based position (line/character)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "line": { "type": "integer", "minimum": 1 },
                "character": { "type": "integer", "minimum": 1 },
                "new_name": { "type": "string" },
                "dry_run": { "type": "boolean", "default": true },
                "expected_before_sha256": {
                    "type": "object",
                    "additionalProperties": { "type": "string" }
                },
                "create_backups": { "type": "boolean", "default": true },
                "backup_suffix": { "type": "string", "default": ".bak" }
            },
            "required": ["file_path", "line", "character", "new_name"],
            "additionalProperties": false
        }))),
    )
}

fn tool_get_diagnostics() -> Tool {
    Tool::new(
        Cow::Borrowed("get_diagnostics"),
        Cow::Borrowed(
            "Get diagnostics for a file (pull if supported; otherwise cached publishDiagnostics).",
        ),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "max_results": { "type": "integer", "minimum": 1, "default": 200 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "required": ["file_path"],
            "additionalProperties": false
        }))),
    )
}

fn tool_restart_server() -> Tool {
    Tool::new(
        Cow::Borrowed("restart_server"),
        Cow::Borrowed("Restart language servers (all or by file extensions)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "extensions": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "additionalProperties": false
        }))),
    )
}

fn tool_stop_server() -> Tool {
    Tool::new(
        Cow::Borrowed("stop_server"),
        Cow::Borrowed("Stop language servers (all or by file extensions)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "extensions": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            },
            "additionalProperties": false
        }))),
    )
}

fn schema(value: serde_json::Value) -> JsonObject {
    #[expect(clippy::expect_used)]
    serde_json::from_value(value).expect("tool schema should deserialize")
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
