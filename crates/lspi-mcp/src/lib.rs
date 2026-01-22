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
mod structured;
mod tool_schemas;
mod tools;
mod workspace_edit;

use output::{effective_max_total_chars, enforce_global_output_caps};
use structured::{structured_error, structured_ok};

fn mcp_error_kind_name(code: i32) -> &'static str {
    match code {
        -32002 => "resource_not_found",
        -32600 => "invalid_request",
        -32601 => "method_not_found",
        -32602 => "invalid_params",
        -32603 => "internal_error",
        -32700 => "parse_error",
        _ => "mcp_error",
    }
}

fn lspi_error_kind_from_data(data: Option<&Value>) -> Option<&str> {
    data.and_then(|d| d.get("lspi_error"))
        .and_then(|e| e.get("kind"))
        .and_then(|k| k.as_str())
}

fn error_next_steps(tool: &str, err: &McpError) -> Vec<Value> {
    let message = err.message.as_ref();
    let lspi_kind = lspi_error_kind_from_data(err.data.as_ref());
    let mut steps = Vec::new();

    if lspi_kind == Some("read_only") || message.contains("disabled in read-only mode") {
        steps.push(json!({
            "kind": "config",
            "message": "This tool is disabled because lspi is running in read-only mode. Start lspi with `--read-write` or set `mcp.read_only=false` (config). If you used `--mode navigation` or `--context codex|navigation`, switch to `--mode refactor` or `--context full`."
        }));
        steps.push(json!({
            "kind": "tool",
            "tool": "get_current_config",
            "arguments": {},
            "message": "Confirm whether `read_only` is enabled and which context/mode defaults were applied."
        }));
        return steps;
    }

    // Always include a minimal introspection path, unless the failing tool is itself introspection.
    if !matches!(
        tool,
        "get_current_config" | "list_servers" | "get_server_status"
    ) {
        steps.push(json!({
            "kind": "tool",
            "tool": "get_current_config",
            "arguments": {},
            "message": "Confirm the effective MCP config (workspace_root, allowed_roots, read_only, output caps)."
        }));
        steps.push(json!({
            "kind": "tool",
            "tool": "list_servers",
            "arguments": {},
            "message": "Confirm configured servers, extensions, and routing metadata."
        }));
        steps.push(json!({
            "kind": "tool",
            "tool": "get_server_status",
            "arguments": {},
            "message": "Confirm server lifecycle status (running, last error, warmup)."
        }));
    }

    if lspi_kind == Some("no_server_for_extension")
        || message.contains("no configured LSP server matches file extension")
    {
        steps.push(json!({
            "kind": "config",
            "message": "Add/verify `servers[].extensions` for this language, or pass a `file_path` with the expected extension so routing can pick the correct server."
        }));
    }

    if lspi_kind == Some("unsupported_server_kind")
        || message.contains("server kind is not supported yet:")
    {
        steps.push(json!({
            "kind": "config",
            "message": "Use `kind = \"generic\"` for stdio JSON-RPC servers, or switch to a supported first-class kind (rust_analyzer, omnisharp, pyright, basedpyright)."
        }));
    }

    if lspi_kind == Some("missing_generic_command")
        || message.contains("missing command for generic server id=")
    {
        steps.push(json!({
            "kind": "config",
            "message": "Set `servers[].command` (and usually `args=[\"--stdio\"]`) for `kind=\"generic\"`, or switch to a first-class kind if available."
        }));
        steps.push(json!({
            "kind": "command",
            "command": "lspi doctor --workspace-root . --json",
            "message": "Run doctor to verify language server installation and provide install hints."
        }));
    }

    if lspi_kind == Some("pyright_preflight_failed") || message.contains("pyright preflight failed")
    {
        steps.push(json!({
            "kind": "command",
            "command": "lspi doctor --workspace-root . --json",
            "message": "Run doctor to validate Pyright/basedpyright availability and see install hints."
        }));
        steps.push(json!({
            "kind": "config",
            "message": "If you have multiple Python tooling installs, set `servers[].command` explicitly (or `LSPI_PYRIGHT_COMMAND` / `LSPI_BASEDPYRIGHT_COMMAND`)."
        }));
    }

    if message.contains("failed to spawn LSP server:")
        || message.contains("failed to capture LSP stdin")
        || message.contains("failed to capture LSP stdout")
        || message.contains("failed to capture LSP stderr")
    {
        steps.push(json!({
            "kind": "command",
            "command": "lspi doctor --workspace-root . --json",
            "message": "Run doctor to confirm the resolved server command and basic preflight checks."
        }));
        steps.push(json!({
            "kind": "config",
            "message": "Verify `servers[].command`, `servers[].cwd`, and `[servers.env]` (PATH / runtime deps)."
        }));
    }

    if message.contains("failed to build rootUri")
        || message.contains("failed to build workspaceFolder URI")
        || message.contains("failed to build rootUri for")
    {
        steps.push(json!({
            "kind": "config",
            "message": "Verify `servers[].root_dir` and `servers[].workspace_folders` paths exist and are valid directories."
        }));
    }

    if message.contains("failed to initialize LSP server") {
        steps.push(json!({
            "kind": "config",
            "message": "Increase `servers[].initialize_timeout_ms` for this server, and verify the server can start in this workspace (root_dir/workspace_folders)."
        }));
        steps.push(json!({
            "kind": "command",
            "command": "lspi doctor --workspace-root . --json",
            "message": "Run doctor to confirm the resolved command and preflight status."
        }));
    }

    if message.contains("-32601") || message.to_ascii_lowercase().contains("method not found") {
        steps.push(json!({
            "kind": "config",
            "message": "The language server likely does not support this method/capability. Consider using an alternative tool, upgrading the server, or switching server kind/adapter."
        }));
        steps.push(json!({
            "kind": "tool",
            "tool": "get_server_status",
            "arguments": {},
            "message": "Check server status and last error (if any)."
        }));
    }

    if lspi_kind == Some("outside_allowed_roots")
        || message.contains("outside allowed roots")
        || message.contains("refusing to write outside allowed roots")
    {
        steps.push(json!({
            "kind": "config",
            "message": "Ensure `file_path` is under the configured `workspace_root` or `servers[].workspace_folders` (multi-root). If you run Codex, also ensure you start it from the intended project root."
        }));
    }

    if message.to_ascii_lowercase().contains("timed out") {
        steps.push(json!({
            "kind": "config",
            "message": "Increase `servers[].request_timeout_ms` or set `servers[].request_timeout_overrides_ms` for slow methods (definition/references/rename/documentSymbol)."
        }));
        steps.push(json!({
            "kind": "tool",
            "tool": "get_server_status",
            "arguments": {},
            "message": "Confirm the server is running and not stuck. Consider `restart_server` if it keeps timing out."
        }));
    }

    steps
}

fn mcp_error_to_call_tool_result(
    tool: &str,
    input: Option<Value>,
    err: McpError,
) -> CallToolResult {
    let code = err.code.0;
    let kind = mcp_error_kind_name(code);
    let message = err.message.to_string();
    let next_steps = error_next_steps(tool, &err);

    let mut structured = structured_error(tool, None, input, kind, &message);
    if let Some(obj) = structured.as_object_mut() {
        obj.insert("message".to_string(), Value::String(message.clone()));
        obj.insert("mcp_error_code".to_string(), json!(code));

        if let Some(error_obj) = obj.get_mut("error").and_then(|v| v.as_object_mut()) {
            error_obj.insert("code".to_string(), json!(code));
            if let Some(data) = err.data {
                error_obj.insert("data".to_string(), data);
            }
        }

        if !next_steps.is_empty() {
            obj.insert("next_steps".to_string(), Value::Array(next_steps));
        }
    }

    CallToolResult {
        // Keep a short text fallback for clients that ignore structuredContent.
        content: vec![Content::text(message)],
        structured_content: Some(structured),
        is_error: Some(true),
        meta: None,
    }
}

pub async fn run_stdio() -> Result<()> {
    run_stdio_with_options(McpOptions::default()).await
}

#[derive(Debug, Clone, Default)]
pub struct McpOptions {
    pub config_path: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    pub warmup: bool,
    pub context: Option<String>,
    pub read_only: bool,
    pub read_write: bool,
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

        let mut config = loaded.config;
        let context = options
            .context
            .clone()
            .or_else(|| config.mcp.as_ref().and_then(|m| m.context.clone()));
        apply_mcp_context_defaults(context.as_deref(), &mut config);

        let servers = lspi_core::config::resolved_servers(&config, &workspace_root);
        let allowed_roots = compute_allowed_roots(&workspace_root, &servers);

        let all_tools = tools::all_tools();
        let cfg_read_only = config
            .mcp
            .as_ref()
            .and_then(|m| m.read_only)
            .unwrap_or(false);
        let read_only = if options.read_write {
            false
        } else if options.read_only {
            true
        } else {
            cfg_read_only
        };

        let tools = tools::filter_tools_by_config(all_tools, config.mcp.as_ref());
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
                config,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpContext {
    Full,
    Codex,
    Navigation,
}

fn parse_mcp_context(value: &str) -> Option<McpContext> {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', '_'], "");
    match normalized.as_str() {
        "" => None,
        "full" | "default" => Some(McpContext::Full),
        "codex" => Some(McpContext::Codex),
        "navigation" | "nav" | "readonly" | "read" => Some(McpContext::Navigation),
        _ => None,
    }
}

fn apply_mcp_context_defaults(context: Option<&str>, config: &mut lspi_core::config::LspiConfig) {
    let Some(ctx) = context.and_then(parse_mcp_context) else {
        return;
    };

    config.mcp.get_or_insert(lspi_core::config::McpConfig {
        context: None,
        read_only: None,
        output: None,
        tools: None,
    });

    let mcp = config.mcp.as_mut().unwrap();

    // Preserve explicit config. Only fill in defaults.
    match ctx {
        McpContext::Full => {}
        McpContext::Codex | McpContext::Navigation => {
            if mcp.read_only.is_none() {
                mcp.read_only = Some(true);
            }
        }
    }

    // Output defaults: keep Codex outputs smaller by default.
    let output = mcp
        .output
        .get_or_insert(lspi_core::config::McpOutputConfig {
            max_total_chars_default: None,
            max_total_chars_hard: None,
        });

    if output.max_total_chars_default.is_none() {
        output.max_total_chars_default = Some(match ctx {
            McpContext::Full => 120_000,
            McpContext::Codex => 80_000,
            McpContext::Navigation => 60_000,
        });
    }
}

#[cfg(test)]
mod mcp_context_tests {
    use super::*;

    #[test]
    fn codex_context_defaults_to_read_only_and_smaller_output() {
        let mut cfg = lspi_core::config::LspiConfig::default();
        apply_mcp_context_defaults(Some("codex"), &mut cfg);
        let mcp = cfg.mcp.unwrap();
        assert_eq!(mcp.read_only, Some(true));
        assert_eq!(mcp.output.unwrap().max_total_chars_default, Some(80_000));
    }

    #[test]
    fn explicit_read_only_is_not_overridden_by_context() {
        let mut cfg = lspi_core::config::LspiConfig {
            mcp: Some(lspi_core::config::McpConfig {
                context: Some("codex".to_string()),
                read_only: Some(false),
                output: None,
                tools: None,
            }),
            ..Default::default()
        };
        let ctx = cfg
            .mcp
            .as_ref()
            .and_then(|m| m.context.as_deref())
            .map(|s| s.to_string());
        apply_mcp_context_defaults(ctx.as_deref(), &mut cfg);
        assert_eq!(cfg.mcp.unwrap().read_only, Some(false));
    }
}

#[cfg(test)]
mod mcp_error_mapping_tests {
    use super::*;

    fn structured_next_steps(result: &CallToolResult) -> Vec<Value> {
        let Some(sc) = result.structured_content.as_ref() else {
            return Vec::new();
        };
        let Some(obj) = sc.as_object() else {
            return Vec::new();
        };
        obj.get("next_steps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    }

    fn has_next_step_tool(steps: &[Value], tool: &str) -> bool {
        steps.iter().any(|v| {
            v.as_object()
                .and_then(|o| o.get("tool"))
                .and_then(|t| t.as_str())
                == Some(tool)
        })
    }

    #[test]
    fn routing_extension_error_includes_introspection_next_steps() {
        let err = McpError::invalid_params(
            "no configured LSP server matches file extension: rs",
            Some(json!({
                "lspi_error": { "kind": "no_server_for_extension", "extension": "rs" }
            })),
        );
        let result = mcp_error_to_call_tool_result("find_definition", None, err);
        assert_eq!(result.is_error, Some(true));
        let steps = structured_next_steps(&result);
        assert!(has_next_step_tool(&steps, "list_servers"));
        assert!(has_next_step_tool(&steps, "get_current_config"));
    }

    #[test]
    fn missing_generic_command_includes_doctor_hint() {
        let err = McpError::invalid_params(
            "missing command for generic server id=ts",
            Some(json!({
                "lspi_error": { "kind": "missing_generic_command", "server_id": "ts" }
            })),
        );
        let result = mcp_error_to_call_tool_result("hover_at", None, err);
        let steps = structured_next_steps(&result);
        assert!(steps.iter().any(|v| {
            v.as_object()
                .and_then(|o| o.get("command"))
                .and_then(|c| c.as_str())
                == Some("lspi doctor --workspace-root . --json")
        }));
    }

    #[test]
    fn outside_allowed_roots_includes_config_hint() {
        let err = McpError::invalid_params(
            "file_path is outside allowed roots (workspace_root=\"X\", file_path=\"Y\")",
            Some(json!({
                "lspi_error": { "kind": "outside_allowed_roots" }
            })),
        );
        let result = mcp_error_to_call_tool_result("rename_symbol", None, err);
        let steps = structured_next_steps(&result);
        assert!(steps.iter().any(|v| {
            v.as_object()
                .and_then(|o| o.get("kind"))
                .and_then(|k| k.as_str())
                == Some("config")
        }));
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
        let tool = request.name.clone();
        let input = request.arguments.clone().map(Value::Object);

        if self.state.read_only
            && matches!(
                request.name.as_ref(),
                "rename_symbol" | "rename_symbol_strict" | "restart_server" | "stop_server"
            )
        {
            let tool = request.name.as_ref();
            let input = request.arguments.clone().map(Value::Object);
            let mut structured = structured::structured_error(
                tool,
                None,
                input,
                "read_only",
                "disabled in read-only mode",
            );
            if let Some(obj) = structured.as_object_mut() {
                let err = McpError::invalid_params(
                    "disabled in read-only mode",
                    Some(json!({
                        "lspi_error": { "kind": "read_only" }
                    })),
                );
                let next_steps = error_next_steps(tool, &err);
                if !next_steps.is_empty() {
                    obj.insert("next_steps".to_string(), Value::Array(next_steps));
                }
                obj.insert(
                    "message".to_string(),
                    Value::String("disabled in read-only mode".to_string()),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(format!(
                    "Tool '{tool}' is disabled in read-only mode."
                ))],
                structured_content: Some(structured),
                is_error: Some(true),
                meta: None,
            });
        }

        let result = match request.name.as_ref() {
            "get_current_config" => self.get_current_config(request).await,
            "list_servers" => self.list_servers(request).await,
            "get_server_status" => self.get_server_status(request).await,
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
                // Keep a short text fallback for clients that ignore structuredContent.
                content: vec![Content::text(format!(
                    "Tool '{other}' is not implemented yet."
                ))],
                structured_content: Some({
                    let input = request.arguments.clone().map(Value::Object);
                    let mut structured = structured::structured_error(
                        other,
                        None,
                        input,
                        "not_implemented",
                        "not implemented yet",
                    );
                    if let Some(obj) = structured.as_object_mut() {
                        obj.insert(
                            "next_steps".to_string(),
                            Value::Array(vec![
                                json!({
                                    "kind": "command",
                                    "command": "lspi --version",
                                    "message": "Confirm your lspi version."
                                }),
                                json!({
                                    "kind": "doc",
                                    "message": "Check `CHANGELOG.md` for tool availability, or upgrade lspi."
                                }),
                            ]),
                        );
                        obj.insert(
                            "message".to_string(),
                            Value::String("not implemented yet".to_string()),
                        );
                    }
                    structured
                }),
                is_error: Some(true),
                meta: None,
            }),
        };

        match result {
            Ok(r) => Ok(r),
            Err(err) => Ok(mcp_error_to_call_tool_result(&tool, input, err)),
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
struct GetCurrentConfigArgs {
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_env: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ListServersArgs {
    #[serde(default)]
    max_total_chars: Option<usize>,
    #[serde(default)]
    include_env: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct GetServerStatusArgs {
    #[serde(default)]
    server_id: Option<String>,
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
    let arguments = arguments.unwrap_or_default();
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
