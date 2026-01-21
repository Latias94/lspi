use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
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
use tracing::warn;
use url::Url;

const DEFAULT_MAX_TOTAL_CHARS: usize = 120_000;
const MIN_MAX_TOTAL_CHARS: usize = 10_000;
const ABS_MAX_TOTAL_CHARS: usize = 2_000_000;

pub async fn run_stdio() -> Result<()> {
    let service = LspiMcpServer::new(McpOptions::default())?;
    let running = service
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    running.waiting().await?;
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct McpOptions {
    pub config_path: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
}

pub async fn run_stdio_with_options(options: McpOptions) -> Result<()> {
    let service = LspiMcpServer::new(options)?;
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
    fn new(options: McpOptions) -> Result<Self> {
        let loaded = lspi_core::config::load_config(
            options.config_path.as_deref(),
            options.workspace_root.as_deref(),
        )?;
        let servers = lspi_core::config::resolved_servers(&loaded.config, &loaded.workspace_root);

        Ok(Self {
            tools: Arc::new(vec![
                tool_find_definition(),
                tool_find_definition_at(),
                tool_find_references(),
                tool_find_references_at(),
                tool_rename_symbol(),
                tool_rename_symbol_strict(),
                tool_get_diagnostics(),
                tool_restart_server(),
            ]),
            state: Arc::new(LspiState {
                workspace_root: loaded.workspace_root,
                config: loaded.config,
                servers,
                rust_analyzer: Mutex::new(HashMap::new()),
            }),
        })
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
            "get_diagnostics" => self.get_diagnostics(request).await,
            "rename_symbol" => self.rename_symbol(request).await,
            "rename_symbol_strict" => self.rename_symbol_strict(request).await,
            "restart_server" => self.restart_server(request).await,
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

struct LspiState {
    workspace_root: PathBuf,
    config: lspi_core::config::LspiConfig,
    servers: Vec<lspi_core::config::ResolvedServerConfig>,
    rust_analyzer: Mutex<HashMap<String, Arc<lspi_lsp::RustAnalyzerClient>>>,
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

fn effective_max_total_chars(
    config: &lspi_core::config::LspiConfig,
    requested: Option<usize>,
) -> (usize, Option<Value>) {
    let output = config.mcp.as_ref().and_then(|m| m.output.as_ref());

    let hard = output
        .and_then(|o| o.max_total_chars_hard)
        .unwrap_or(ABS_MAX_TOTAL_CHARS)
        .clamp(MIN_MAX_TOTAL_CHARS, ABS_MAX_TOTAL_CHARS);

    let default_value = output
        .and_then(|o| o.max_total_chars_default)
        .unwrap_or(DEFAULT_MAX_TOTAL_CHARS)
        .clamp(MIN_MAX_TOTAL_CHARS, hard);

    let effective = requested
        .unwrap_or(default_value)
        .clamp(MIN_MAX_TOTAL_CHARS, hard);

    let warning = requested.and_then(|req| {
        if req == effective {
            None
        } else {
            Some(json!({
                "kind": "max_total_chars_clamped",
                "message": "Requested max_total_chars was clamped by policy.",
                "requested": req,
                "effective": effective,
                "hard": hard,
                "min": MIN_MAX_TOTAL_CHARS
            }))
        }
    });

    (effective, warning)
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

impl LspiMcpServer {
    async fn rust_analyzer_for_file(
        &self,
        abs_file: &Path,
    ) -> Result<(String, Arc<lspi_lsp::RustAnalyzerClient>), McpError> {
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

        if !is_rust_analyzer_kind(&server.kind) {
            return Err(McpError::invalid_params(
                format!(
                    "server kind is not supported yet (only rust_analyzer): id={} kind={}",
                    server.id, server.kind
                ),
                None,
            ));
        }

        let existing = {
            let guard = self.state.rust_analyzer.lock().await;
            guard.get(&server.id).cloned()
        };
        if let Some(existing) = existing {
            return Ok((server.id.clone(), existing));
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
            warmup_timeout,
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);

        let inserted = {
            let mut guard = self.state.rust_analyzer.lock().await;
            if let Some(existing) = guard.get(&server.id) {
                Some(existing.clone())
            } else {
                guard.insert(server.id.clone(), arc.clone());
                None
            }
        };

        if let Some(existing) = inserted {
            if Arc::strong_count(&arc) == 1 {
                if let Ok(client) = Arc::try_unwrap(arc) {
                    let _ = client.shutdown().await;
                }
            }
            return Ok((server.id.clone(), existing));
        }

        Ok((server.id.clone(), arc))
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let matches = ra
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

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
            match ra.definition_at(&abs_file, pos.clone(), max_results).await {
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
        if let Some(used) = used_pos.clone() {
            if used.line != best_guess.line || used.character != best_guess.character {
                warnings.push(json!({
                    "kind": "position_fuzzing",
                    "message": "Applied bounded position fuzzing to locate the symbol position.",
                    "input": { "line": args.line, "character": args.character },
                    "used_lsp_position": { "line": used.line, "character": used.character }
                }));
            }
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

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
            match ra
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
        if let Some(used) = used_pos.clone() {
            if used.line != best_guess.line || used.character != best_guess.character {
                warnings.push(json!({
                    "kind": "position_fuzzing",
                    "message": "Applied bounded position fuzzing to locate the symbol position.",
                    "input": { "line": args.line, "character": args.character },
                    "used_lsp_position": { "line": used.line, "character": used.character }
                }));
            }
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let matches = ra
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

        let mut diagnostics = ra
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

        let kind_num = args
            .symbol_kind
            .as_deref()
            .and_then(lspi_lsp::parse_symbol_kind);

        let candidates = ra
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

        let changes = ra
            .rename_at(&abs_file, pos, &args.new_name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let preview = workspace_edit_preview(&changes)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if !dry_run {
            let apply_result = apply_workspace_edit(
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

        let (server_id, ra) = self.rust_analyzer_for_file(&abs_file).await?;

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
            match ra
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

        let preview = workspace_edit_preview(&changes)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos {
            if used.line != best_guess.line || used.character != best_guess.character {
                warnings.push(json!({
                    "kind": "position_fuzzing",
                    "message": "Applied bounded position fuzzing to locate the symbol position.",
                    "input": { "line": args.line, "character": args.character },
                    "used_lsp_position": { "line": used.line, "character": used.character }
                }));
            }
        }

        if !dry_run {
            let apply_result = apply_workspace_edit(
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

        for id in target_server_ids {
            let ra_arc = {
                let mut guard = self.state.rust_analyzer.lock().await;
                guard.remove(&id)
            };

            let Some(ra_arc) = ra_arc else {
                warnings.push(json!({
                    "kind": "server_not_running",
                    "server_id": id,
                    "message": "server is not running"
                }));
                continue;
            };

            if Arc::strong_count(&ra_arc) > 1 {
                let mut guard = self.state.rust_analyzer.lock().await;
                guard.insert(id.clone(), ra_arc);
                busy.push(id);
                continue;
            }

            match Arc::try_unwrap(ra_arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    restarted.push(id);
                }
                Err(arc) => {
                    let mut guard = self.state.rust_analyzer.lock().await;
                    guard.insert(id.clone(), arc);
                    busy.push(id);
                }
            }
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
}

fn is_rust_analyzer_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "rust_analyzer" || normalized == "rust"
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct WorkspaceEditPreviewFile {
    uri: String,
    file_path: Option<String>,
    before_sha256: Option<String>,
    edits: Vec<lspi_lsp::LspTextEdit>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct WorkspaceEditPreview {
    files: Vec<WorkspaceEditPreviewFile>,
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

#[derive(Debug, serde::Serialize)]
struct ApplyWorkspaceEditResult {
    files_modified: Vec<String>,
    backup_files: Vec<String>,
}

async fn workspace_edit_preview(
    changes: &std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>,
) -> anyhow::Result<WorkspaceEditPreview> {
    let mut files = Vec::new();
    for (uri, edits) in changes {
        let (file_path, before_sha256) = match uri_to_path_maybe(uri).await {
            Ok(Some(path)) => {
                let bytes = tokio::fs::read(&path).await.ok();
                let hash = bytes.as_deref().map(lspi_core::hashing::sha256_hex);
                (Some(path.to_string_lossy().to_string()), hash)
            }
            Ok(None) => (None, None),
            Err(_) => (None, None),
        };

        files.push(WorkspaceEditPreviewFile {
            uri: uri.clone(),
            file_path,
            before_sha256,
            edits: edits.clone(),
        });
    }
    Ok(WorkspaceEditPreview { files })
}

async fn uri_to_path_maybe(uri: &str) -> anyhow::Result<Option<PathBuf>> {
    let url = Url::parse(uri)?;
    if url.scheme() != "file" {
        return Ok(None);
    }
    Ok(url.to_file_path().ok())
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

async fn apply_workspace_edit(
    workspace_root: &Path,
    changes: &std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>,
    expected_before_sha256: Option<&std::collections::HashMap<String, String>>,
    create_backups: bool,
    backup_suffix: &str,
) -> anyhow::Result<ApplyWorkspaceEditResult> {
    let root = workspace_root.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize workspace root: {}",
            workspace_root.to_string_lossy()
        )
    })?;

    struct FileState {
        uri: String,
        path: PathBuf,
        original_bytes: Vec<u8>,
        backup_path: Option<PathBuf>,
        edits: Vec<lspi_core::text_edit::TextEdit>,
    }

    let mut files = Vec::<FileState>::new();

    for (uri, edits) in changes {
        let Some(path) = uri_to_path_maybe(uri).await? else {
            return Err(anyhow::anyhow!(
                "unsupported edit URI (only file:// supported): {uri}"
            ));
        };

        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {path:?}"))?;
        if !canonical.starts_with(&root) {
            return Err(anyhow::anyhow!(
                "refusing to write outside workspace root (root={:?}, path={:?})",
                root,
                canonical
            ));
        }

        let original_bytes = tokio::fs::read(&canonical)
            .await
            .with_context(|| format!("failed to read file: {canonical:?}"))?;

        let current_hash = lspi_core::hashing::sha256_hex(&original_bytes);
        if let Some(expected) = expected_before_sha256 {
            let key = canonical.to_string_lossy().to_string();
            let Some(want) = expected.get(&key) else {
                return Err(anyhow::anyhow!(
                    "missing expected_before_sha256 entry for {key}"
                ));
            };
            if want != &current_hash {
                return Err(anyhow::anyhow!(
                    "sha256 mismatch for {} (expected={}, got={})",
                    key,
                    want,
                    current_hash
                ));
            }
        }

        let mut converted = Vec::with_capacity(edits.len());
        for e in edits {
            converted.push(lspi_core::text_edit::TextEdit {
                range: lspi_core::text_edit::Range {
                    start: lspi_core::text_edit::Position {
                        line: e.range.start.line,
                        character: e.range.start.character,
                    },
                    end: lspi_core::text_edit::Position {
                        line: e.range.end.line,
                        character: e.range.end.character,
                    },
                },
                new_text: e.new_text.clone(),
            });
        }

        files.push(FileState {
            uri: uri.clone(),
            path: canonical,
            original_bytes,
            backup_path: None,
            edits: converted,
        });
    }

    let mut files_modified = Vec::new();
    let mut backup_files = Vec::new();

    for f in &mut files {
        if create_backups {
            let backup_path =
                PathBuf::from(format!("{}{}", f.path.to_string_lossy(), backup_suffix));
            tokio::fs::write(&backup_path, &f.original_bytes)
                .await
                .with_context(|| format!("failed to write backup file: {backup_path:?}"))?;
            backup_files.push(backup_path.to_string_lossy().to_string());
            f.backup_path = Some(backup_path);
        }
    }

    let apply_result: anyhow::Result<()> = async {
        for f in &files {
            let original_text =
                String::from_utf8(f.original_bytes.clone()).context("file is not valid UTF-8")?;
            let new_text = lspi_core::text_edit::apply_text_edits_utf16(&original_text, &f.edits)?;
            write_best_effort_atomic(&f.path, new_text.as_bytes()).await?;
            files_modified.push(f.path.to_string_lossy().to_string());
        }
        Ok(())
    }
    .await;

    if let Err(err) = apply_result {
        for f in &files {
            let _ = tokio::fs::write(&f.path, &f.original_bytes).await;
        }
        for f in &files {
            if let Some(backup_path) = &f.backup_path {
                let _ = tokio::fs::remove_file(backup_path).await;
            }
        }
        return Err(err);
    }

    Ok(ApplyWorkspaceEditResult {
        files_modified,
        backup_files,
    })
}

async fn write_best_effort_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {path:?}"))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name: {path:?}"))?
        .to_string_lossy();

    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    let tmp_path = parent.join(format!(".{file_name}.lspi-tmp-{nonce}"));
    tokio::fs::write(&tmp_path, bytes)
        .await
        .with_context(|| format!("failed to write temp file: {tmp_path:?}"))?;

    match tokio::fs::rename(&tmp_path, path).await {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            let _ = tokio::fs::remove_file(path).await;
            match tokio::fs::rename(&tmp_path, path).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    Err(anyhow::anyhow!(
                        "failed to replace file: {path:?} (rename_err={rename_err}, err={err})"
                    ))
                }
            }
        }
    }
}

fn enforce_global_output_caps(max_total_chars: usize, include_snippet: bool, payload: &mut Value) {
    let Some(tool) = payload
        .get("tool")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return;
    };

    if json_len(payload) <= max_total_chars {
        return;
    }

    let mut warnings = payload
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut changed = false;

    // 1) Drop snippets (cheap win).
    if include_snippet {
        if let Some(results) = payload.get_mut("results") {
            strip_snippets(results);
            warnings.push(json!({
                "kind": "global_cap_dropped_snippet",
                "message": "Dropped snippets to satisfy max_total_chars.",
                "max_total_chars": max_total_chars
            }));
            changed = true;
        }
    }

    // 2) Truncate the main arrays until size is below cap.
    if json_len(payload) > max_total_chars {
        match tool.as_str() {
            "get_diagnostics" => {
                while json_len(payload) > max_total_chars {
                    let len = payload
                        .get("diagnostics")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if len <= 1 {
                        break;
                    }
                    {
                        let diags = payload
                            .get_mut("diagnostics")
                            .and_then(|v| v.as_array_mut())
                            .unwrap();
                        diags.truncate((len + 1) / 2);
                    }
                    changed = true;
                }
                let diag_len = payload
                    .get("diagnostics")
                    .and_then(|v| v.as_array())
                    .map(|diags| diags.len());
                if let (Some(diag_len), Some(count)) = (diag_len, payload.get_mut("count")) {
                    *count = Value::Number(serde_json::Number::from(diag_len));
                }
            }
            "find_definition" | "find_references" => {
                while json_len(payload) > max_total_chars {
                    let total_locations = payload
                        .get("results")
                        .and_then(|v| v.as_array())
                        .map(|results| count_locations(results.as_slice()))
                        .unwrap_or(0);
                    if total_locations <= 1 {
                        break;
                    }
                    let target = (total_locations + 1) / 2;
                    {
                        let results = payload
                            .get_mut("results")
                            .and_then(|v| v.as_array_mut())
                            .unwrap();
                        truncate_locations(results, target);
                    }
                    changed = true;
                }

                let total = payload
                    .get("results")
                    .and_then(|v| v.as_array())
                    .map(|results| count_locations(results.as_slice()))
                    .unwrap_or(0);

                if tool == "find_definition" {
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert(
                            "definition_locations".to_string(),
                            Value::Number(serde_json::Number::from(total)),
                        );
                    }
                }
                if tool == "find_references" {
                    if let Some(obj) = payload.as_object_mut() {
                        obj.insert(
                            "reference_locations".to_string(),
                            Value::Number(serde_json::Number::from(total)),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    if json_len(payload) > max_total_chars {
        // Worst-case fallback: keep metadata + warnings, drop large payloads.
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("results".to_string(), Value::Array(Vec::new()));
            obj.insert("diagnostics".to_string(), Value::Array(Vec::new()));
        }
        warnings.push(json!({
            "kind": "global_cap_cleared_results",
            "message": "Cleared results to satisfy max_total_chars.",
            "max_total_chars": max_total_chars
        }));
        changed = true;
    }

    if changed {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("warnings".to_string(), Value::Array(warnings));
            obj.insert("truncated".to_string(), Value::Bool(true));
        }
    }
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
}

fn strip_snippets(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for v in arr {
                strip_snippets(v);
            }
        }
        Value::Object(map) => {
            map.remove("snippet");
            for (_, v) in map.iter_mut() {
                strip_snippets(v);
            }
        }
        _ => {}
    }
}

fn count_locations(results: &[Value]) -> usize {
    let mut total = 0usize;
    for r in results {
        if let Some(defs) = r.get("definitions").and_then(|v| v.as_array()) {
            total += defs.len();
        }
        if let Some(refs) = r.get("references").and_then(|v| v.as_array()) {
            total += refs.len();
        }
    }
    total
}

fn truncate_locations(results: &mut [Value], mut remaining: usize) {
    for r in results {
        if remaining == 0 {
            if let Some(defs) = r.get_mut("definitions").and_then(|v| v.as_array_mut()) {
                defs.clear();
            }
            if let Some(refs) = r.get_mut("references").and_then(|v| v.as_array_mut()) {
                refs.clear();
            }
            continue;
        }

        if let Some(defs) = r.get_mut("definitions").and_then(|v| v.as_array_mut()) {
            if defs.len() > remaining {
                defs.truncate(remaining);
                remaining = 0;
            } else {
                remaining -= defs.len();
            }
        }
        if let Some(refs) = r.get_mut("references").and_then(|v| v.as_array_mut()) {
            if remaining == 0 {
                refs.clear();
            } else if refs.len() > remaining {
                refs.truncate(remaining);
                remaining = 0;
            } else {
                remaining -= refs.len();
            }
        }
    }
}

#[cfg(test)]
mod output_caps_tests {
    use super::*;

    #[test]
    fn drops_snippets_and_truncates_results() {
        let mut payload = json!({
            "ok": true,
            "tool": "find_definition",
            "results": [{
                "symbol": {"name":"x"},
                "definitions": (0..100).map(|_| json!({
                    "file_path": "a.rs",
                    "uri": "file:///a.rs",
                    "range": {"start":{"line":0,"character":0},"end":{"line":0,"character":1}},
                    "snippet": {"start_line":0,"text":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","truncated":false}
                })).collect::<Vec<_>>()
            }],
            "warnings": [],
            "definition_locations": 100,
            "truncated": false
        });

        enforce_global_output_caps(2000, true, &mut payload);
        assert_eq!(payload.get("truncated"), Some(&Value::Bool(true)));
        let len = json_len(&payload);
        assert!(len <= 2000);
        // Ensure snippet keys are removed
        let defs = payload["results"][0]["definitions"].as_array().unwrap();
        assert!(defs.iter().all(|d| d.get("snippet").is_none()));
    }
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

#[cfg(test)]
mod apply_workspace_edit_tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use url::Url;

    use super::apply_workspace_edit;

    fn file_uri(path: &Path) -> String {
        Url::from_file_path(path).unwrap().to_string()
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

        let backup_path = PathBuf::from(format!("{}{}", canonical.to_string_lossy(), ".bak"));
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

        let backup_path = PathBuf::from(format!("{}{}", canonical.to_string_lossy(), ".bak"));
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
        Cow::Borrowed("Find definition locations for a symbol in a file."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "max_results": { "type": "integer", "minimum": 1 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400 }
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
                "max_results": { "type": "integer", "minimum": 1 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": true },
                "snippet_context_lines": { "type": "integer", "minimum": 0, "default": 1 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400 }
            },
            "required": ["file_path", "line", "character"],
            "additionalProperties": false
        }))),
    )
}

fn tool_find_references() -> Tool {
    Tool::new(
        Cow::Borrowed("find_references"),
        Cow::Borrowed("Find references for a symbol across the workspace."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "file_path": { "type": "string" },
                "symbol_name": { "type": "string" },
                "symbol_kind": { "type": "string" },
                "include_declaration": { "type": "boolean", "default": true },
                "max_results": { "type": "integer", "minimum": 1 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": false },
                "snippet_context_lines": { "type": "integer", "minimum": 0 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400 }
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
                "max_results": { "type": "integer", "minimum": 1 },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_snippet": { "type": "boolean", "default": false },
                "snippet_context_lines": { "type": "integer", "minimum": 0 },
                "max_snippet_chars": { "type": "integer", "minimum": 40, "default": 400 }
            },
            "required": ["file_path", "line", "character"],
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
        Cow::Borrowed("Get diagnostics for a file."),
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

fn schema(value: serde_json::Value) -> JsonObject {
    #[expect(clippy::expect_used)]
    serde_json::from_value(value).expect("tool schema should deserialize")
}
