use std::path::{Path, PathBuf};

use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParam, CallToolResult, Content};
use serde_json::{Value, json};
use tracing::warn;
use url::Url;

use crate::{
    DefinitionMatchOut, FindDefinitionArgs, FindDefinitionAtArgs, FindImplementationAtArgs,
    FindIncomingCallsArgs, FindIncomingCallsAtArgs, FindOutgoingCallsArgs, FindOutgoingCallsAtArgs,
    FindReferencesArgs, FindReferencesAtArgs, FindTypeDefinitionAtArgs, GetDocumentSymbolsArgs,
    HoverAtArgs, LocationWithSnippet, LspiMcpServer, ReferenceMatchOut, SearchWorkspaceSymbolsArgs,
    canonicalize_within, effective_max_total_chars, enforce_global_output_caps, hover_to_text,
    is_method_not_found_error, lsp_position_1based, lsp_range_1based, maybe_snippet_for_file_path,
    parse_arguments, structured_error,
};

impl LspiMcpServer {
    pub(crate) async fn get_document_symbols(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetDocumentSymbolsArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(500).clamp(1, 5000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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

    pub(crate) async fn search_workspace_symbols(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: SearchWorkspaceSymbolsArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(100).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let routed = if let Some(file_path) = args.file_path.as_deref() {
            let abs_file = canonicalize_within(
                &self.state.workspace_root,
                &self.state.allowed_roots,
                Path::new(file_path),
            )
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
            let servers = self
                .state
                .servers
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "kind": s.kind,
                        "extensions": s.extensions,
                        "root_dir": s.root_dir.to_string_lossy(),
                        "workspace_folders": s.workspace_folders.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();

            let mut structured_content = json!({
                "ok": true,
                "tool": "search_workspace_symbols",
                "needs_disambiguation": true,
                "message": "multiple servers configured; provide file_path to pick a language server",
                "input": {
                    "query": args.query,
                    "file_path": args.file_path,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars
                },
                "servers": servers,
                "warnings": [],
                "truncated": false
            });
            enforce_global_output_caps(max_total_chars, false, &mut structured_content);

            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Multiple language servers are configured. Provide file_path to select the correct server.",
                )],
                structured_content: Some(structured_content),
                is_error: Some(false),
                meta: None,
            });
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

    pub(crate) async fn find_definition(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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

        let root = &self.state.workspace_root;

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
                        root,
                        &self.state.allowed_roots,
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

    pub(crate) async fn find_definition_at(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
            let mut structured_content = structured_error(
                "find_definition_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "snippet_context_lines": snippet_context_lines,
                    "max_snippet_chars": max_snippet_chars
                })),
                "lsp_error",
                "definition lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("definition lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Definition lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
                is_error: Some(true),
                meta: None,
            });
        };

        let root = &self.state.workspace_root;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut defs = Vec::new();
        for d in definitions {
            let snippet = if include_snippet {
                match maybe_snippet_for_file_path(
                    root,
                    &self.state.allowed_roots,
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

    pub(crate) async fn find_references_at(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
            let mut structured_content = structured_error(
                "find_references_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "include_declaration": include_declaration,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "snippet_context_lines": snippet_context_lines,
                    "max_snippet_chars": max_snippet_chars
                })),
                "lsp_error",
                "reference lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("reference lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Reference lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
                is_error: Some(true),
                meta: None,
            });
        };

        let root = &self.state.workspace_root;

        let mut snippet_truncated = false;
        let mut snippet_skipped = 0usize;

        let mut refs = Vec::new();
        for r in references {
            let snippet = if include_snippet {
                match maybe_snippet_for_file_path(
                    root,
                    &self.state.allowed_roots,
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

    pub(crate) async fn hover_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: HoverAtArgs = parse_arguments(request.arguments)?;

        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
            let mut structured_content = structured_error(
                "hover_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_total_chars": max_total_chars
                })),
                "lsp_error",
                "hover lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("hover lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Hover lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
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

    pub(crate) async fn find_implementation_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindImplementationAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(50).clamp(1, 500);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
                let mut structured_content = json!({
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
                });
                crate::structured::ensure_common_fields(&mut structured_content);
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Implementation lookup is not supported by this language server.",
                    )],
                    structured_content: Some(structured_content),
                    is_error: Some(false),
                    meta: None,
                });
            }

            let mut structured_content = structured_error(
                "find_implementation_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars
                })),
                "lsp_error",
                "implementation lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("implementation lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Implementation lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
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

    pub(crate) async fn find_type_definition_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindTypeDefinitionAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(50).clamp(1, 500);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
                let mut structured_content = json!({
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
                });
                crate::structured::ensure_common_fields(&mut structured_content);
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Type definition lookup is not supported by this language server.",
                    )],
                    structured_content: Some(structured_content),
                    is_error: Some(false),
                    meta: None,
                });
            }

            let mut structured_content = structured_error(
                "find_type_definition_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars
                })),
                "lsp_error",
                "type definition lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("type definition lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Type definition lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
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

    pub(crate) async fn find_incoming_calls(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
            let mut structured_content = structured_error(
                "find_incoming_calls",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "symbol_name": args.symbol_name,
                    "symbol_kind": args.symbol_kind,
                    "max_symbols": max_symbols,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "max_snippet_chars": max_snippet_chars
                })),
                "no_match",
                "no matching symbols found",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("no matching symbols found".to_string()),
                );
                obj.insert("candidates".to_string(), Value::Array(Vec::new()));
            }
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(structured_content),
                is_error: Some(true),
                meta: None,
            });
        }

        if candidates.len() > 1 {
            let root = &self.state.workspace_root;
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
                        root,
                        &self.state.allowed_roots,
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
                    let mut structured_content = json!({
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
                    });
                    crate::structured::ensure_common_fields(&mut structured_content);
                    return Ok(CallToolResult {
                        content: vec![Content::text(
                            "Call hierarchy is not supported by this language server.",
                        )],
                        structured_content: Some(structured_content),
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

    pub(crate) async fn find_outgoing_calls(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
            let mut structured_content = structured_error(
                "find_outgoing_calls",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "symbol_name": args.symbol_name,
                    "symbol_kind": args.symbol_kind,
                    "max_symbols": max_symbols,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars,
                    "include_snippet": include_snippet,
                    "max_snippet_chars": max_snippet_chars
                })),
                "no_match",
                "no matching symbols found",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("no matching symbols found".to_string()),
                );
                obj.insert("candidates".to_string(), Value::Array(Vec::new()));
            }
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(structured_content),
                is_error: Some(true),
                meta: None,
            });
        }

        if candidates.len() > 1 {
            let root = &self.state.workspace_root;
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
                        root,
                        &self.state.allowed_roots,
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
                    let mut structured_content = json!({
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
                    });
                    crate::structured::ensure_common_fields(&mut structured_content);
                    return Ok(CallToolResult {
                        content: vec![Content::text(
                            "Call hierarchy is not supported by this language server.",
                        )],
                        structured_content: Some(structured_content),
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

    pub(crate) async fn find_incoming_calls_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindIncomingCallsAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
                let mut structured_content = json!({
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
                });
                crate::structured::ensure_common_fields(&mut structured_content);
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Call hierarchy is not supported by this language server.",
                    )],
                    structured_content: Some(structured_content),
                    is_error: Some(false),
                    meta: None,
                });
            }

            let mut structured_content = structured_error(
                "find_incoming_calls_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars
                })),
                "lsp_error",
                "call hierarchy lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("call hierarchy lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Call hierarchy lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
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

    pub(crate) async fn find_outgoing_calls_at(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: FindOutgoingCallsAtArgs = parse_arguments(request.arguments)?;

        let max_results = args.max_results.unwrap_or(200).clamp(1, 2000);
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let file_path = PathBuf::from(&args.file_path);
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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
                let mut structured_content = json!({
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
                });
                crate::structured::ensure_common_fields(&mut structured_content);
                return Ok(CallToolResult {
                    content: vec![Content::text(
                        "Call hierarchy is not supported by this language server.",
                    )],
                    structured_content: Some(structured_content),
                    is_error: Some(false),
                    meta: None,
                });
            }

            let mut structured_content = structured_error(
                "find_outgoing_calls_at",
                Some(&server_id),
                Some(json!({
                    "file_path": args.file_path,
                    "line": args.line,
                    "character": args.character,
                    "max_results": max_results,
                    "max_total_chars": max_total_chars
                })),
                "lsp_error",
                "call hierarchy lookup failed",
            );
            if let Some(obj) = structured_content.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("call hierarchy lookup failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text(
                    "Call hierarchy lookup failed at the provided position.",
                )],
                structured_content: Some(structured_content),
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

    pub(crate) async fn find_references(
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
        let abs_file = canonicalize_within(
            &self.state.workspace_root,
            &self.state.allowed_roots,
            &file_path,
        )
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

        let root = &self.state.workspace_root;

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
                        root,
                        &self.state.allowed_roots,
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
}

#[cfg(test)]
mod search_workspace_symbols_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use rmcp::model::CallToolRequestParam;
    use serde_json::Value;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    use crate::{LspiMcpServer, LspiState, compute_allowed_roots};

    #[tokio::test]
    async fn returns_disambiguation_payload_when_multiple_servers_configured() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path().to_path_buf();

        let servers = vec![
            lspi_core::config::ResolvedServerConfig {
                id: "ra".to_string(),
                kind: "rust_analyzer".to_string(),
                command: None,
                args: Vec::new(),
                extensions: vec!["rs".to_string()],
                language_id: Some("rust".to_string()),
                root_dir: root.clone(),
                cwd: root.clone(),
                workspace_folders: Vec::new(),
                env: HashMap::new(),
                adapter: None,
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
            lspi_core::config::ResolvedServerConfig {
                id: "go".to_string(),
                kind: "generic".to_string(),
                command: Some("gopls".to_string()),
                args: vec!["serve".to_string()],
                extensions: vec!["go".to_string()],
                language_id: Some("go".to_string()),
                root_dir: root.clone(),
                cwd: root.clone(),
                workspace_folders: Vec::new(),
                env: HashMap::new(),
                adapter: None,
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
        ];

        let allowed_roots = compute_allowed_roots(&root, &servers);

        let server = LspiMcpServer {
            tools: Arc::new(Vec::new()),
            state: Arc::new(LspiState {
                workspace_root: root,
                allowed_roots,
                read_only: false,
                config: lspi_core::config::LspiConfig::default(),
                servers,
                rust_analyzer: Mutex::new(HashMap::new()),
                omnisharp: Mutex::new(HashMap::new()),
                generic: Mutex::new(HashMap::new()),
            }),
        };

        let mut arguments = serde_json::Map::new();
        arguments.insert("query".to_string(), Value::String("foo".to_string()));

        let out = server
            .search_workspace_symbols(CallToolRequestParam {
                name: "search_workspace_symbols".into(),
                arguments: Some(arguments),
                task: None,
            })
            .await
            .unwrap();

        let structured = out.structured_content.unwrap();
        assert_eq!(
            structured["tool"],
            Value::String("search_workspace_symbols".to_string())
        );
        assert_eq!(structured["needs_disambiguation"], Value::Bool(true));
        assert!(structured["servers"].as_array().unwrap().len() >= 2);
    }
}
