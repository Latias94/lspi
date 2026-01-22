use std::path::PathBuf;

use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParam, CallToolResult, Content};
use serde_json::{Value, json};
use url::Url;

use crate::{
    LspiMcpServer, RenameSymbolArgs, RenameSymbolStrictArgs, canonicalize_within,
    maybe_snippet_for_file_path, parse_arguments, structured_error, structured_ok, workspace_edit,
};

impl LspiMcpServer {
    pub(crate) async fn rename_symbol(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: RenameSymbolArgs = parse_arguments(request.arguments)?;
        let dry_run = args.dry_run.unwrap_or(true);

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
            .list_symbol_candidates(&abs_file, &args.symbol_name, kind_num, 50)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if candidates.is_empty() {
            let input = json!({
                "file_path": args.file_path,
                "symbol_name": args.symbol_name,
                "symbol_kind": args.symbol_kind,
                "new_name": args.new_name,
                "dry_run": dry_run
            });
            let mut structured = structured_error(
                "rename_symbol",
                Some(&server_id),
                Some(input),
                "no_match",
                "no matching symbols found",
            );
            if let Some(obj) = structured.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("no matching symbols found".to_string()),
                );
                obj.insert("candidates".to_string(), Value::Array(Vec::new()));
            }
            return Ok(CallToolResult {
                content: vec![Content::text("No matching symbols found.")],
                structured_content: Some(structured),
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
                let selection_start_0based = lspi_lsp::LspPosition {
                    line: c.selection_range.start.line,
                    character: c.selection_range.start.character,
                };

                let snippet = match maybe_snippet_for_file_path(
                    root,
                    &self.state.allowed_roots,
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
                structured_content: Some({
                    let mut structured = structured_ok(
                        "rename_symbol",
                        Some(&server_id),
                        json!({
                            "file_path": args.file_path,
                            "symbol_name": args.symbol_name,
                            "symbol_kind": args.symbol_kind,
                            "new_name": args.new_name,
                            "dry_run": true
                        }),
                    );
                    if let Some(obj) = structured.as_object_mut() {
                        obj.insert("needs_disambiguation".to_string(), Value::Bool(true));
                        obj.insert("candidates".to_string(), Value::Array(candidates_out));
                        obj.insert("dry_run".to_string(), Value::Bool(true));
                        obj.insert("warnings".to_string(), Value::Array(warnings));
                    }
                    structured
                }),
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
                &self.state.allowed_roots,
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
                structured_content: Some({
                    let mut structured = structured_ok(
                        "rename_symbol",
                        Some(&server_id),
                        json!({
                            "file_path": args.file_path,
                            "symbol_name": args.symbol_name,
                            "symbol_kind": args.symbol_kind,
                            "new_name": args.new_name,
                            "dry_run": false,
                            "expected_before_sha256": args.expected_before_sha256,
                            "create_backups": args.create_backups,
                            "backup_suffix": args.backup_suffix
                        }),
                    );
                    if let Some(obj) = structured.as_object_mut() {
                        obj.insert("dry_run".to_string(), Value::Bool(false));
                        obj.insert(
                            "symbol".to_string(),
                            serde_json::to_value(candidate).unwrap_or(Value::Null),
                        );
                        obj.insert("new_name".to_string(), Value::String(args.new_name));
                        obj.insert(
                            "edit".to_string(),
                            serde_json::to_value(preview).unwrap_or(Value::Null),
                        );
                        obj.insert(
                            "apply".to_string(),
                            serde_json::to_value(apply_result).unwrap_or(Value::Null),
                        );
                    }
                    structured
                }),
                is_error: Some(false),
                meta: None,
            });
        }

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Preview rename: {} files affected.",
                preview.files.len()
            ))],
            structured_content: Some({
                let mut structured = structured_ok(
                    "rename_symbol",
                    Some(&server_id),
                    json!({
                        "file_path": args.file_path,
                        "symbol_name": args.symbol_name,
                        "symbol_kind": args.symbol_kind,
                        "new_name": args.new_name,
                        "dry_run": true,
                        "expected_before_sha256": args.expected_before_sha256,
                        "create_backups": args.create_backups,
                        "backup_suffix": args.backup_suffix
                    }),
                );
                if let Some(obj) = structured.as_object_mut() {
                    obj.insert("dry_run".to_string(), Value::Bool(true));
                    obj.insert(
                        "symbol".to_string(),
                        serde_json::to_value(candidate).unwrap_or(Value::Null),
                    );
                    obj.insert("new_name".to_string(), Value::String(args.new_name));
                    obj.insert(
                        "edit".to_string(),
                        serde_json::to_value(preview).unwrap_or(Value::Null),
                    );
                }
                structured
            }),
            is_error: Some(false),
            meta: None,
        })
    }

    pub(crate) async fn rename_symbol_strict(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: RenameSymbolStrictArgs = parse_arguments(request.arguments)?;
        let dry_run = args.dry_run.unwrap_or(true);

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
            let input = json!({
                "file_path": args.file_path,
                "line": args.line,
                "character": args.character,
                "new_name": args.new_name,
                "dry_run": dry_run
            });
            let mut structured = structured_error(
                "rename_symbol_strict",
                Some(&server_id),
                Some(input),
                "rename_failed",
                "rename failed",
            );
            if let Some(obj) = structured.as_object_mut() {
                obj.insert(
                    "message".to_string(),
                    Value::String("rename failed".to_string()),
                );
                obj.insert(
                    "cause".to_string(),
                    last_err
                        .map(|e| Value::String(e.to_string()))
                        .unwrap_or(Value::Null),
                );
            }
            return Ok(CallToolResult {
                content: vec![Content::text("Rename failed at the provided position.")],
                structured_content: Some(structured),
                is_error: Some(true),
                meta: None,
            });
        };

        let preview = workspace_edit::workspace_edit_preview(&changes)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut warnings = Vec::<Value>::new();
        if let Some(used) = used_pos.as_ref()
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
                &self.state.allowed_roots,
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
                structured_content: Some({
                    let mut structured = structured_ok(
                        "rename_symbol_strict",
                        Some(&server_id),
                        json!({
                            "file_path": args.file_path,
                            "line": args.line,
                            "character": args.character,
                            "new_name": args.new_name.clone(),
                            "dry_run": false,
                            "expected_before_sha256": args.expected_before_sha256,
                            "create_backups": args.create_backups,
                            "backup_suffix": args.backup_suffix
                        }),
                    );
                    if let Some(obj) = structured.as_object_mut() {
                        obj.insert("dry_run".to_string(), Value::Bool(false));
                        obj.insert(
                            "used_lsp_position".to_string(),
                            used_pos
                                .as_ref()
                                .map(|p| json!({"line": p.line, "character": p.character}))
                                .unwrap_or(Value::Null),
                        );
                        obj.insert("new_name".to_string(), Value::String(args.new_name.clone()));
                        obj.insert(
                            "edit".to_string(),
                            serde_json::to_value(preview).unwrap_or(Value::Null),
                        );
                        obj.insert(
                            "apply".to_string(),
                            serde_json::to_value(apply_result).unwrap_or(Value::Null),
                        );
                        obj.insert("warnings".to_string(), Value::Array(warnings));
                    }
                    structured
                }),
                is_error: Some(false),
                meta: None,
            });
        }

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Preview rename: {} files affected.",
                preview.files.len()
            ))],
            structured_content: Some({
                let mut structured = structured_ok(
                    "rename_symbol_strict",
                    Some(&server_id),
                    json!({
                        "file_path": args.file_path,
                        "line": args.line,
                        "character": args.character,
                        "new_name": args.new_name.clone(),
                        "dry_run": true,
                        "expected_before_sha256": args.expected_before_sha256,
                        "create_backups": args.create_backups,
                        "backup_suffix": args.backup_suffix
                    }),
                );
                if let Some(obj) = structured.as_object_mut() {
                    obj.insert("dry_run".to_string(), Value::Bool(true));
                    obj.insert(
                        "used_lsp_position".to_string(),
                        used_pos
                            .as_ref()
                            .map(|p| json!({"line": p.line, "character": p.character}))
                            .unwrap_or(Value::Null),
                    );
                    obj.insert("new_name".to_string(), Value::String(args.new_name));
                    obj.insert(
                        "edit".to_string(),
                        serde_json::to_value(preview).unwrap_or(Value::Null),
                    );
                    obj.insert("warnings".to_string(), Value::Array(warnings));
                }
                structured
            }),
            is_error: Some(false),
            meta: None,
        })
    }
}
