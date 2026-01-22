use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParam, CallToolResult, Content};
use serde_json::{Value, json};

use crate::{
    GetCurrentConfigArgs, GetServerStatusArgs, ListServersArgs, LspiMcpServer,
    effective_max_total_chars, enforce_global_output_caps, parse_arguments, structured_ok,
};

fn redact_env(env: &std::collections::HashMap<String, String>) -> Value {
    let mut keys: Vec<String> = env.keys().cloned().collect();
    keys.sort();
    json!({
        "redacted": true,
        "keys": keys
    })
}

impl LspiMcpServer {
    pub(crate) async fn list_servers(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: ListServersArgs = parse_arguments(request.arguments)?;
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let mut servers = Vec::new();
        for s in &self.state.servers {
            servers.push(json!({
                "id": s.id,
                "kind": s.kind,
                "extensions": s.extensions,
                "root_dir": s.root_dir.to_string_lossy(),
                "cwd": s.cwd.to_string_lossy(),
                "workspace_folders": s.workspace_folders.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                "language_id": s.language_id,
                "adapter": s.adapter,
                "restart_interval_minutes": s.restart_interval_minutes,
                "idle_shutdown_ms": s.idle_shutdown_ms,
                "initialize_timeout_ms": s.initialize_timeout_ms,
                "request_timeout_ms": s.request_timeout_ms,
                "request_timeout_overrides_ms": s.request_timeout_overrides_ms,
                "env": if args.include_env.unwrap_or(false) {
                    redact_env(&s.env)
                } else {
                    Value::Null
                },
                "has_initialize_options": s.initialize_options.is_some(),
                "has_client_capabilities": s.client_capabilities.is_some(),
                "workspace_configuration_keys": s.workspace_configuration.keys().cloned().collect::<Vec<_>>(),
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = structured_ok(
            "list_servers",
            None,
            json!({
                "max_total_chars": max_total_chars,
                "include_env": args.include_env.unwrap_or(false),
            }),
        );
        if let Some(obj) = structured_content.as_object_mut() {
            obj.insert(
                "server_count".to_string(),
                Value::Number(serde_json::Number::from(servers.len() as u64)),
            );
            obj.insert("servers".to_string(), Value::Array(servers));
            obj.insert("warnings".to_string(), Value::Array(warnings));
        }
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Found {} configured language servers.",
                structured_content["server_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    pub(crate) async fn get_server_status(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetServerStatusArgs = parse_arguments(request.arguments)?;
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let now = std::time::Instant::now();

        let mut statuses = Vec::new();
        for s in &self.state.servers {
            if let Some(wanted) = args.server_id.as_deref()
                && wanted.trim() != s.id.as_str()
            {
                continue;
            }

            let mut running = false;
            let mut started_ms_ago: Option<u64> = None;
            let mut last_used_ms_ago: Option<u64> = None;
            let mut server_status: Option<Value> = None;

            let normalized_kind = s.kind.trim().to_ascii_lowercase().replace('-', "_");
            if normalized_kind == "rust_analyzer" || normalized_kind == "rust" {
                let guard = self.state.rust_analyzer.lock().await;
                if let Some(entry) = guard.get(&s.id) {
                    running = true;
                    started_ms_ago = Some(now.duration_since(entry.started_at).as_millis() as u64);
                    last_used_ms_ago = Some(now.duration_since(entry.last_used).as_millis() as u64);
                    server_status = entry
                        .client
                        .status_snapshot()
                        .map(|st| json!({"health": st.health, "quiescent": st.quiescent, "message": st.message}));
                }
            } else if normalized_kind == "omnisharp" || normalized_kind == "csharp" {
                let guard = self.state.omnisharp.lock().await;
                if let Some(entry) = guard.get(&s.id) {
                    running = true;
                    started_ms_ago = Some(now.duration_since(entry.started_at).as_millis() as u64);
                    last_used_ms_ago = Some(now.duration_since(entry.last_used).as_millis() as u64);
                }
            } else {
                let guard = self.state.generic.lock().await;
                if let Some(entry) = guard.get(&s.id) {
                    running = true;
                    started_ms_ago = Some(now.duration_since(entry.started_at).as_millis() as u64);
                    last_used_ms_ago = Some(now.duration_since(entry.last_used).as_millis() as u64);
                }
            }

            statuses.push(json!({
                "server_id": s.id,
                "kind": s.kind,
                "extensions": s.extensions,
                "running": running,
                "started_ms_ago": started_ms_ago,
                "last_used_ms_ago": last_used_ms_ago,
                "server_status": server_status
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = structured_ok(
            "get_server_status",
            None,
            json!({
                "server_id": args.server_id,
                "max_total_chars": max_total_chars,
            }),
        );
        if let Some(obj) = structured_content.as_object_mut() {
            obj.insert(
                "status_count".to_string(),
                Value::Number(serde_json::Number::from(statuses.len() as u64)),
            );
            obj.insert("statuses".to_string(), Value::Array(statuses));
            obj.insert("warnings".to_string(), Value::Array(warnings));
        }
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Returned status for {} servers.",
                structured_content["status_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }

    pub(crate) async fn get_current_config(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetCurrentConfigArgs = parse_arguments(request.arguments)?;
        let (max_total_chars, max_total_chars_warning) =
            effective_max_total_chars(&self.state.config, args.max_total_chars);

        let include_env = args.include_env.unwrap_or(false);

        let mcp = self
            .state
            .config
            .mcp
            .as_ref()
            .map(|m| {
                json!({
                    "read_only": m.read_only,
                    "output": m.output,
                    "tools": m.tools
                })
            })
            .unwrap_or(Value::Null);

        let mut servers = Vec::new();
        for s in &self.state.servers {
            servers.push(json!({
                "id": s.id,
                "kind": s.kind,
                "extensions": s.extensions,
                "root_dir": s.root_dir.to_string_lossy(),
                "cwd": s.cwd.to_string_lossy(),
                "workspace_folders": s.workspace_folders.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
                "language_id": s.language_id,
                "adapter": s.adapter,
                "initialize_timeout_ms": s.initialize_timeout_ms,
                "request_timeout_ms": s.request_timeout_ms,
                "request_timeout_overrides_ms": s.request_timeout_overrides_ms,
                "env": if include_env { redact_env(&s.env) } else { Value::Null },
            }));
        }

        let mut warnings = Vec::<Value>::new();
        if let Some(w) = max_total_chars_warning {
            warnings.push(w);
        }

        let mut structured_content = structured_ok(
            "get_current_config",
            None,
            json!({
                "max_total_chars": max_total_chars,
                "include_env": include_env,
            }),
        );
        if let Some(obj) = structured_content.as_object_mut() {
            obj.insert(
                "workspace_root".to_string(),
                Value::String(self.state.workspace_root.to_string_lossy().to_string()),
            );
            obj.insert(
                "allowed_roots".to_string(),
                Value::Array(
                    self.state
                        .allowed_roots
                        .iter()
                        .map(|p| Value::String(p.to_string_lossy().to_string()))
                        .collect(),
                ),
            );
            obj.insert("read_only".to_string(), Value::Bool(self.state.read_only));
            obj.insert("mcp".to_string(), mcp);
            obj.insert(
                "server_count".to_string(),
                Value::Number(serde_json::Number::from(servers.len() as u64)),
            );
            obj.insert("servers".to_string(), Value::Array(servers));
            obj.insert("warnings".to_string(), Value::Array(warnings));
        }
        enforce_global_output_caps(max_total_chars, false, &mut structured_content);

        Ok(CallToolResult {
            content: vec![Content::text(format!(
                "Loaded config for workspace root {} ({} servers).",
                self.state.workspace_root.to_string_lossy(),
                structured_content["server_count"].as_u64().unwrap_or(0)
            ))],
            structured_content: Some(structured_content),
            is_error: Some(false),
            meta: None,
        })
    }
}
