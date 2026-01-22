use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParam, CallToolResult, Content};
use serde_json::{Value, json};

use crate::{
    LspiMcpServer, RestartServerArgs, StopServerArgs, is_generic_kind, is_omnisharp_kind,
    is_pyright_kind, is_rust_analyzer_kind, parse_arguments, shutdown_generic_managed,
    shutdown_omnisharp_managed, shutdown_rust_analyzer_managed,
};

impl LspiMcpServer {
    pub(crate) async fn restart_server(
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

    pub(crate) async fn stop_server(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
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
