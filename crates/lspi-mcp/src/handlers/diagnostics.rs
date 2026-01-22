use std::path::PathBuf;

use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolRequestParam, CallToolResult, Content};
use serde_json::{Value, json};

use crate::{
    GetDiagnosticsArgs, LspiMcpServer, canonicalize_within, effective_max_total_chars,
    enforce_global_output_caps, parse_arguments,
};

impl LspiMcpServer {
    pub(crate) async fn get_diagnostics(
        &self,
        request: CallToolRequestParam,
    ) -> Result<CallToolResult, McpError> {
        let args: GetDiagnosticsArgs = parse_arguments(request.arguments)?;
        let max_results = args.max_results.unwrap_or(200).clamp(1, 5000);
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
}
