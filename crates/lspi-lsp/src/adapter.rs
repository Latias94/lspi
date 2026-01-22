use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFolder {
    pub uri: String,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub enum LspAdapter {
    #[default]
    Default,
    TsServerProtocol,
}

impl LspAdapter {
    pub fn name(&self) -> &'static str {
        match self {
            LspAdapter::Default => "default",
            LspAdapter::TsServerProtocol => "tsserver",
        }
    }

    pub fn server_request_result(
        &self,
        method: &str,
        params: Option<&Value>,
        _workspace_folders: &[WorkspaceFolder],
        _workspace_configuration: &HashMap<String, Value>,
    ) -> Option<Value> {
        match self {
            LspAdapter::Default => None,
            LspAdapter::TsServerProtocol => tsserver_request_result(method, params),
        }
    }

    pub fn server_notification_response(
        &self,
        method: &str,
        params: Option<&Value>,
    ) -> Option<Value> {
        match self {
            LspAdapter::Default => None,
            LspAdapter::TsServerProtocol => tsserver_notification_response(method, params),
        }
    }
}

pub fn adapter_from_name(name: &str) -> Option<LspAdapter> {
    let normalized = name.trim().to_ascii_lowercase().replace(['-', '_'], "");
    match normalized.as_str() {
        "" | "default" | "none" => Some(LspAdapter::Default),
        "tsserver" | "typescript" | "typescriptlanguageserver" | "vue" | "vuelanguageserver" => {
            Some(LspAdapter::TsServerProtocol)
        }
        _ => None,
    }
}

pub fn adapter_from_command(command: &str) -> Option<LspAdapter> {
    let c = command.trim().to_ascii_lowercase();
    if c.contains("typescript-language-server")
        || c.contains("vue-language-server")
        || c.contains("vtsls")
    {
        return Some(LspAdapter::TsServerProtocol);
    }
    None
}

fn tsserver_request_result(method: &str, params: Option<&Value>) -> Option<Value> {
    if method != "tsserver/request" {
        return None;
    }

    let Some(arr) = params.and_then(|p| p.as_array()) else {
        return Some(json!([0, null]));
    };
    let id = arr.first().cloned().unwrap_or(Value::Null);
    let request_type = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");

    // Vue language tooling uses a custom tsserver bridge where the LSP client is expected to forward
    // requests to an editor/tsserver integration (e.g. VSCode's `typescript.tsserverRequest`) and then
    // respond via `tsserver/response`. In lspi we don't embed tsserver, so we return `null` (similar to
    // how VSCode responds with `undefined` on failure) to avoid hangs and let the server fall back.
    //
    // Returning `{}` is unsafe for some request types (notably `_vue:projectInfo`) because it is truthy
    // and may be treated as a valid response body.
    if request_type.starts_with("_vue:") {
        return Some(json!([id, null]));
    }

    Some(json!([id, null]))
}

fn tsserver_notification_response(method: &str, params: Option<&Value>) -> Option<Value> {
    if method != "tsserver/request" {
        return None;
    }

    let arr = params.and_then(|p| p.as_array())?;
    let id = arr.first().cloned()?;

    Some(json!({
        "jsonrpc": "2.0",
        "method": "tsserver/response",
        "params": [id, null]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_from_name_accepts_common_variants() {
        assert!(matches!(
            adapter_from_name("default"),
            Some(LspAdapter::Default)
        ));
        assert!(matches!(
            adapter_from_name("tsserver"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(matches!(
            adapter_from_name("TypeScript-Language-Server"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(matches!(
            adapter_from_name("vue_language_server"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(adapter_from_name("unknown").is_none());
    }

    #[test]
    fn adapter_from_command_detects_typescript_and_vue_servers() {
        assert!(matches!(
            adapter_from_command("typescript-language-server"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(matches!(
            adapter_from_command("C:\\\\bin\\\\vue-language-server.exe"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(matches!(
            adapter_from_command("vtsls"),
            Some(LspAdapter::TsServerProtocol)
        ));
        assert!(adapter_from_command("rust-analyzer").is_none());
    }

    #[test]
    fn tsserver_request_result_handles_vue_project_info() {
        let params = json!([42, "_vue:projectInfo", {}]);
        let out = LspAdapter::TsServerProtocol
            .server_request_result("tsserver/request", Some(&params), &[], &HashMap::new())
            .unwrap();
        assert_eq!(out, json!([42, null]));
    }

    #[test]
    fn tsserver_notification_response_wraps_id() {
        let params = json!([42, "any", {}]);
        let out = LspAdapter::TsServerProtocol
            .server_notification_response("tsserver/request", Some(&params))
            .unwrap();
        assert_eq!(out["method"], json!("tsserver/response"));
        assert_eq!(out["params"], json!([42, null]));
    }
}
