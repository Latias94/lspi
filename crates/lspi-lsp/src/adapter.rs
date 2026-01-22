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
        return Some(json!([0, {}]));
    };
    let id = arr.first().cloned().unwrap_or(Value::Null);
    let request_type = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
    if request_type == "_vue:projectInfo" {
        return Some(json!([
            id,
            { "configFiles": [], "sourceFiles": [] }
        ]));
    }
    Some(json!([id, {}]))
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
