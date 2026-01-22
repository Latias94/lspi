use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{JsonObject, Tool};
use serde_json::json;

pub(crate) fn tool_find_definition() -> Tool {
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

pub(crate) fn tool_find_definition_at() -> Tool {
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

pub(crate) fn tool_find_references() -> Tool {
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

pub(crate) fn tool_find_references_at() -> Tool {
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

pub(crate) fn tool_hover_at() -> Tool {
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

pub(crate) fn tool_find_implementation_at() -> Tool {
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

pub(crate) fn tool_find_type_definition_at() -> Tool {
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

pub(crate) fn tool_find_incoming_calls() -> Tool {
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

pub(crate) fn tool_find_outgoing_calls() -> Tool {
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

pub(crate) fn tool_find_incoming_calls_at() -> Tool {
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

pub(crate) fn tool_find_outgoing_calls_at() -> Tool {
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

pub(crate) fn tool_get_document_symbols() -> Tool {
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

pub(crate) fn tool_search_workspace_symbols() -> Tool {
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

pub(crate) fn tool_rename_symbol() -> Tool {
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

pub(crate) fn tool_rename_symbol_strict() -> Tool {
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

pub(crate) fn tool_get_diagnostics() -> Tool {
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

pub(crate) fn tool_restart_server() -> Tool {
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

pub(crate) fn tool_stop_server() -> Tool {
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

pub(crate) fn tool_get_current_config() -> Tool {
    Tool::new(
        Cow::Borrowed("get_current_config"),
        Cow::Borrowed("Show the currently loaded lspi configuration (redacts env values)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_env": { "type": "boolean", "default": false }
            },
            "additionalProperties": false
        }))),
    )
}

pub(crate) fn tool_list_servers() -> Tool {
    Tool::new(
        Cow::Borrowed("list_servers"),
        Cow::Borrowed("List configured language servers (from lspi config)."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 },
                "include_env": { "type": "boolean", "default": false }
            },
            "additionalProperties": false
        }))),
    )
}

pub(crate) fn tool_get_server_status() -> Tool {
    Tool::new(
        Cow::Borrowed("get_server_status"),
        Cow::Borrowed("Show runtime status for configured language servers."),
        Arc::new(schema(json!({
            "type": "object",
            "properties": {
                "server_id": { "type": "string" },
                "max_total_chars": { "type": "integer", "minimum": 10000, "default": 120000 }
            },
            "additionalProperties": false
        }))),
    )
}

fn schema(value: serde_json::Value) -> JsonObject {
    #[expect(clippy::expect_used)]
    serde_json::from_value(value).expect("tool schema should deserialize")
}
