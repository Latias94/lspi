use rmcp::model::Tool;
use tracing::warn;

pub(crate) fn all_tools() -> Vec<Tool> {
    use crate::tool_schemas as schemas;
    vec![
        schemas::tool_get_current_config(),
        schemas::tool_list_servers(),
        schemas::tool_get_server_status(),
        schemas::tool_find_definition(),
        schemas::tool_find_definition_at(),
        schemas::tool_find_references(),
        schemas::tool_find_references_at(),
        schemas::tool_hover_at(),
        schemas::tool_find_implementation_at(),
        schemas::tool_find_type_definition_at(),
        schemas::tool_find_incoming_calls(),
        schemas::tool_find_outgoing_calls(),
        schemas::tool_find_incoming_calls_at(),
        schemas::tool_find_outgoing_calls_at(),
        schemas::tool_get_document_symbols(),
        schemas::tool_search_workspace_symbols(),
        schemas::tool_rename_symbol(),
        schemas::tool_rename_symbol_strict(),
        schemas::tool_get_diagnostics(),
        schemas::tool_restart_server(),
        schemas::tool_stop_server(),
    ]
}

pub(crate) fn filter_tools_by_config(
    tools: Vec<Tool>,
    mcp: Option<&lspi_core::config::McpConfig>,
) -> Vec<Tool> {
    let Some(tools_cfg) = mcp.and_then(|m| m.tools.as_ref()) else {
        return tools;
    };

    let normalize = |s: &str| s.trim().to_ascii_lowercase();
    let known: std::collections::HashSet<String> = tools
        .iter()
        .map(|t| normalize(t.name.as_ref()))
        .filter(|n| !n.is_empty())
        .collect();
    let mut allow_set = std::collections::HashSet::<String>::new();
    if let Some(list) = tools_cfg.allow.as_ref() {
        for item in list {
            let n = normalize(item);
            if !n.is_empty() {
                allow_set.insert(n);
            }
        }
    }

    let mut exclude_set = std::collections::HashSet::<String>::new();
    if let Some(list) = tools_cfg.exclude.as_ref() {
        for item in list {
            let n = normalize(item);
            if !n.is_empty() {
                exclude_set.insert(n);
            }
        }
    }

    let has_allow = !allow_set.is_empty();

    let filtered: Vec<Tool> = tools
        .into_iter()
        .filter(|tool| {
            let name = normalize(tool.name.as_ref());
            if has_allow {
                return allow_set.contains(&name);
            }
            !exclude_set.contains(&name)
        })
        .collect();

    if has_allow {
        for wanted in allow_set {
            if !known.contains(&wanted) {
                warn!("mcp.tools.allow includes unknown tool: {wanted}");
            }
        }
    } else {
        for denied in exclude_set {
            if !known.contains(&denied) {
                warn!("mcp.tools.exclude includes unknown tool: {denied}");
            }
        }
    }

    filtered
}

pub(crate) fn filter_tools_read_only(tools: Vec<Tool>) -> Vec<Tool> {
    let deny: std::collections::HashSet<&'static str> = [
        "rename_symbol",
        "rename_symbol_strict",
        "restart_server",
        "stop_server",
    ]
    .into_iter()
    .collect();

    tools
        .into_iter()
        .filter(|t| !deny.contains(t.name.as_ref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_filter_removes_write_tools() {
        let tools = all_tools();
        let names: std::collections::HashSet<String> = filter_tools_read_only(tools)
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();

        assert!(!names.contains("rename_symbol"));
        assert!(!names.contains("rename_symbol_strict"));
        assert!(!names.contains("restart_server"));
        assert!(!names.contains("stop_server"));
        assert!(names.contains("find_definition_at"));
        assert!(names.contains("get_diagnostics"));
    }
}
