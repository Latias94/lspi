use rmcp::model::Tool;
use tracing::warn;

pub(crate) fn all_tools() -> Vec<Tool> {
    vec![
        crate::tool_find_definition(),
        crate::tool_find_definition_at(),
        crate::tool_find_references(),
        crate::tool_find_references_at(),
        crate::tool_hover_at(),
        crate::tool_find_implementation_at(),
        crate::tool_find_type_definition_at(),
        crate::tool_find_incoming_calls(),
        crate::tool_find_outgoing_calls(),
        crate::tool_find_incoming_calls_at(),
        crate::tool_find_outgoing_calls_at(),
        crate::tool_get_document_symbols(),
        crate::tool_search_workspace_symbols(),
        crate::tool_rename_symbol(),
        crate::tool_rename_symbol_strict(),
        crate::tool_get_diagnostics(),
        crate::tool_restart_server(),
        crate::tool_stop_server(),
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
