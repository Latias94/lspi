use serde_json::{Value, json};

pub(crate) const DEFAULT_MAX_TOTAL_CHARS: usize = 120_000;
pub(crate) const MIN_MAX_TOTAL_CHARS: usize = 10_000;
pub(crate) const ABS_MAX_TOTAL_CHARS: usize = 2_000_000;

pub(crate) fn effective_max_total_chars(
    config: &lspi_core::config::LspiConfig,
    requested: Option<usize>,
) -> (usize, Option<Value>) {
    let output = config.mcp.as_ref().and_then(|m| m.output.as_ref());

    let hard = output
        .and_then(|o| o.max_total_chars_hard)
        .unwrap_or(ABS_MAX_TOTAL_CHARS)
        .clamp(MIN_MAX_TOTAL_CHARS, ABS_MAX_TOTAL_CHARS);

    let default_value = output
        .and_then(|o| o.max_total_chars_default)
        .unwrap_or(DEFAULT_MAX_TOTAL_CHARS)
        .clamp(MIN_MAX_TOTAL_CHARS, hard);

    let effective = requested
        .unwrap_or(default_value)
        .clamp(MIN_MAX_TOTAL_CHARS, hard);

    let warning = requested.and_then(|req| {
        if req == effective {
            None
        } else {
            Some(json!({
                "kind": "max_total_chars_clamped",
                "message": "Requested max_total_chars was clamped by policy.",
                "requested": req,
                "effective": effective,
                "hard": hard,
                "min": MIN_MAX_TOTAL_CHARS
            }))
        }
    });

    (effective, warning)
}

pub(crate) fn enforce_global_output_caps(
    max_total_chars: usize,
    include_snippet: bool,
    payload: &mut Value,
) {
    let Some(tool) = payload
        .get("tool")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    else {
        return;
    };

    if json_len(payload) <= max_total_chars {
        return;
    }

    let mut warnings = payload
        .get("warnings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut changed = false;

    // 1) Drop snippets (cheap win).
    if include_snippet && let Some(results) = payload.get_mut("results") {
        strip_snippets(results);
        warnings.push(json!({
            "kind": "global_cap_dropped_snippet",
            "message": "Dropped snippets to satisfy max_total_chars.",
            "max_total_chars": max_total_chars
        }));
        changed = true;
    }

    // 2) Truncate the main arrays until size is below cap.
    if json_len(payload) > max_total_chars {
        match tool.as_str() {
            "get_diagnostics" => {
                while json_len(payload) > max_total_chars {
                    let len = payload
                        .get("diagnostics")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if len <= 1 {
                        break;
                    }
                    {
                        let diags = payload
                            .get_mut("diagnostics")
                            .and_then(|v| v.as_array_mut())
                            .unwrap();
                        diags.truncate(len.div_ceil(2));
                    }
                    changed = true;
                }
                let diag_len = payload
                    .get("diagnostics")
                    .and_then(|v| v.as_array())
                    .map(|diags| diags.len());
                if let (Some(diag_len), Some(count)) = (diag_len, payload.get_mut("count")) {
                    *count = Value::Number(serde_json::Number::from(diag_len));
                }
            }
            "find_definition" | "find_references" => {
                while json_len(payload) > max_total_chars {
                    let total_locations = payload
                        .get("results")
                        .and_then(|v| v.as_array())
                        .map(|results| count_locations(results.as_slice()))
                        .unwrap_or(0);
                    if total_locations <= 1 {
                        break;
                    }
                    let target = total_locations.div_ceil(2);
                    {
                        let results = payload
                            .get_mut("results")
                            .and_then(|v| v.as_array_mut())
                            .unwrap();
                        truncate_locations(results, target);
                    }
                    changed = true;
                }

                let total = payload
                    .get("results")
                    .and_then(|v| v.as_array())
                    .map(|results| count_locations(results.as_slice()))
                    .unwrap_or(0);

                if tool == "find_definition"
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert(
                        "definition_locations".to_string(),
                        Value::Number(serde_json::Number::from(total)),
                    );
                }
                if tool == "find_references"
                    && let Some(obj) = payload.as_object_mut()
                {
                    obj.insert(
                        "reference_locations".to_string(),
                        Value::Number(serde_json::Number::from(total)),
                    );
                }
            }
            _ => {}
        }
    }

    if json_len(payload) > max_total_chars {
        // Worst-case fallback: keep metadata + warnings, drop large payloads.
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("results".to_string(), Value::Array(Vec::new()));
            obj.insert("diagnostics".to_string(), Value::Array(Vec::new()));
        }
        warnings.push(json!({
            "kind": "global_cap_cleared_results",
            "message": "Cleared results to satisfy max_total_chars.",
            "max_total_chars": max_total_chars
        }));
        changed = true;
    }

    if changed && let Some(obj) = payload.as_object_mut() {
        obj.insert("warnings".to_string(), Value::Array(warnings));
        obj.insert("truncated".to_string(), Value::Bool(true));
    }
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
}

fn strip_snippets(value: &mut Value) {
    match value {
        Value::Array(arr) => {
            for v in arr {
                strip_snippets(v);
            }
        }
        Value::Object(map) => {
            map.remove("snippet");
            for (_, v) in map.iter_mut() {
                strip_snippets(v);
            }
        }
        _ => {}
    }
}

fn count_locations(results: &[Value]) -> usize {
    let mut total = 0usize;
    for r in results {
        if let Some(defs) = r.get("definitions").and_then(|v| v.as_array()) {
            total += defs.len();
        }
        if let Some(refs) = r.get("references").and_then(|v| v.as_array()) {
            total += refs.len();
        }
    }
    total
}

fn truncate_locations(results: &mut [Value], mut remaining: usize) {
    for r in results {
        if remaining == 0 {
            if let Some(defs) = r.get_mut("definitions").and_then(|v| v.as_array_mut()) {
                defs.clear();
            }
            if let Some(refs) = r.get_mut("references").and_then(|v| v.as_array_mut()) {
                refs.clear();
            }
            continue;
        }

        if let Some(defs) = r.get_mut("definitions").and_then(|v| v.as_array_mut()) {
            if defs.len() > remaining {
                defs.truncate(remaining);
                remaining = 0;
            } else {
                remaining -= defs.len();
            }
        }
        if let Some(refs) = r.get_mut("references").and_then(|v| v.as_array_mut()) {
            if remaining == 0 {
                refs.clear();
            } else if refs.len() > remaining {
                refs.truncate(remaining);
                remaining = 0;
            } else {
                remaining -= refs.len();
            }
        }
    }
}

#[cfg(test)]
mod output_caps_tests {
    use super::*;

    #[test]
    fn drops_snippets_and_truncates_results() {
        let mut payload = json!({
            "ok": true,
            "tool": "find_definition",
            "results": [{
                "symbol": {"name":"x"},
                "definitions": (0..100).map(|_| json!({
                    "file_path": "a.rs",
                    "uri": "file:///a.rs",
                    "range": {"start":{"line":0,"character":0},"end":{"line":0,"character":1}},
                    "snippet": {"start_line":0,"text":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","truncated":false}
                })).collect::<Vec<_>>()
            }],
            "warnings": [],
            "definition_locations": 100,
            "truncated": false
        });

        enforce_global_output_caps(2000, true, &mut payload);
        assert_eq!(payload.get("truncated"), Some(&Value::Bool(true)));
        let len = serde_json::to_string(&payload).unwrap().len();
        assert!(len <= 2000);
        // Ensure snippet keys are removed
        let defs = payload["results"][0]["definitions"].as_array().unwrap();
        assert!(defs.iter().all(|d| d.get("snippet").is_none()));
    }
}
