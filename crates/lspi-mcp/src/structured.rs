use serde_json::{Value, json};

pub(crate) const STRUCTURED_SCHEMA_VERSION: u32 = 1;

pub(crate) fn structured_ok(tool: &str, server_id: Option<&str>, input: Value) -> Value {
    json!({
        "schema_version": STRUCTURED_SCHEMA_VERSION,
        "ok": true,
        "tool": tool,
        "server_id": server_id,
        "input": input,
        "warnings": [],
        "truncated": false
    })
}

pub(crate) fn structured_error(
    tool: &str,
    server_id: Option<&str>,
    input: Option<Value>,
    kind: &str,
    message: &str,
) -> Value {
    json!({
        "schema_version": STRUCTURED_SCHEMA_VERSION,
        "ok": false,
        "tool": tool,
        "server_id": server_id,
        "input": input,
        "error": {
            "kind": kind,
            "message": message
        },
        "warnings": [],
        "truncated": false
    })
}

pub(crate) fn ensure_common_fields(payload: &mut Value) {
    let Some(obj) = payload.as_object_mut() else {
        return;
    };

    obj.entry("schema_version".to_string())
        .or_insert_with(|| Value::Number(serde_json::Number::from(STRUCTURED_SCHEMA_VERSION)));

    obj.entry("warnings".to_string())
        .or_insert_with(|| Value::Array(Vec::new()));

    obj.entry("truncated".to_string())
        .or_insert_with(|| Value::Bool(false));
}
