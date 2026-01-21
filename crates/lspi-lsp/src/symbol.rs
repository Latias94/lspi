use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;
use serde_json::Value;

use crate::lsp::{
    LspDocumentSymbol, LspLocation, LspLocationLink, LspRange, LspSymbolInformation, uri_to_path,
};

#[derive(Debug, Clone, Serialize)]
pub struct DefinitionMatch {
    pub symbol: ResolvedSymbol,
    pub definitions: Vec<ResolvedLocation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReferenceMatch {
    pub symbol: ResolvedSymbol,
    pub references: Vec<ResolvedLocation>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkspaceSymbolMatch {
    pub name: String,
    pub kind: u32,
    pub location: ResolvedLocation,
}

#[derive(Debug, Clone, Serialize)]
pub struct RenameCandidate {
    pub name: String,
    pub kind: u32,
    pub line: u32,
    pub character: u32,
    pub selection_range: LspRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedSymbol {
    pub name: String,
    pub kind: u32,
    pub range: LspRange,
    pub selection_range: LspRange,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedLocation {
    pub file_path: String,
    pub uri: String,
    pub range: LspRange,
}

#[derive(Debug, Clone)]
pub(crate) struct FlatSymbol {
    pub(crate) name: String,
    pub(crate) kind: u32,
    pub(crate) range: LspRange,
    pub(crate) selection_range: LspRange,
}

pub(crate) fn parse_symbols(value: Value) -> Result<Vec<FlatSymbol>> {
    if value.is_null() {
        return Ok(Vec::new());
    }

    // textDocument/documentSymbol can return either DocumentSymbol[] or SymbolInformation[].
    if value.as_array().is_none() {
        return Err(anyhow!("documentSymbol response is not an array"));
    }

    let arr = value.as_array().unwrap();
    if arr.is_empty() {
        return Ok(Vec::new());
    }

    // Heuristic: detect DocumentSymbol by presence of "selectionRange".
    let is_document_symbol =
        arr[0].get("selectionRange").is_some() || arr[0].get("selection_range").is_some();

    if is_document_symbol {
        let roots: Vec<LspDocumentSymbol> = serde_json::from_value(Value::Array(arr.clone()))
            .context("failed to parse DocumentSymbol[]")?;
        let mut out = Vec::new();
        for root in roots {
            flatten_document_symbol(&root, &mut out);
        }
        return Ok(out);
    }

    let infos: Vec<LspSymbolInformation> = serde_json::from_value(Value::Array(arr.clone()))
        .context("failed to parse SymbolInformation[]")?;
    Ok(infos
        .into_iter()
        .map(|i| FlatSymbol {
            name: i.name,
            kind: i.kind,
            range: i.location.range.clone(),
            selection_range: i.location.range,
        })
        .collect())
}

pub(crate) fn parse_workspace_symbols(value: Value) -> Result<Vec<WorkspaceSymbolMatch>> {
    if value.is_null() {
        return Ok(Vec::new());
    }

    let Some(arr) = value.as_array() else {
        return Err(anyhow!("workspace/symbol response is not an array"));
    };
    if arr.is_empty() {
        return Ok(Vec::new());
    }

    // Common case: SymbolInformation[]
    if let Ok(infos) =
        serde_json::from_value::<Vec<LspSymbolInformation>>(Value::Array(arr.clone()))
    {
        let mut out = Vec::with_capacity(infos.len());
        for i in infos {
            if let Ok(location) = to_resolved_location(&i.location) {
                out.push(WorkspaceSymbolMatch {
                    name: i.name,
                    kind: i.kind,
                    location,
                });
            }
        }
        return Ok(out);
    }

    // Fallback: WorkspaceSymbol[] (has `location` field containing a Location).
    let mut out = Vec::new();
    for item in arr {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some(name) = obj.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(kind) = obj.get("kind").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(loc_val) = obj.get("location") else {
            continue;
        };

        let loc: LspLocation = serde_json::from_value(loc_val.clone())
            .context("failed to parse workspace/symbol location")?;
        if let Ok(location) = to_resolved_location(&loc) {
            out.push(WorkspaceSymbolMatch {
                name: name.to_string(),
                kind: kind as u32,
                location,
            });
        }
    }
    Ok(out)
}

fn flatten_document_symbol(sym: &LspDocumentSymbol, out: &mut Vec<FlatSymbol>) {
    out.push(FlatSymbol {
        name: sym.name.clone(),
        kind: sym.kind,
        range: sym.range.clone(),
        selection_range: sym.selection_range.clone(),
    });
    for child in &sym.children {
        flatten_document_symbol(child, out);
    }
}

pub(crate) fn parse_locations(value: Value) -> Result<Vec<Value>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    if let Some(arr) = value.as_array() {
        return Ok(arr.clone());
    }
    if value.is_object() {
        return Ok(vec![value]);
    }
    Err(anyhow!("location response is neither array nor object"))
}

pub(crate) fn to_lsp_location(value: &Value) -> Result<LspLocation> {
    if value.get("uri").is_some() {
        let loc: LspLocation =
            serde_json::from_value(value.clone()).context("failed to parse Location")?;
        return Ok(loc);
    }

    // LocationLink
    if value.get("targetUri").is_some() {
        let link: LspLocationLink =
            serde_json::from_value(value.clone()).context("failed to parse LocationLink")?;
        return Ok(LspLocation {
            uri: link.target_uri,
            range: link.target_selection_range,
        });
    }

    Err(anyhow!("unknown location shape"))
}

pub(crate) fn to_resolved_location(loc: &LspLocation) -> Result<ResolvedLocation> {
    let path: PathBuf = uri_to_path(&loc.uri)?;
    Ok(ResolvedLocation {
        file_path: path.to_string_lossy().to_string(),
        uri: loc.uri.clone(),
        range: loc.range.clone(),
    })
}

pub fn parse_symbol_kind(kind: &str) -> Option<u32> {
    // LSP SymbolKind numbers:
    // https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#symbolKind
    match kind.to_ascii_lowercase().as_str() {
        "file" => Some(1),
        "module" => Some(2),
        "namespace" => Some(3),
        "package" => Some(4),
        "class" => Some(5),
        "method" => Some(6),
        "property" => Some(7),
        "field" => Some(8),
        "constructor" => Some(9),
        "enum" => Some(10),
        "interface" => Some(11),
        "function" => Some(12),
        "variable" => Some(13),
        "constant" => Some(14),
        "string" => Some(15),
        "number" => Some(16),
        "boolean" => Some(17),
        "array" => Some(18),
        "object" => Some(19),
        "key" => Some(20),
        "null" => Some(21),
        "enummember" | "enum_member" => Some(22),
        "struct" => Some(23),
        "event" => Some(24),
        "operator" => Some(25),
        "typeparameter" | "type_parameter" => Some(26),
        _ => None,
    }
}
