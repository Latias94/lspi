use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct LspiConfig {
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
    #[serde(default)]
    pub servers: Option<Vec<LspServerConfig>>,
    #[serde(default)]
    pub mcp: Option<McpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LspServerConfig {
    /// Optional stable identifier for logs and future UX.
    #[serde(default)]
    pub id: Option<String>,
    /// Server kind (supported: `rust_analyzer`, `omnisharp`, `generic`, `pyright`, `basedpyright`).
    #[serde(default)]
    pub kind: Option<String>,
    /// Command to start the server.
    #[serde(default)]
    pub command: Option<String>,
    /// Arguments passed to the server (do not include `--stdio` if the server uses stdio by default).
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// File extensions (without a leading dot) routed to this server, e.g. `["rs"]`.
    #[serde(default)]
    pub extensions: Option<Vec<String>>,
    /// Optional languageId used for textDocument/didOpen when `kind = "generic"`.
    /// If omitted, lspi tries a best-effort mapping from the first extension.
    #[serde(default)]
    #[serde(alias = "languageId")]
    pub language_id: Option<String>,
    /// Optional root directory for this server (absolute or relative to `workspace_root`).
    #[serde(default)]
    #[serde(alias = "rootDir")]
    pub root_dir: Option<PathBuf>,
    #[serde(default)]
    pub initialize_timeout_ms: Option<u64>,
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    /// Optional per-method request timeouts (milliseconds).
    /// Keys are full LSP method names, e.g. `textDocument/references`.
    #[serde(default)]
    #[serde(alias = "requestTimeoutOverridesMs")]
    pub request_timeout_overrides_ms: Option<HashMap<String, u64>>,
    #[serde(default)]
    pub warmup_timeout_ms: Option<u64>,
    /// Optional interval (minutes) to auto-restart long-running servers (helps stability for some LSPs).
    #[serde(default)]
    pub restart_interval_minutes: Option<u64>,
    /// Optional idle shutdown (milliseconds). If set, lspi may stop the server after being idle.
    #[serde(default)]
    pub idle_shutdown_ms: Option<u64>,
    /// Optional `initializationOptions` passed to the `initialize` request.
    /// Useful for servers that require non-standard options (most often when using `kind = "generic"`).
    #[serde(default)]
    #[serde(alias = "initializeOptions")]
    pub initialize_options: Option<JsonValue>,
    /// Optional full `capabilities` object for the `initialize` request.
    /// If omitted, lspi uses a conservative default capability set.
    #[serde(default)]
    #[serde(alias = "clientCapabilities")]
    pub client_capabilities: Option<JsonValue>,
    /// Optional responses for server-initiated `workspace/configuration` requests.
    /// Keys are the `section` values requested by the server (e.g. `formattingOptions` for TypeScript LS).
    #[serde(default)]
    #[serde(alias = "workspaceConfiguration")]
    pub workspace_configuration: Option<HashMap<String, JsonValue>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct McpConfig {
    #[serde(default)]
    pub output: Option<McpOutputConfig>,
    #[serde(default)]
    pub tools: Option<McpToolsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct McpToolsConfig {
    /// If set and non-empty, only these tools are exposed through MCP.
    #[serde(default)]
    pub allow: Option<Vec<String>>,
    /// Tools to exclude from MCP exposure (ignored when `allow` is set and non-empty).
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct McpOutputConfig {
    #[serde(default)]
    pub max_total_chars_default: Option<usize>,
    #[serde(default)]
    pub max_total_chars_hard: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: LspiConfig,
    pub workspace_root: PathBuf,
    pub source: ConfigSource,
}

#[derive(Debug, Clone)]
pub enum ConfigSource {
    None,
    Path(PathBuf),
    Env(PathBuf),
    Workspace(PathBuf),
}

#[derive(Debug, Clone)]
pub struct ResolvedServerConfig {
    pub id: String,
    pub kind: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub extensions: Vec<String>,
    pub language_id: Option<String>,
    pub root_dir: PathBuf,
    pub initialize_timeout_ms: Option<u64>,
    pub request_timeout_ms: Option<u64>,
    pub request_timeout_overrides_ms: HashMap<String, u64>,
    pub warmup_timeout_ms: Option<u64>,
    pub restart_interval_minutes: Option<u64>,
    pub idle_shutdown_ms: Option<u64>,
    pub initialize_options: Option<JsonValue>,
    pub client_capabilities: Option<JsonValue>,
    pub workspace_configuration: HashMap<String, JsonValue>,
}

pub fn load_config(
    cli_config_path: Option<&Path>,
    cli_workspace_root: Option<&Path>,
) -> Result<LoadedConfig> {
    let from_cli = cli_config_path.map(PathBuf::from);
    if let Some(path) = from_cli.as_deref() {
        let config = read_config_file(path)?;
        let workspace_root =
            resolve_workspace_root(cli_workspace_root, config.workspace_root.as_deref())?;
        return Ok(LoadedConfig {
            config,
            workspace_root,
            source: ConfigSource::Path(path.to_path_buf()),
        });
    }

    if let Ok(path) = std::env::var("LSPI_CONFIG_PATH")
        && !path.trim().is_empty()
    {
        let path = PathBuf::from(path);
        let config = read_config_file(&path)?;
        let workspace_root =
            resolve_workspace_root(cli_workspace_root, config.workspace_root.as_deref())?;
        return Ok(LoadedConfig {
            config,
            workspace_root,
            source: ConfigSource::Env(path),
        });
    }

    let fallback_root = cli_workspace_root
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let workspace_root = fallback_root
        .canonicalize()
        .unwrap_or(fallback_root.clone());

    for candidate in workspace_config_candidates(&workspace_root) {
        if candidate.exists() {
            let config = read_config_file(&candidate)?;
            let effective_root =
                resolve_workspace_root(Some(&workspace_root), config.workspace_root.as_deref())?;
            return Ok(LoadedConfig {
                config,
                workspace_root: effective_root,
                source: ConfigSource::Workspace(candidate),
            });
        }
    }

    Ok(LoadedConfig {
        config: LspiConfig::default(),
        workspace_root,
        source: ConfigSource::None,
    })
}

fn resolve_workspace_root(cli: Option<&Path>, from_config: Option<&Path>) -> Result<PathBuf> {
    if let Some(cli) = cli {
        return cli
            .canonicalize()
            .with_context(|| format!("failed to canonicalize workspace_root: {cli:?}"));
    }
    if let Some(cfg) = from_config {
        return cfg
            .canonicalize()
            .with_context(|| format!("failed to canonicalize workspace_root: {cfg:?}"));
    }
    Ok(std::env::current_dir()
        .context("failed to get current_dir")?
        .canonicalize()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))))
}

fn workspace_config_candidates(workspace_root: &Path) -> Vec<PathBuf> {
    vec![
        workspace_root.join(".lspi").join("config.toml"),
        workspace_root.join(".lspi").join("config.json"),
        workspace_root.join("lspi.toml"),
        workspace_root.join("lspi.json"),
    ]
}

fn read_config_file(path: &Path) -> Result<LspiConfig> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read config file: {path:?}"))?;
    let ext = path.extension().and_then(OsStr::to_str).unwrap_or("");

    if ext.eq_ignore_ascii_case("toml") {
        let s = String::from_utf8(bytes).context("config file is not valid UTF-8")?;
        let cfg: LspiConfig = toml::from_str(&s).context("failed to parse TOML config")?;
        return Ok(cfg);
    }
    if ext.eq_ignore_ascii_case("json") {
        let cfg: LspiConfig =
            serde_json::from_slice(&bytes).context("failed to parse JSON config")?;
        return Ok(cfg);
    }

    Err(anyhow!(
        "unsupported config extension (expected .toml or .json): {path:?}"
    ))
}

pub fn resolved_servers(config: &LspiConfig, workspace_root: &Path) -> Vec<ResolvedServerConfig> {
    let workspace_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());

    if let Some(servers) = config.servers.as_ref().filter(|s| !s.is_empty()) {
        return servers
            .iter()
            .enumerate()
            .map(|(idx, s)| resolve_server_config(s, idx, &workspace_root))
            .collect();
    }

    vec![default_rust_analyzer_server(&workspace_root)]
}

pub fn route_server_by_path<'a>(
    file_path: &Path,
    servers: &'a [ResolvedServerConfig],
) -> Option<&'a ResolvedServerConfig> {
    let ext = file_path
        .extension()
        .and_then(OsStr::to_str)
        .map(|s| s.to_ascii_lowercase())?;

    let mut matches: Vec<&ResolvedServerConfig> = servers
        .iter()
        .filter(|s| s.extensions.iter().any(|e| e.eq_ignore_ascii_case(&ext)))
        .collect();

    if matches.is_empty() {
        return None;
    }

    let mut contained: Vec<&ResolvedServerConfig> = matches
        .iter()
        .copied()
        .filter(|s| file_path.starts_with(&s.root_dir))
        .collect();

    if contained.is_empty() {
        return Some(matches.remove(0));
    }

    contained.sort_by_key(|s| std::cmp::Reverse(s.root_dir.components().count()));
    Some(contained[0])
}

fn resolve_server_config(
    server: &LspServerConfig,
    index: usize,
    workspace_root: &Path,
) -> ResolvedServerConfig {
    let kind = server
        .kind
        .as_deref()
        .unwrap_or("rust_analyzer")
        .trim()
        .to_string();

    let id = server
        .id
        .as_deref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_server_id(&kind, index));

    let extensions = server
        .extensions
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter_map(normalize_extension)
        .collect::<Vec<_>>();

    let root_dir = resolve_root_dir(workspace_root, server.root_dir.as_deref());

    ResolvedServerConfig {
        id,
        kind,
        command: server
            .command
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        args: server.args.clone().unwrap_or_default(),
        extensions,
        language_id: server
            .language_id
            .clone()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        root_dir,
        initialize_timeout_ms: server.initialize_timeout_ms,
        request_timeout_ms: server.request_timeout_ms,
        request_timeout_overrides_ms: server
            .request_timeout_overrides_ms
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                let key = k.trim().to_string();
                if key.is_empty() || v == 0 {
                    None
                } else {
                    Some((key, v))
                }
            })
            .collect(),
        warmup_timeout_ms: server.warmup_timeout_ms,
        restart_interval_minutes: server.restart_interval_minutes,
        idle_shutdown_ms: server.idle_shutdown_ms,
        initialize_options: server.initialize_options.clone(),
        client_capabilities: server.client_capabilities.clone(),
        workspace_configuration: server
            .workspace_configuration
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| {
                let key = k.trim().to_string();
                if key.is_empty() { None } else { Some((key, v)) }
            })
            .collect(),
    }
}

fn default_rust_analyzer_server(workspace_root: &Path) -> ResolvedServerConfig {
    ResolvedServerConfig {
        id: "rust-analyzer".to_string(),
        kind: "rust_analyzer".to_string(),
        command: None,
        args: Vec::new(),
        extensions: vec!["rs".to_string()],
        language_id: Some("rust".to_string()),
        root_dir: workspace_root.to_path_buf(),
        initialize_timeout_ms: None,
        request_timeout_ms: None,
        request_timeout_overrides_ms: HashMap::new(),
        warmup_timeout_ms: None,
        restart_interval_minutes: None,
        idle_shutdown_ms: None,
        initialize_options: None,
        client_capabilities: None,
        workspace_configuration: HashMap::new(),
    }
}

fn default_server_id(kind: &str, index: usize) -> String {
    if index == 0 {
        kind.replace('_', "-")
    } else {
        format!("{}-{}", kind.replace('_', "-"), index + 1)
    }
}

fn normalize_extension(ext: String) -> Option<String> {
    let ext = ext.trim();
    if ext.is_empty() {
        return None;
    }
    let ext = ext.strip_prefix('.').unwrap_or(ext);
    let ext = ext.trim();
    if ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

fn resolve_root_dir(workspace_root: &Path, root_dir: Option<&Path>) -> PathBuf {
    let resolved = match root_dir {
        None => workspace_root.to_path_buf(),
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => workspace_root.join(p),
    };
    resolved.canonicalize().unwrap_or(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("lspi-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn resolved_servers_defaults_to_rust_analyzer() {
        let root = temp_root("resolved-defaults");
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.clone());
        let config = LspiConfig::default();
        let servers = resolved_servers(&config, &root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "rust-analyzer");
        assert_eq!(servers[0].kind, "rust_analyzer");
        assert_eq!(servers[0].extensions, vec!["rs".to_string()]);
        assert_eq!(servers[0].language_id.as_deref(), Some("rust"));
        assert_eq!(servers[0].root_dir, root_canon);
    }

    #[test]
    fn resolved_servers_parses_and_normalizes_extensions() {
        let root = temp_root("resolved-parse");
        std::fs::create_dir_all(root.join("crates")).unwrap();

        let toml = r#"
[[servers]]
id = "ra"
kind = "rust_analyzer"
extensions = [".RS", "rs", ""]
root_dir = "crates"
"#;
        let config: LspiConfig = toml::from_str(toml).unwrap();
        let servers = resolved_servers(&config, &root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "ra");
        assert_eq!(servers[0].kind, "rust_analyzer");
        assert!(servers[0].extensions.iter().any(|e| e == "rs"));
        assert!(servers[0].root_dir.ends_with("crates"));
    }

    #[test]
    fn json_accepts_root_dir_alias_root_dir() {
        let root = temp_root("resolved-json-alias");
        std::fs::create_dir_all(root.join("crates")).unwrap();

        let json = r#"
{
  "servers": [
    {
      "id": "ra",
      "kind": "rust_analyzer",
      "extensions": ["rs"],
      "rootDir": "crates"
    }
  ]
}
"#;
        let config: LspiConfig = serde_json::from_str(json).unwrap();
        let servers = resolved_servers(&config, &root);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, "ra");
        assert!(servers[0].root_dir.ends_with("crates"));
    }

    #[test]
    fn toml_parses_mcp_tools_allow_and_exclude() {
        let toml = r#"
[mcp.tools]
allow = ["find_definition_at", "find_references_at"]
exclude = ["rename_symbol"]
"#;
        let config: LspiConfig = toml::from_str(toml).unwrap();
        let tools = config.mcp.unwrap().tools.unwrap();
        assert_eq!(
            tools.allow.unwrap(),
            vec![
                "find_definition_at".to_string(),
                "find_references_at".to_string()
            ]
        );
        assert_eq!(tools.exclude.unwrap(), vec!["rename_symbol".to_string()]);
    }

    #[test]
    fn json_parses_mcp_tools_allow_and_exclude() {
        let json = r#"
{
  "mcp": {
    "tools": {
      "allow": ["find_definition_at", "find_references_at"],
      "exclude": ["rename_symbol"]
    }
  }
}
"#;
        let config: LspiConfig = serde_json::from_str(json).unwrap();
        let tools = config.mcp.unwrap().tools.unwrap();
        assert_eq!(
            tools.allow.unwrap(),
            vec![
                "find_definition_at".to_string(),
                "find_references_at".to_string()
            ]
        );
        assert_eq!(tools.exclude.unwrap(), vec!["rename_symbol".to_string()]);
    }

    #[test]
    fn toml_parses_workspace_configuration_map() {
        let toml = r#"
[[servers]]
id = "ts"
kind = "generic"
extensions = ["ts"]
command = "typescript-language-server"
args = ["--stdio"]
language_id = "typescript"

[servers.workspace_configuration]
formattingOptions = { tabSize = 2, insertSpaces = true }
"#;
        let config: LspiConfig = toml::from_str(toml).unwrap();
        let server = config.servers.unwrap().into_iter().next().unwrap();
        let map = server.workspace_configuration.unwrap();
        assert!(map.contains_key("formattingOptions"));
    }

    #[test]
    fn toml_parses_request_timeout_overrides_ms() {
        let toml = r#"
[[servers]]
id = "py"
kind = "generic"
extensions = ["py"]
command = "pyright-langserver"
args = ["--stdio"]
language_id = "python"

[servers.request_timeout_overrides_ms]
"textDocument/references" = 120000
"textDocument/rename" = 120000
"textDocument/definition" = 5000
"#;
        let config: LspiConfig = toml::from_str(toml).unwrap();
        let server = config.servers.unwrap().into_iter().next().unwrap();
        let map = server.request_timeout_overrides_ms.unwrap();
        assert_eq!(map.get("textDocument/references").copied(), Some(120000));
        assert_eq!(map.get("textDocument/definition").copied(), Some(5000));
    }

    #[test]
    fn toml_parses_initialize_options_and_client_capabilities() {
        let toml = r#"
[[servers]]
id = "ts"
kind = "generic"
extensions = ["ts"]
command = "typescript-language-server"
args = ["--stdio"]
language_id = "typescript"
initialize_options = { foo = "bar", nested = { x = 1 } }
client_capabilities = { workspace = { configuration = true } }
"#;

        let config: LspiConfig = toml::from_str(toml).unwrap();
        let server = config.servers.unwrap().into_iter().next().unwrap();
        assert_eq!(
            server
                .initialize_options
                .and_then(|v| v.get("foo").and_then(|v| v.as_str()).map(|s| s.to_string())),
            Some("bar".to_string())
        );
        assert_eq!(
            server.client_capabilities.and_then(|v| {
                v.get("workspace")
                    .and_then(|v| v.get("configuration"))
                    .and_then(|v| v.as_bool())
            }),
            Some(true)
        );
    }

    #[test]
    fn json_parses_initialize_options_and_client_capabilities_aliases() {
        let json = r#"
{
  "servers": [
    {
      "id": "ts",
      "kind": "generic",
      "extensions": ["ts"],
      "command": "typescript-language-server",
      "args": ["--stdio"],
      "languageId": "typescript",
      "initializeOptions": { "foo": "bar" },
      "clientCapabilities": { "workspace": { "configuration": true } }
    }
  ]
}
"#;

        let config: LspiConfig = serde_json::from_str(json).unwrap();
        let server = config.servers.unwrap().into_iter().next().unwrap();
        assert_eq!(
            server
                .initialize_options
                .and_then(|v| v.get("foo").and_then(|v| v.as_str()).map(|s| s.to_string())),
            Some("bar".to_string())
        );
        assert_eq!(
            server.client_capabilities.and_then(|v| {
                v.get("workspace")
                    .and_then(|v| v.get("configuration"))
                    .and_then(|v| v.as_bool())
            }),
            Some(true)
        );
    }

    #[test]
    fn route_server_by_path_prefers_longest_root_dir_match() {
        let root = temp_root("route-longest");
        let nested = root.join("nested");
        std::fs::create_dir_all(nested.join("src")).unwrap();

        let servers = vec![
            ResolvedServerConfig {
                id: "root".to_string(),
                kind: "rust_analyzer".to_string(),
                command: None,
                args: Vec::new(),
                extensions: vec!["rs".to_string()],
                language_id: None,
                root_dir: root.clone(),
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
            ResolvedServerConfig {
                id: "nested".to_string(),
                kind: "rust_analyzer".to_string(),
                command: None,
                args: Vec::new(),
                extensions: vec!["rs".to_string()],
                language_id: None,
                root_dir: nested.clone(),
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
        ];

        let file_in_nested = nested.join("src").join("lib.rs");
        let routed = route_server_by_path(&file_in_nested, &servers).unwrap();
        assert_eq!(routed.id, "nested");

        let file_in_root = root.join("main.rs");
        let routed = route_server_by_path(&file_in_root, &servers).unwrap();
        assert_eq!(routed.id, "root");
    }

    #[test]
    fn route_server_by_path_falls_back_to_first_extension_match() {
        let root = temp_root("route-fallback");
        let file = root.join("main.rs");

        let servers = vec![
            ResolvedServerConfig {
                id: "first".to_string(),
                kind: "rust_analyzer".to_string(),
                command: None,
                args: Vec::new(),
                extensions: vec!["rs".to_string()],
                language_id: None,
                root_dir: root.join("does-not-contain"),
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
            ResolvedServerConfig {
                id: "second".to_string(),
                kind: "rust_analyzer".to_string(),
                command: None,
                args: Vec::new(),
                extensions: vec!["rs".to_string()],
                language_id: None,
                root_dir: root.join("also-does-not-contain"),
                initialize_timeout_ms: None,
                request_timeout_ms: None,
                request_timeout_overrides_ms: HashMap::new(),
                warmup_timeout_ms: None,
                restart_interval_minutes: None,
                idle_shutdown_ms: None,
                initialize_options: None,
                client_capabilities: None,
                workspace_configuration: HashMap::new(),
            },
        ];

        let routed = route_server_by_path(&file, &servers).unwrap();
        assert_eq!(routed.id, "first");
    }
}
