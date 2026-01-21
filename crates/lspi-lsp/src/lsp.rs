use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex, Notify, oneshot, watch};
use tokio::time::{Duration, timeout};
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspRange {
    pub start: LspPosition,
    pub end: LspPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspLocation {
    pub uri: String,
    pub range: LspRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspLocationLink {
    #[serde(rename = "targetUri")]
    pub target_uri: String,
    #[serde(rename = "targetRange")]
    pub target_range: LspRange,
    #[serde(rename = "targetSelectionRange")]
    pub target_selection_range: LspRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspTextEdit {
    pub range: LspRange,
    #[serde(rename = "newText")]
    pub new_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspOptionalVersionedTextDocumentIdentifier {
    pub uri: String,
    #[serde(default)]
    pub version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspTextDocumentEdit {
    pub text_document: LspOptionalVersionedTextDocumentIdentifier,
    pub edits: Vec<LspTextEdit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LspWorkspaceEdit {
    #[serde(default)]
    pub changes: Option<HashMap<String, Vec<LspTextEdit>>>,
    #[serde(rename = "documentChanges", default)]
    pub document_changes: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspDiagnostic {
    pub range: LspRange,
    #[serde(default)]
    pub severity: Option<u32>,
    #[serde(default)]
    pub code: Option<Value>,
    #[serde(default)]
    pub source: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishDiagnosticsParams {
    pub uri: String,
    pub diagnostics: Vec<LspDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspTextDocumentItem {
    pub uri: String,
    pub language_id: String,
    pub version: i32,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspTextDocumentIdentifier {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspDidOpenTextDocumentParams {
    pub text_document: LspTextDocumentItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspVersionedTextDocumentIdentifier {
    pub uri: String,
    pub version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspTextDocumentContentChangeEvent {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspDidChangeTextDocumentParams {
    pub text_document: LspVersionedTextDocumentIdentifier,
    pub content_changes: Vec<LspTextDocumentContentChangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspTextDocumentPositionParams {
    pub text_document: LspTextDocumentIdentifier,
    pub position: LspPosition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspReferenceContext {
    pub include_declaration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspReferencesParams {
    pub text_document: LspTextDocumentIdentifier,
    pub position: LspPosition,
    pub context: LspReferenceContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspDocumentSymbolParams {
    pub text_document: LspTextDocumentIdentifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspSymbolInformation {
    pub name: String,
    pub kind: u32,
    pub location: LspLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LspDocumentSymbol {
    pub name: String,
    pub kind: u32,
    pub range: LspRange,
    pub selection_range: LspRange,
    #[serde(default)]
    pub children: Vec<LspDocumentSymbol>,
}

#[derive(Debug, Clone)]
pub struct ServerStatus {
    pub health: String,
    pub quiescent: bool,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct LspClientOptions {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub initialize_timeout: Duration,
    pub request_timeout: Duration,
}

#[derive(Debug)]
struct LspState {
    next_id: i64,
    pending: HashMap<i64, oneshot::Sender<Value>>,
}

pub struct LspClient {
    stdin: Mutex<ChildStdin>,
    state: Arc<Mutex<LspState>>,
    #[allow(dead_code)]
    child: Child,
    diagnostics: Arc<Mutex<HashMap<String, Vec<LspDiagnostic>>>>,
    diagnostics_notify: Arc<Notify>,
    server_status_tx: watch::Sender<Option<ServerStatus>>,
    server_status_rx: watch::Receiver<Option<ServerStatus>>,
    initialized: Notify,
    root_uri: String,
    diagnostic_pull_supported: AtomicU8, // 0=unknown, 1=yes, 2=no
    default_request_timeout: Duration,
}

impl LspClient {
    pub async fn start(options: LspClientOptions) -> Result<Self> {
        let mut command = Command::new(&options.command);
        command
            .args(&options.args)
            .current_dir(&options.cwd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to spawn LSP server: {}", options.command))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("failed to capture LSP stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("failed to capture LSP stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("failed to capture LSP stderr"))?;

        let (server_status_tx, server_status_rx) = watch::channel(None);
        let client = Self {
            stdin: Mutex::new(stdin),
            state: Arc::new(Mutex::new(LspState {
                next_id: 1,
                pending: HashMap::new(),
            })),
            child,
            diagnostics: Arc::new(Mutex::new(HashMap::new())),
            diagnostics_notify: Arc::new(Notify::new()),
            server_status_tx,
            server_status_rx,
            initialized: Notify::new(),
            root_uri: Url::from_directory_path(&options.cwd)
                .map_err(|_| anyhow!("failed to build rootUri for {:?}", options.cwd))?
                .to_string(),
            diagnostic_pull_supported: AtomicU8::new(0),
            default_request_timeout: options.request_timeout,
        };

        client.spawn_stdout_reader(stdout);
        spawn_stderr_logger(stderr);

        client
            .initialize(options.initialize_timeout)
            .await
            .context("failed to initialize LSP server")?;

        Ok(client)
    }

    pub fn server_status_receiver(&self) -> watch::Receiver<Option<ServerStatus>> {
        self.server_status_rx.clone()
    }

    pub async fn did_open(
        &self,
        path: &Path,
        language_id: &str,
        version: i32,
        text: String,
    ) -> Result<()> {
        let uri = path_to_uri(path)?;
        let params = LspDidOpenTextDocumentParams {
            text_document: LspTextDocumentItem {
                uri,
                language_id: language_id.to_string(),
                version,
                text,
            },
        };
        self.send_notification("textDocument/didOpen", &params)
            .await
    }

    pub async fn did_change(&self, path: &Path, version: i32, text: String) -> Result<()> {
        let uri = path_to_uri(path)?;
        let params = LspDidChangeTextDocumentParams {
            text_document: LspVersionedTextDocumentIdentifier { uri, version },
            content_changes: vec![LspTextDocumentContentChangeEvent { text }],
        };
        self.send_notification("textDocument/didChange", &params)
            .await
    }

    pub async fn document_symbols(&self, path: &Path) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = LspDocumentSymbolParams {
            text_document: LspTextDocumentIdentifier { uri },
        };
        self.send_request("textDocument/documentSymbol", &params, None)
            .await
    }

    pub async fn definition(&self, path: &Path, position: LspPosition) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = LspTextDocumentPositionParams {
            text_document: LspTextDocumentIdentifier { uri },
            position,
        };
        self.send_request("textDocument/definition", &params, None)
            .await
    }

    pub async fn references(
        &self,
        path: &Path,
        position: LspPosition,
        include_declaration: bool,
    ) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = LspReferencesParams {
            text_document: LspTextDocumentIdentifier { uri },
            position,
            context: LspReferenceContext {
                include_declaration,
            },
        };
        self.send_request("textDocument/references", &params, None)
            .await
    }

    pub async fn rename(
        &self,
        path: &Path,
        position: LspPosition,
        new_name: &str,
    ) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": position,
            "newName": new_name
        });
        self.send_request("textDocument/rename", &params, None)
            .await
    }

    pub async fn hover(&self, path: &Path, position: LspPosition) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": position
        });
        self.send_request("textDocument/hover", &params, None).await
    }

    pub async fn implementation(&self, path: &Path, position: LspPosition) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": position
        });
        self.send_request("textDocument/implementation", &params, None)
            .await
    }

    pub async fn type_definition(&self, path: &Path, position: LspPosition) -> Result<Value> {
        let uri = path_to_uri(path)?;
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "position": position
        });
        self.send_request("textDocument/typeDefinition", &params, None)
            .await
    }

    pub async fn document_diagnostics(
        &self,
        path: &Path,
        request_timeout: Duration,
    ) -> Result<Option<Vec<LspDiagnostic>>> {
        if self.diagnostic_pull_supported.load(Ordering::Relaxed) == 2 {
            return Ok(None);
        }

        let uri = path_to_uri(path)?;
        let params = serde_json::json!({
            "textDocument": { "uri": uri },
            "identifier": null,
            "previousResultId": null
        });

        match self
            .send_request("textDocument/diagnostic", &params, Some(request_timeout))
            .await
        {
            Ok(value) => {
                self.diagnostic_pull_supported.store(1, Ordering::Relaxed);
                parse_document_diagnostic_report(value).map(Some)
            }
            Err(err) => {
                let msg = err.to_string().to_ascii_lowercase();
                if msg.contains("-32601") || msg.contains("method not found") {
                    self.diagnostic_pull_supported.store(2, Ordering::Relaxed);
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    pub async fn get_cached_diagnostics(&self, path: &Path) -> Result<Vec<LspDiagnostic>> {
        let uri = path_to_uri(path)?;
        let guard = self.diagnostics.lock().await;
        Ok(guard.get(&uri).cloned().unwrap_or_default())
    }

    pub async fn wait_for_diagnostics_update(
        &self,
        path: &Path,
        max_wait: Duration,
    ) -> Result<Vec<LspDiagnostic>> {
        let uri = path_to_uri(path)?;
        {
            let guard = self.diagnostics.lock().await;
            if let Some(existing) = guard.get(&uri) {
                return Ok(existing.clone());
            }
        }

        if timeout(max_wait, self.diagnostics_notify.notified())
            .await
            .is_err()
        {
            return self.get_cached_diagnostics(path).await;
        }

        self.get_cached_diagnostics(path).await
    }

    pub async fn workspace_symbols(&self, query: &str) -> Result<Value> {
        let params = serde_json::json!({ "query": query });
        self.send_request("workspace/symbol", &params, None).await
    }

    pub async fn send_request<T: Serialize>(
        &self,
        method: &str,
        params: &T,
        request_timeout: Option<Duration>,
    ) -> Result<Value> {
        let id = {
            let mut state = self.state.lock().await;
            let id = state.next_id;
            state.next_id += 1;
            id
        };

        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.state.lock().await;
            state.pending.insert(id, tx);
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.write_message(&request).await?;

        let wait = request_timeout.unwrap_or(self.default_request_timeout);
        let response_value = timeout(wait, rx)
            .await
            .with_context(|| format!("LSP request timed out: {method}"))?
            .map_err(|_| anyhow!("LSP response channel closed: {method}"))?;

        if let Some(error) = response_value.get("error") {
            return Err(anyhow!("LSP error for {method}: {error}"));
        }

        Ok(response_value.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn send_notification<T: Serialize>(&self, method: &str, params: &T) -> Result<()> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_message(&request).await
    }

    pub async fn shutdown(mut self) -> Result<()> {
        // Best-effort graceful shutdown, then kill as fallback.
        let _ = self
            .send_request("shutdown", &Value::Null, Some(Duration::from_secs(2)))
            .await;
        let _ = self.send_notification("exit", &Value::Null).await;

        // Ensure the child process does not linger.
        let _ = self.child.kill().await;
        let _ = self.child.wait().await;
        Ok(())
    }

    async fn initialize(&self, initialize_timeout: Duration) -> Result<()> {
        let params = serde_json::json!({
            "processId": null,
            "rootUri": self.root_uri,
            "capabilities": {
                "textDocument": {
                    "documentSymbol": {
                        "hierarchicalDocumentSymbolSupport": true
                    }
                },
                "experimental": {
                    "serverStatusNotification": true
                }
            },
            "workspaceFolders": [
                { "uri": self.root_uri, "name": "workspace" }
            ]
        });

        let _ = self
            .send_request("initialize", &params, Some(initialize_timeout))
            .await?;
        self.send_notification("initialized", &serde_json::json!({}))
            .await?;

        self.initialized.notify_waiters();
        Ok(())
    }

    async fn write_message(&self, value: &Value) -> Result<()> {
        let body = serde_json::to_vec(value)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        let mut stdin = self.stdin.lock().await;
        stdin.write_all(header.as_bytes()).await?;
        stdin.write_all(&body).await?;
        stdin.flush().await?;
        Ok(())
    }

    fn spawn_stdout_reader(&self, stdout: ChildStdout) {
        let pending = self.state.clone();
        let server_status_tx = self.server_status_tx.clone();
        let diagnostics = self.diagnostics.clone();
        let diagnostics_notify = self.diagnostics_notify.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_lsp_message(&mut reader).await {
                    Ok(Some(message)) => {
                        handle_lsp_message(
                            message,
                            pending.clone(),
                            &server_status_tx,
                            diagnostics.clone(),
                            diagnostics_notify.clone(),
                        )
                        .await;
                    }
                    Ok(None) => break,
                    Err(err) => {
                        warn!("failed to read LSP message: {err:#}");
                        break;
                    }
                }
            }
        });
    }
}

fn parse_document_diagnostic_report(value: Value) -> Result<Vec<LspDiagnostic>> {
    // DocumentDiagnosticReport: { kind: "full", items: Diagnostic[] } or { kind: "unchanged" }.
    if value.is_null() {
        return Ok(Vec::new());
    }

    let Some(items) = value.get("items").and_then(|v| v.as_array()) else {
        return Ok(Vec::new());
    };

    let diags: Vec<LspDiagnostic> = serde_json::from_value(Value::Array(items.clone()))
        .context("failed to parse Diagnostic[]")?;
    Ok(diags)
}

async fn handle_lsp_message(
    message: Value,
    state: Arc<Mutex<LspState>>,
    server_status_tx: &watch::Sender<Option<ServerStatus>>,
    diagnostics: Arc<Mutex<HashMap<String, Vec<LspDiagnostic>>>>,
    diagnostics_notify: Arc<Notify>,
) {
    if let Some(method) = message.get("method").and_then(|m| m.as_str()) {
        if method == "experimental/serverStatus"
            && let Some(params) = message.get("params")
        {
            match serde_json::from_value::<ServerStatusParams>(params.clone()) {
                Ok(p) => {
                    let _ = server_status_tx.send(Some(ServerStatus {
                        health: p.health,
                        quiescent: p.quiescent,
                        message: p.message,
                    }));
                }
                Err(err) => warn!("failed to parse serverStatus params: {err:#}"),
            }
        }
        if method == "textDocument/publishDiagnostics"
            && let Some(params) = message.get("params")
        {
            match serde_json::from_value::<PublishDiagnosticsParams>(params.clone()) {
                Ok(p) => {
                    let mut guard = diagnostics.lock().await;
                    guard.insert(p.uri, p.diagnostics);
                    diagnostics_notify.notify_waiters();
                }
                Err(err) => warn!("failed to parse publishDiagnostics params: {err:#}"),
            }
        }
        return;
    }

    let id = match message.get("id") {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    };

    if let Some(id) = id {
        let tx = {
            let mut guard = state.lock().await;
            guard.pending.remove(&id)
        };
        if let Some(tx) = tx {
            let _ = tx.send(message);
        } else {
            debug!("received response for unknown id: {id}");
        }
    }
}

#[derive(Debug, Deserialize)]
struct ServerStatusParams {
    health: String,
    quiescent: bool,
    #[serde(default)]
    message: Option<String>,
}

async fn read_lsp_message(reader: &mut BufReader<ChildStdout>) -> Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            return Ok(None);
        }

        let line_trimmed = line.trim_end_matches(['\r', '\n']);
        if line_trimmed.is_empty() {
            break;
        }

        if let Some(value) = line_trimmed.strip_prefix("Content-Length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let Some(len) = content_length else {
        return Err(anyhow!("missing Content-Length header"));
    };

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let value: Value = serde_json::from_slice(&buf)?;
    Ok(Some(value))
}

fn spawn_stderr_logger(stderr: ChildStderr) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => debug!(target: "lsp.stderr", "{}", line.trim_end()),
                Err(_) => break,
            }
        }
    });
}

pub fn path_to_uri(path: &Path) -> Result<String> {
    Url::from_file_path(path)
        .map_err(|_| anyhow!("failed to convert path to file URI: {path:?}"))
        .map(|u| u.to_string())
}

pub fn uri_to_path(uri: &str) -> Result<PathBuf> {
    let url = Url::parse(uri).with_context(|| format!("invalid URI: {uri}"))?;
    if url.scheme() != "file" {
        return Err(anyhow!("unsupported URI scheme: {}", url.scheme()));
    }
    url.to_file_path()
        .map_err(|_| anyhow!("failed to convert URI to path: {uri}"))
}

pub fn normalize_workspace_edit(value: Value) -> Result<HashMap<String, Vec<LspTextEdit>>> {
    let edit: LspWorkspaceEdit =
        serde_json::from_value(value).context("failed to parse WorkspaceEdit")?;
    let mut out = edit.changes.unwrap_or_default();

    let Some(document_changes) = edit.document_changes else {
        return Ok(out);
    };

    for change in document_changes {
        let is_text_document_edit =
            change.get("textDocument").is_some() && change.get("edits").is_some();
        if !is_text_document_edit {
            continue;
        }
        let tde: LspTextDocumentEdit = serde_json::from_value(change)
            .context("failed to parse TextDocumentEdit in WorkspaceEdit")?;
        out.entry(tde.text_document.uri)
            .or_default()
            .extend(tde.edits);
    }

    Ok(out)
}
