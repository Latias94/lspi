use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use lspi_core::hashing::sha256_hex;
use serde_json::Value;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::lsp::{
    LspClient, LspClientOptions, LspDiagnostic, LspPosition, LspTextEdit, ServerStatus,
    normalize_workspace_edit,
};
use crate::symbol::{
    DefinitionMatch, FlatSymbol, ReferenceMatch, RenameCandidate, ResolvedLocation, ResolvedSymbol,
    parse_locations, parse_symbols, to_lsp_location, to_resolved_location,
};

#[derive(Debug, Clone)]
pub struct RustAnalyzerClientOptions {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub initialize_timeout: Duration,
    pub request_timeout: Duration,
    pub warmup_timeout: Duration,
}

pub async fn resolve_rust_analyzer_command() -> Result<String> {
    if let Ok(value) = std::env::var("LSPI_RUST_ANALYZER_COMMAND")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }

    // If the user installed rust-analyzer via rustup component, rustup can tell us the actual path.
    let output = Command::new("rustup")
        .args(["which", "rust-analyzer"])
        .output()
        .await;

    if let Ok(output) = output
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(path);
        }
    }

    Ok("rust-analyzer".to_string())
}

pub async fn preflight_rust_analyzer(command: &str) -> Result<()> {
    let output = Command::new(command)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("failed to run `{command} --version`"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("Unknown binary") && stderr.contains("rust-analyzer") {
        return Err(anyhow::anyhow!(
            "rust-analyzer is not installed. Install it via `rustup component add rust-analyzer` or set LSPI_RUST_ANALYZER_COMMAND to a valid rust-analyzer binary."
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(anyhow!(
        "`{command} --version` failed (status={} stdout={:?} stderr={:?})",
        output.status,
        stdout.trim(),
        stderr.trim()
    ))
}

impl Default for RustAnalyzerClientOptions {
    fn default() -> Self {
        Self {
            command: "rust-analyzer".to_string(),
            args: Vec::new(),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            initialize_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            warmup_timeout: Duration::from_secs(5),
        }
    }
}

pub struct RustAnalyzerClient {
    lsp: LspClient,
    open_files: Mutex<HashMap<PathBuf, OpenFileState>>,
    status_rx: tokio::sync::watch::Receiver<Option<ServerStatus>>,
    warmup_timeout: Duration,
}

#[derive(Debug, Clone)]
struct OpenFileState {
    version: i32,
    last_sha256: String,
}

impl RustAnalyzerClient {
    pub async fn start(options: RustAnalyzerClientOptions) -> Result<Self> {
        let lsp = LspClient::start(LspClientOptions {
            command: options.command,
            args: options.args,
            cwd: options.cwd,
            initialize_timeout: options.initialize_timeout,
            request_timeout: options.request_timeout,
        })
        .await?;

        let status_rx = lsp.server_status_receiver();

        Ok(Self {
            lsp,
            open_files: Mutex::new(HashMap::new()),
            status_rx,
            warmup_timeout: options.warmup_timeout,
        })
    }

    pub async fn shutdown(self) -> Result<()> {
        self.lsp.shutdown().await
    }

    pub async fn wait_quiescent(&self) -> Result<Option<ServerStatus>> {
        let mut rx = self.status_rx.clone();
        let deadline = tokio::time::Instant::now() + self.warmup_timeout;

        loop {
            if let Some(status) = rx.borrow().clone()
                && status.quiescent
            {
                return Ok(Some(status));
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Ok(rx.borrow().clone());
            }

            let remaining = deadline.saturating_duration_since(now);
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return Ok(rx.borrow().clone());
            }
        }
    }

    async fn document_symbols_with_retry(&self, file_path: &Path) -> Result<Vec<FlatSymbol>> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..3 {
            match self.lsp.document_symbols(file_path).await {
                Ok(value) => match parse_symbols(value) {
                    Ok(symbols) => {
                        if !symbols.is_empty() {
                            return Ok(symbols);
                        }
                        if attempt == 0 {
                            let _ = self.wait_quiescent().await?;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }

        if let Some(err) = last_err {
            return Err(err);
        }
        Ok(Vec::new())
    }

    async fn definition_values_with_retry(
        &self,
        file_path: &Path,
        position: LspPosition,
    ) -> Result<Vec<Value>> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..3 {
            match self.lsp.definition(file_path, position.clone()).await {
                Ok(value) => match parse_locations(value) {
                    Ok(defs) => {
                        if !defs.is_empty() {
                            return Ok(defs);
                        }
                        if attempt == 0 {
                            let _ = self.wait_quiescent().await?;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }

        if let Some(err) = last_err {
            return Err(err);
        }
        Ok(Vec::new())
    }

    async fn reference_values_with_retry(
        &self,
        file_path: &Path,
        position: LspPosition,
        include_declaration: bool,
    ) -> Result<Vec<Value>> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..3 {
            match self
                .lsp
                .references(file_path, position.clone(), include_declaration)
                .await
            {
                Ok(value) => match parse_locations(value) {
                    Ok(refs) => {
                        if !refs.is_empty() {
                            return Ok(refs);
                        }
                        if attempt == 0 {
                            let _ = self.wait_quiescent().await?;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }

        if let Some(err) = last_err {
            return Err(err);
        }
        Ok(Vec::new())
    }

    pub async fn find_definition_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> Result<Vec<DefinitionMatch>> {
        self.open_or_sync(file_path, "rust").await?;

        // For a better first-call experience, wait (bounded) for rust-analyzer to settle.
        if let Some(status) = self.wait_quiescent().await?
            && !status.quiescent
        {
            warn!(
                "rust-analyzer not quiescent yet: health={} message={:?}",
                status.health, status.message
            );
        }

        let symbols = self.document_symbols_with_retry(file_path).await?;

        let mut matches = Vec::new();
        for sym in symbols
            .into_iter()
            .filter(|s| s.name == symbol_name)
            .filter(|s| symbol_kind.map(|k| k == s.kind).unwrap_or(true))
            .take(max_symbols)
        {
            let pos = sym.selection_range.start.clone();
            let defs = self.definition_values_with_retry(file_path, pos).await?;
            let mut resolved = Vec::new();
            for def in defs {
                let lsp_loc = to_lsp_location(&def)?;
                if let Ok(r) = to_resolved_location(&lsp_loc) {
                    resolved.push(r);
                }
            }

            matches.push(DefinitionMatch {
                symbol: ResolvedSymbol {
                    name: sym.name,
                    kind: sym.kind,
                    range: sym.range,
                    selection_range: sym.selection_range,
                },
                definitions: resolved,
            });
        }

        Ok(matches)
    }

    pub async fn definition_at(
        &self,
        file_path: &Path,
        position: LspPosition,
        max_definitions: usize,
    ) -> Result<Vec<ResolvedLocation>> {
        self.open_or_sync(file_path, "rust").await?;

        if let Some(status) = self.wait_quiescent().await?
            && !status.quiescent
        {
            warn!(
                "rust-analyzer not quiescent yet: health={} message={:?}",
                status.health, status.message
            );
        }

        let defs = self
            .definition_values_with_retry(file_path, position)
            .await?;

        let mut resolved = Vec::new();
        for def in defs.into_iter().take(max_definitions.max(1)) {
            let lsp_loc = to_lsp_location(&def)?;
            if let Ok(r) = to_resolved_location(&lsp_loc) {
                resolved.push(r);
            }
        }
        Ok(resolved)
    }

    pub async fn references_at(
        &self,
        file_path: &Path,
        position: LspPosition,
        include_declaration: bool,
        max_references: usize,
    ) -> Result<(Vec<ResolvedLocation>, bool)> {
        self.open_or_sync(file_path, "rust").await?;

        if let Some(status) = self.wait_quiescent().await?
            && !status.quiescent
        {
            warn!(
                "rust-analyzer not quiescent yet: health={} message={:?}",
                status.health, status.message
            );
        }

        let refs = self
            .reference_values_with_retry(file_path, position, include_declaration)
            .await?;

        let mut resolved = Vec::new();
        let mut truncated = false;
        let limit = max_references.max(1);
        for def in refs {
            if resolved.len() >= limit {
                truncated = true;
                break;
            }
            let lsp_loc = to_lsp_location(&def)?;
            if let Ok(r) = to_resolved_location(&lsp_loc) {
                resolved.push(r);
            }
        }
        Ok((resolved, truncated))
    }

    pub async fn find_references_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        include_declaration: bool,
        max_symbols: usize,
        max_references: usize,
    ) -> Result<Vec<ReferenceMatch>> {
        self.open_or_sync(file_path, "rust").await?;

        if let Some(status) = self.wait_quiescent().await?
            && !status.quiescent
        {
            warn!(
                "rust-analyzer not quiescent yet: health={} message={:?}",
                status.health, status.message
            );
        }

        let symbols = self.document_symbols_with_retry(file_path).await?;

        let mut results = Vec::new();
        let mut remaining = max_references.max(1);

        for sym in symbols
            .into_iter()
            .filter(|s| s.name == symbol_name)
            .filter(|s| symbol_kind.map(|k| k == s.kind).unwrap_or(true))
            .take(max_symbols)
        {
            if remaining == 0 {
                break;
            }

            let pos = sym.selection_range.start.clone();
            let refs = self
                .reference_values_with_retry(file_path, pos, include_declaration)
                .await?;
            let mut references = Vec::new();
            let mut truncated = false;

            for r in refs {
                let lsp_loc = to_lsp_location(&r)?;
                if let Ok(resolved) = to_resolved_location(&lsp_loc) {
                    references.push(resolved);
                    remaining = remaining.saturating_sub(1);
                    if remaining == 0 {
                        truncated = true;
                        break;
                    }
                }
            }

            results.push(ReferenceMatch {
                symbol: ResolvedSymbol {
                    name: sym.name,
                    kind: sym.kind,
                    range: sym.range,
                    selection_range: sym.selection_range,
                },
                references,
                truncated,
            });
        }

        Ok(results)
    }

    pub async fn get_diagnostics(
        &self,
        file_path: &Path,
        max_wait: Duration,
    ) -> Result<Vec<LspDiagnostic>> {
        self.open_or_sync(file_path, "rust").await?;
        let _ = self.wait_quiescent().await?;

        if let Some(diags) = self.lsp.document_diagnostics(file_path, max_wait).await? {
            return Ok(diags);
        }

        self.lsp
            .wait_for_diagnostics_update(file_path, max_wait)
            .await
    }

    pub async fn list_symbol_candidates(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> Result<Vec<RenameCandidate>> {
        self.open_or_sync(file_path, "rust").await?;

        let _ = self.wait_quiescent().await?;

        let symbols = self.document_symbols_with_retry(file_path).await?;

        Ok(symbols
            .into_iter()
            .filter(|s| s.name == symbol_name)
            .filter(|s| symbol_kind.map(|k| k == s.kind).unwrap_or(true))
            .take(max_symbols)
            .map(|s| RenameCandidate {
                name: s.name,
                kind: s.kind,
                line: s.selection_range.start.line + 1,
                character: s.selection_range.start.character + 1,
                selection_range: s.selection_range,
            })
            .collect())
    }

    pub async fn rename_at(
        &self,
        file_path: &Path,
        position: LspPosition,
        new_name: &str,
    ) -> Result<HashMap<String, Vec<LspTextEdit>>> {
        self.prepare_file(file_path).await?;
        self.rename_at_prepared(file_path, position, new_name).await
    }

    pub async fn rename_at_prepared(
        &self,
        file_path: &Path,
        position: LspPosition,
        new_name: &str,
    ) -> Result<HashMap<String, Vec<LspTextEdit>>> {
        let raw = self.lsp.rename(file_path, position, new_name).await?;
        normalize_workspace_edit(raw)
    }

    async fn prepare_file(&self, file_path: &Path) -> Result<()> {
        self.open_or_sync(file_path, "rust").await?;
        let _ = self.wait_quiescent().await?;
        Ok(())
    }

    async fn open_or_sync(&self, file_path: &Path, language_id: &str) -> Result<()> {
        let abs = file_path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize file path: {file_path:?}"))?;
        let content = fs::read(&abs)
            .await
            .with_context(|| format!("failed to read file: {abs:?}"))?;
        let hash = sha256_hex(&content);
        let text = String::from_utf8(content).context("file is not valid UTF-8")?;

        let mut open = self.open_files.lock().await;
        match open.get_mut(&abs) {
            None => {
                debug!("didOpen {:?}", abs);
                self.lsp.did_open(&abs, language_id, 1, text).await?;
                open.insert(
                    abs,
                    OpenFileState {
                        version: 1,
                        last_sha256: hash,
                    },
                );
            }
            Some(state) => {
                if state.last_sha256 != hash {
                    state.version += 1;
                    state.last_sha256 = hash;
                    debug!("didChange {:?} version={}", abs, state.version);
                    self.lsp.did_change(&abs, state.version, text).await?;
                }
            }
        }
        Ok(())
    }
}
