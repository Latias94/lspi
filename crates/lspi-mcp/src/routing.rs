use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::ErrorData as McpError;
use tracing::info;

use crate::routed_client::RoutedClient;
use crate::{LspiMcpServer, ManagedClient};

impl LspiMcpServer {
    pub(crate) fn start_idle_reaper_if_configured(&self) {
        let mut idle_policies = std::collections::HashMap::<String, (String, Duration)>::new();
        for s in &self.state.servers {
            let Some(ms) = s.idle_shutdown_ms.filter(|ms| *ms > 0) else {
                continue;
            };
            idle_policies.insert(s.id.clone(), (s.kind.clone(), Duration::from_millis(ms)));
        }

        if idle_policies.is_empty() {
            return;
        }

        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;

                let now = Instant::now();
                let mut to_shutdown_ra: Vec<(String, ManagedClient<lspi_lsp::RustAnalyzerClient>)> =
                    Vec::new();
                let mut to_shutdown_os: Vec<(String, ManagedClient<lspi_lsp::OmniSharpClient>)> =
                    Vec::new();
                let mut to_shutdown_generic: Vec<(
                    String,
                    ManagedClient<lspi_lsp::GenericLspClient>,
                )> = Vec::new();

                for (id, (kind, idle)) in idle_policies.iter() {
                    if is_rust_analyzer_kind(kind) {
                        let removed = {
                            let mut guard = state.rust_analyzer.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_ra.push(r);
                        }
                        continue;
                    }

                    if is_omnisharp_kind(kind) {
                        let removed = {
                            let mut guard = state.omnisharp.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_os.push(r);
                        }
                        continue;
                    }

                    if is_generic_kind(kind) || is_pyright_kind(kind) {
                        let removed = {
                            let mut guard = state.generic.lock().await;
                            if let Some(entry) = guard.get(id) {
                                if now.duration_since(entry.last_used) >= *idle {
                                    guard.remove(id).map(|e| (id.clone(), e))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        };
                        if let Some(r) = removed {
                            to_shutdown_generic.push(r);
                        }
                        continue;
                    }
                }

                for (id, entry) in to_shutdown_ra {
                    info!("idle shutdown: stopping rust-analyzer server_id={id}");
                    if let Err(entry) = shutdown_rust_analyzer_managed(entry).await {
                        let mut guard = state.rust_analyzer.lock().await;
                        guard.insert(id, entry);
                    }
                }
                for (id, entry) in to_shutdown_os {
                    info!("idle shutdown: stopping omnisharp server_id={id}");
                    if let Err(entry) = shutdown_omnisharp_managed(entry).await {
                        let mut guard = state.omnisharp.lock().await;
                        guard.insert(id, entry);
                    }
                }
                for (id, entry) in to_shutdown_generic {
                    info!("idle shutdown: stopping generic server_id={id}");
                    if let Err(entry) = shutdown_generic_managed(entry).await {
                        let mut guard = state.generic.lock().await;
                        guard.insert(id, entry);
                    }
                }
            }
        });
    }

    pub(crate) async fn client_for_file(&self, abs_file: &Path) -> Result<RoutedClient, McpError> {
        let Some(server) = lspi_core::config::route_server_by_path(abs_file, &self.state.servers)
        else {
            let ext = abs_file
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("<none>");
            return Err(McpError::invalid_params(
                format!("no configured LSP server matches file extension: {ext}"),
                None,
            ));
        };

        self.client_for_server(server).await
    }

    pub(crate) async fn client_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<RoutedClient, McpError> {
        if is_rust_analyzer_kind(&server.kind) {
            let client = self.rust_analyzer_for_server(server).await?;
            return Ok(RoutedClient::Rust {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_omnisharp_kind(&server.kind) {
            let client = self.omnisharp_for_server(server).await?;
            return Ok(RoutedClient::OmniSharp {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_pyright_kind(&server.kind) {
            let client = self.pyright_for_server(server).await?;
            return Ok(RoutedClient::Generic {
                server_id: server.id.clone(),
                client,
            });
        }

        if is_generic_kind(&server.kind) {
            let client = self.generic_for_server(server).await?;
            return Ok(RoutedClient::Generic {
                server_id: server.id.clone(),
                client,
            });
        }

        Err(McpError::invalid_params(
            format!(
                "server kind is not supported yet: id={} kind={}",
                server.id, server.kind
            ),
            None,
        ))
    }

    pub(crate) async fn rust_analyzer_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::RustAnalyzerClient>, McpError> {
        let now = Instant::now();

        // Fast path: reuse running server unless restart policy triggers.
        let restart_old = {
            let mut guard = self.state.rust_analyzer.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_rust_analyzer_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    // Server is busy; keep the existing instance to avoid leaking a subprocess.
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.rust_analyzer.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = match server.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => lspi_lsp::resolve_rust_analyzer_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };
        lspi_lsp::preflight_rust_analyzer(&command)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(10));
        let request_timeout = server
            .request_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);
        let warmup_timeout = server
            .warmup_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(5));

        let client = lspi_lsp::RustAnalyzerClient::start(lspi_lsp::RustAnalyzerClientOptions {
            command,
            args: server.args.clone(),
            cwd: server.cwd.clone(),
            env: server.env.clone(),
            workspace_folders: server.workspace_folders.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            warmup_timeout,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.rust_analyzer.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_rust_analyzer_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    pub(crate) async fn omnisharp_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::OmniSharpClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.omnisharp.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_omnisharp_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.omnisharp.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = match server.command.as_deref() {
            Some(c) if !c.trim().is_empty() => c.to_string(),
            _ => lspi_lsp::resolve_omnisharp_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };
        lspi_lsp::preflight_omnisharp(&command)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let args = if server.args.is_empty() {
            vec!["-lsp".to_string()]
        } else {
            server.args.clone()
        };

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(10));
        let request_timeout = server
            .request_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);
        let warmup_delay = server
            .warmup_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(1));

        let client = lspi_lsp::OmniSharpClient::start(lspi_lsp::OmniSharpClientOptions {
            command,
            args,
            cwd: server.cwd.clone(),
            env: server.env.clone(),
            workspace_folders: server.workspace_folders.clone(),
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.omnisharp.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_omnisharp_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    pub(crate) async fn generic_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::GenericLspClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.generic.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_generic_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.generic.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let command = server
            .command
            .as_deref()
            .filter(|c| !c.trim().is_empty())
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("missing command for generic server id={}", server.id),
                    None,
                )
            })?
            .to_string();

        let args = if server.args.is_empty() {
            vec!["--stdio".to_string()]
        } else {
            server.args.clone()
        };

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(20));
        let request_timeout = server
            .request_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));
        let request_timeout_overrides =
            request_timeout_overrides_to_durations(&server.request_timeout_overrides_ms);

        let warmup_delay = server
            .warmup_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(0));

        let language_id = server
            .language_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| guess_language_id_from_extensions(&server.extensions));

        let adapter = server
            .adapter
            .as_deref()
            .and_then(lspi_lsp::adapter_from_name)
            .or_else(|| lspi_lsp::adapter_from_command(&command))
            .unwrap_or_default();

        let client = lspi_lsp::GenericLspClient::start(lspi_lsp::GenericLspClientOptions {
            command,
            args,
            cwd: server.cwd.clone(),
            env: server.env.clone(),
            workspace_folders: server.workspace_folders.clone(),
            adapter,
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            language_id,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.generic.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_generic_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }

    pub(crate) async fn pyright_for_server(
        &self,
        server: &lspi_core::config::ResolvedServerConfig,
    ) -> Result<Arc<lspi_lsp::GenericLspClient>, McpError> {
        let now = Instant::now();

        let restart_old = {
            let mut guard = self.state.generic.lock().await;
            if let Some(entry) = guard.get_mut(&server.id) {
                if should_restart(now, entry.started_at, server.restart_interval_minutes) {
                    guard.remove(&server.id)
                } else {
                    entry.last_used = now;
                    return Ok(entry.client.clone());
                }
            } else {
                None
            }
        };

        if let Some(old) = restart_old {
            match shutdown_generic_managed(old).await {
                Ok(()) => {}
                Err(mut old) => {
                    old.last_used = now;
                    let client = old.client.clone();
                    let mut guard = self.state.generic.lock().await;
                    guard.insert(server.id.clone(), old);
                    return Ok(client);
                }
            }
        }

        let normalized_kind = server.kind.trim().to_ascii_lowercase().replace('-', "_");
        let command = match server.command.as_deref().filter(|c| !c.trim().is_empty()) {
            Some(c) => c.to_string(),
            None if normalized_kind == "basedpyright" => lspi_lsp::resolve_basedpyright_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            None => lspi_lsp::resolve_pyright_command()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        };

        if let Err(err) = lspi_lsp::preflight_pyright(&command).await {
            return Err(McpError::invalid_params(
                format!("pyright preflight failed for command={command}: {err:#}"),
                None,
            ));
        }

        let args = if server.args.is_empty() {
            vec!["--stdio".to_string()]
        } else {
            server.args.clone()
        };

        let initialize_timeout = server
            .initialize_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(20));
        let request_timeout = server
            .request_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));

        let mut overrides_ms = pyright_default_request_timeout_overrides_ms();
        overrides_ms.extend(server.request_timeout_overrides_ms.clone());
        let request_timeout_overrides = request_timeout_overrides_to_durations(&overrides_ms);

        let warmup_delay = server
            .warmup_timeout_ms
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_millis(0));

        let language_id = server
            .language_id
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "python".to_string());

        let adapter = server
            .adapter
            .as_deref()
            .and_then(lspi_lsp::adapter_from_name)
            .or_else(|| lspi_lsp::adapter_from_command(&command))
            .unwrap_or_default();

        let client = lspi_lsp::GenericLspClient::start(lspi_lsp::GenericLspClientOptions {
            command,
            args,
            cwd: server.cwd.clone(),
            env: server.env.clone(),
            workspace_folders: server.workspace_folders.clone(),
            adapter,
            initialize_timeout,
            request_timeout,
            request_timeout_overrides,
            language_id,
            warmup_delay,
            workspace_configuration: server.workspace_configuration.clone(),
            initialize_options: server.initialize_options.clone(),
            client_capabilities: server.client_capabilities.clone(),
        })
        .await
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let arc = Arc::new(client);
        let managed = ManagedClient::new(arc.clone());

        let inserted = {
            let mut guard = self.state.generic.lock().await;
            if let Some(existing) = guard.get_mut(&server.id) {
                existing.last_used = now;
                Some(existing.client.clone())
            } else {
                guard.insert(server.id.clone(), managed);
                None
            }
        };

        if let Some(existing) = inserted {
            let _ = shutdown_generic_arc(arc).await;
            return Ok(existing);
        }

        Ok(arc)
    }
}

pub(crate) fn is_rust_analyzer_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "rust_analyzer" || normalized == "rust"
}

pub(crate) fn is_omnisharp_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "omnisharp" || normalized == "csharp"
}

pub(crate) fn is_generic_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "generic" || normalized == "lsp"
}

pub(crate) fn is_pyright_kind(kind: &str) -> bool {
    let normalized = kind.trim().to_ascii_lowercase().replace('-', "_");
    normalized == "pyright" || normalized == "basedpyright"
}

fn guess_language_id_from_extensions(extensions: &[String]) -> String {
    let Some(first) = extensions.first() else {
        return "plaintext".to_string();
    };

    let ext = first.trim().trim_start_matches('.').to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "cs" => "csharp",
        "ts" => "typescript",
        "tsx" => "typescriptreact",
        "js" => "javascript",
        "jsx" => "javascriptreact",
        "py" => "python",
        "go" => "go",
        "c" => "c",
        "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" => "cpp",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "json" => "json",
        "toml" => "toml",
        "yaml" | "yml" => "yaml",
        _ => "plaintext",
    }
    .to_string()
}

fn pyright_default_request_timeout_overrides_ms() -> std::collections::HashMap<String, u64> {
    [
        ("textDocument/definition", 45_000),
        ("textDocument/references", 60_000),
        ("textDocument/rename", 60_000),
        ("textDocument/documentSymbol", 45_000),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

fn request_timeout_overrides_to_durations(
    overrides_ms: &std::collections::HashMap<String, u64>,
) -> std::collections::HashMap<String, Duration> {
    overrides_ms
        .iter()
        .filter_map(|(k, v)| {
            let key = k.trim();
            if key.is_empty() || *v == 0 {
                return None;
            }
            Some((key.to_string(), Duration::from_millis(*v)))
        })
        .collect()
}

fn should_restart(
    now: Instant,
    started_at: Instant,
    restart_interval_minutes: Option<u64>,
) -> bool {
    let Some(minutes) = restart_interval_minutes.filter(|m| *m > 0) else {
        return false;
    };
    now.duration_since(started_at) >= Duration::from_secs(minutes.saturating_mul(60))
}

async fn shutdown_rust_analyzer_arc(
    mut arc: Arc<lspi_lsp::RustAnalyzerClient>,
) -> std::result::Result<(), Arc<lspi_lsp::RustAnalyzerClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_omnisharp_arc(
    mut arc: Arc<lspi_lsp::OmniSharpClient>,
) -> std::result::Result<(), Arc<lspi_lsp::OmniSharpClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_generic_arc(
    mut arc: Arc<lspi_lsp::GenericLspClient>,
) -> std::result::Result<(), Arc<lspi_lsp::GenericLspClient>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Arc::strong_count(&arc) == 1 {
            match Arc::try_unwrap(arc) {
                Ok(client) => {
                    let _ = client.shutdown().await;
                    return Ok(());
                }
                Err(a) => arc = a,
            }
        }

        if Instant::now() >= deadline {
            return Err(arc);
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) async fn shutdown_rust_analyzer_managed(
    entry: ManagedClient<lspi_lsp::RustAnalyzerClient>,
) -> std::result::Result<(), ManagedClient<lspi_lsp::RustAnalyzerClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_rust_analyzer_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
}

pub(crate) async fn shutdown_omnisharp_managed(
    entry: ManagedClient<lspi_lsp::OmniSharpClient>,
) -> std::result::Result<(), ManagedClient<lspi_lsp::OmniSharpClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_omnisharp_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
}

pub(crate) async fn shutdown_generic_managed(
    entry: ManagedClient<lspi_lsp::GenericLspClient>,
) -> std::result::Result<(), ManagedClient<lspi_lsp::GenericLspClient>> {
    let ManagedClient {
        client,
        started_at,
        last_used,
    } = entry;

    match shutdown_generic_arc(client).await {
        Ok(()) => Ok(()),
        Err(client) => Err(ManagedClient {
            client,
            started_at,
            last_used,
        }),
    }
}
