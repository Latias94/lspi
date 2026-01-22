use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

pub(crate) enum RoutedClient {
    Rust {
        server_id: String,
        client: Arc<lspi_lsp::RustAnalyzerClient>,
    },
    OmniSharp {
        server_id: String,
        client: Arc<lspi_lsp::OmniSharpClient>,
    },
    Generic {
        server_id: String,
        client: Arc<lspi_lsp::GenericLspClient>,
    },
}

impl RoutedClient {
    pub(crate) fn server_id(&self) -> &str {
        match self {
            RoutedClient::Rust { server_id, .. } => server_id,
            RoutedClient::OmniSharp { server_id, .. } => server_id,
            RoutedClient::Generic { server_id, .. } => server_id,
        }
    }

    pub(crate) async fn document_symbols(
        &self,
        file_path: &Path,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedSymbol>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
            RoutedClient::Generic { client, .. } => {
                client.document_symbols(file_path, max_results).await
            }
        }
    }

    pub(crate) async fn workspace_symbols(
        &self,
        query: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::WorkspaceSymbolMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => client.workspace_symbols(query, max_results).await,
            RoutedClient::OmniSharp { client, .. } => {
                client.workspace_symbols(query, max_results).await
            }
            RoutedClient::Generic { client, .. } => {
                client.workspace_symbols(query, max_results).await
            }
        }
    }

    pub(crate) async fn find_definition_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::DefinitionMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .find_definition_by_name(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
        }
    }

    pub(crate) async fn definition_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_definitions: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .definition_at(file_path, position, max_definitions)
                    .await
            }
        }
    }

    pub(crate) async fn find_references_by_name(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        include_declaration: bool,
        max_symbols: usize,
        max_references: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ReferenceMatch>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .find_references_by_name(
                        file_path,
                        symbol_name,
                        symbol_kind,
                        include_declaration,
                        max_symbols,
                        max_references,
                    )
                    .await
            }
        }
    }

    pub(crate) async fn references_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        include_declaration: bool,
        max_references: usize,
    ) -> anyhow::Result<(Vec<lspi_lsp::ResolvedLocation>, bool)> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .references_at(file_path, position, include_declaration, max_references)
                    .await
            }
        }
    }

    pub(crate) async fn hover_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
    ) -> anyhow::Result<Value> {
        match self {
            RoutedClient::Rust { client, .. } => client.hover_at(file_path, position).await,
            RoutedClient::OmniSharp { client, .. } => client.hover_at(file_path, position).await,
            RoutedClient::Generic { client, .. } => client.hover_at(file_path, position).await,
        }
    }

    pub(crate) async fn implementation_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .implementation_at(file_path, position, max_results)
                    .await
            }
        }
    }

    pub(crate) async fn type_definition_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::ResolvedLocation>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .type_definition_at(file_path, position, max_results)
                    .await
            }
        }
    }

    pub(crate) async fn incoming_calls_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<lspi_lsp::CallHierarchyIncomingResult> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .incoming_calls_at(file_path, position, max_results)
                    .await
            }
        }
    }

    pub(crate) async fn outgoing_calls_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        max_results: usize,
    ) -> anyhow::Result<lspi_lsp::CallHierarchyOutgoingResult> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .outgoing_calls_at(file_path, position, max_results)
                    .await
            }
        }
    }

    pub(crate) async fn get_diagnostics(
        &self,
        file_path: &Path,
        max_wait: Duration,
    ) -> anyhow::Result<Vec<lspi_lsp::LspDiagnostic>> {
        match self {
            RoutedClient::Rust { client, .. } => client.get_diagnostics(file_path, max_wait).await,
            RoutedClient::OmniSharp { client, .. } => {
                client.get_diagnostics(file_path, max_wait).await
            }
            RoutedClient::Generic { client, .. } => {
                client.get_diagnostics(file_path, max_wait).await
            }
        }
    }

    pub(crate) async fn list_symbol_candidates(
        &self,
        file_path: &Path,
        symbol_name: &str,
        symbol_kind: Option<u32>,
        max_symbols: usize,
    ) -> anyhow::Result<Vec<lspi_lsp::RenameCandidate>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .list_symbol_candidates(file_path, symbol_name, symbol_kind, max_symbols)
                    .await
            }
        }
    }

    pub(crate) async fn rename_at(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        new_name: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
            RoutedClient::Generic { client, .. } => {
                client.rename_at(file_path, position, new_name).await
            }
        }
    }

    pub(crate) async fn rename_at_prepared(
        &self,
        file_path: &Path,
        position: lspi_lsp::LspPosition,
        new_name: &str,
    ) -> anyhow::Result<std::collections::HashMap<String, Vec<lspi_lsp::LspTextEdit>>> {
        match self {
            RoutedClient::Rust { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
            RoutedClient::OmniSharp { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
            RoutedClient::Generic { client, .. } => {
                client
                    .rename_at_prepared(file_path, position, new_name)
                    .await
            }
        }
    }
}
