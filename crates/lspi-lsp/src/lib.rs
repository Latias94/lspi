mod adapter;
mod generic;
mod lsp;
mod omnisharp;
mod pyright;
mod rust_analyzer;
mod symbol;

pub use adapter::{LspAdapter, WorkspaceFolder, adapter_from_command, adapter_from_name};
pub use lsp::{LspDiagnostic, LspPosition, LspRange, LspTextEdit};

pub use generic::{GenericLspClient, GenericLspClientOptions};
pub use omnisharp::{
    OmniSharpClient, OmniSharpClientOptions, preflight_omnisharp, resolve_omnisharp_command,
};
pub use pyright::{preflight_pyright, resolve_basedpyright_command, resolve_pyright_command};
pub use symbol::parse_symbol_kind;
pub use symbol::{
    CallHierarchyIncomingResult, CallHierarchyItemResolved, CallHierarchyOutgoingResult,
    DefinitionMatch, ReferenceMatch, RenameCandidate, ResolvedLocation, ResolvedSymbol,
    WorkspaceSymbolMatch,
};

pub use rust_analyzer::{
    RustAnalyzerClient, RustAnalyzerClientOptions, preflight_rust_analyzer,
    resolve_rust_analyzer_command,
};
