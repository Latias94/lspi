use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WorkspaceEditPreviewFile {
    pub(crate) uri: String,
    pub(crate) file_path: Option<String>,
    pub(crate) before_sha256: Option<String>,
    pub(crate) edits: Vec<lspi_lsp::LspTextEdit>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct WorkspaceEditPreview {
    pub(crate) files: Vec<WorkspaceEditPreviewFile>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApplyWorkspaceEditResult {
    pub(crate) files_modified: Vec<String>,
    pub(crate) backup_files: Vec<String>,
}

pub(crate) async fn workspace_edit_preview(
    changes: &HashMap<String, Vec<lspi_lsp::LspTextEdit>>,
) -> anyhow::Result<WorkspaceEditPreview> {
    let mut files = Vec::new();
    for (uri, edits) in changes {
        let (file_path, before_sha256) = match uri_to_path_maybe(uri).await {
            Ok(Some(path)) => {
                let bytes = tokio::fs::read(&path).await.ok();
                let hash = bytes.as_deref().map(lspi_core::hashing::sha256_hex);
                (Some(path.to_string_lossy().to_string()), hash)
            }
            Ok(None) => (None, None),
            Err(_) => (None, None),
        };

        files.push(WorkspaceEditPreviewFile {
            uri: uri.clone(),
            file_path,
            before_sha256,
            edits: edits.clone(),
        });
    }
    Ok(WorkspaceEditPreview { files })
}

async fn uri_to_path_maybe(uri: &str) -> anyhow::Result<Option<PathBuf>> {
    let url = Url::parse(uri)?;
    if url.scheme() != "file" {
        return Ok(None);
    }
    Ok(url.to_file_path().ok())
}

pub(crate) async fn apply_workspace_edit(
    workspace_root: &Path,
    changes: &HashMap<String, Vec<lspi_lsp::LspTextEdit>>,
    expected_before_sha256: Option<&HashMap<String, String>>,
    create_backups: bool,
    backup_suffix: &str,
) -> anyhow::Result<ApplyWorkspaceEditResult> {
    let root = workspace_root.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize workspace root: {}",
            workspace_root.to_string_lossy()
        )
    })?;

    struct FileState {
        path: PathBuf,
        original_bytes: Vec<u8>,
        backup_path: Option<PathBuf>,
        edits: Vec<lspi_core::text_edit::TextEdit>,
    }

    let mut files = Vec::<FileState>::new();

    for (uri, edits) in changes {
        let Some(path) = uri_to_path_maybe(uri).await? else {
            return Err(anyhow::anyhow!(
                "unsupported edit URI (only file:// supported): {uri}"
            ));
        };

        let canonical = path
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {path:?}"))?;
        if !canonical.starts_with(&root) {
            return Err(anyhow::anyhow!(
                "refusing to write outside workspace root (root={:?}, path={:?})",
                root,
                canonical
            ));
        }

        let original_bytes = tokio::fs::read(&canonical)
            .await
            .with_context(|| format!("failed to read file: {canonical:?}"))?;

        let current_hash = lspi_core::hashing::sha256_hex(&original_bytes);
        if let Some(expected) = expected_before_sha256 {
            let key = canonical.to_string_lossy().to_string();
            let Some(want) = expected.get(&key) else {
                return Err(anyhow::anyhow!(
                    "missing expected_before_sha256 entry for {key}"
                ));
            };
            if want != &current_hash {
                return Err(anyhow::anyhow!(
                    "sha256 mismatch for {} (expected={}, got={})",
                    key,
                    want,
                    current_hash
                ));
            }
        }

        let mut converted = Vec::with_capacity(edits.len());
        for e in edits {
            converted.push(lspi_core::text_edit::TextEdit {
                range: lspi_core::text_edit::Range {
                    start: lspi_core::text_edit::Position {
                        line: e.range.start.line,
                        character: e.range.start.character,
                    },
                    end: lspi_core::text_edit::Position {
                        line: e.range.end.line,
                        character: e.range.end.character,
                    },
                },
                new_text: e.new_text.clone(),
            });
        }

        files.push(FileState {
            path: canonical,
            original_bytes,
            backup_path: None,
            edits: converted,
        });
    }

    let mut files_modified = Vec::new();
    let mut backup_files = Vec::new();

    for f in &mut files {
        if create_backups {
            let backup_path = backup_path_for(&f.path, backup_suffix)?;
            tokio::fs::write(&backup_path, &f.original_bytes)
                .await
                .with_context(|| format!("failed to write backup file: {backup_path:?}"))?;
            backup_files.push(backup_path.to_string_lossy().to_string());
            f.backup_path = Some(backup_path);
        }
    }

    let apply_result: anyhow::Result<()> = async {
        for f in &files {
            let original_text =
                String::from_utf8(f.original_bytes.clone()).context("file is not valid UTF-8")?;
            let new_text = lspi_core::text_edit::apply_text_edits_utf16(&original_text, &f.edits)?;
            write_best_effort_atomic(&f.path, new_text.as_bytes()).await?;
            files_modified.push(f.path.to_string_lossy().to_string());
        }
        Ok(())
    }
    .await;

    if let Err(err) = apply_result {
        for f in &files {
            let _ = tokio::fs::write(&f.path, &f.original_bytes).await;
        }
        for f in &files {
            if let Some(backup_path) = &f.backup_path {
                let _ = tokio::fs::remove_file(backup_path).await;
            }
        }
        return Err(err);
    }

    Ok(ApplyWorkspaceEditResult {
        files_modified,
        backup_files,
    })
}

fn backup_path_for(path: &Path, backup_suffix: &str) -> anyhow::Result<PathBuf> {
    if backup_suffix.is_empty() {
        return Err(anyhow::anyhow!("backup_suffix must not be empty"));
    }
    if backup_suffix.contains('/') || backup_suffix.contains('\\') {
        return Err(anyhow::anyhow!(
            "backup_suffix must not contain path separators"
        ));
    }
    if backup_suffix.contains(':') {
        return Err(anyhow::anyhow!("backup_suffix must not contain ':'"));
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name: {path:?}"))?
        .to_string_lossy();

    Ok(path.with_file_name(format!("{file_name}{backup_suffix}")))
}

async fn write_best_effort_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {path:?}"))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no file name: {path:?}"))?
        .to_string_lossy();

    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );

    let tmp_path = parent.join(format!(".{file_name}.lspi-tmp-{nonce}"));
    tokio::fs::write(&tmp_path, bytes)
        .await
        .with_context(|| format!("failed to write temp file: {tmp_path:?}"))?;

    match tokio::fs::rename(&tmp_path, path).await {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            let _ = tokio::fs::remove_file(path).await;
            match tokio::fs::rename(&tmp_path, path).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    Err(anyhow::anyhow!(
                        "failed to replace file: {path:?} (rename_err={rename_err}, err={err})"
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;
    use url::Url;

    use super::apply_workspace_edit;

    fn file_uri(path: &Path) -> String {
        Url::from_file_path(path).unwrap().to_string()
    }

    fn expected_backup_path(path: &Path, suffix: &str) -> PathBuf {
        let file_name = path.file_name().unwrap().to_string_lossy();
        path.with_file_name(format!("{file_name}{suffix}"))
    }

    #[tokio::test]
    async fn apply_workspace_edit_happy_path_creates_backup_and_writes_file() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();
        let key = canonical.to_string_lossy().to_string();
        let original_bytes = tokio::fs::read(&canonical).await.unwrap();
        let before_sha256 = lspi_core::hashing::sha256_hex(&original_bytes);

        let mut expected = HashMap::new();
        expected.insert(key, before_sha256);

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let result = apply_workspace_edit(root, &changes, Some(&expected), true, ".bak")
            .await
            .unwrap();

        assert_eq!(result.files_modified.len(), 1);
        assert_eq!(result.backup_files.len(), 1);

        let new_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(new_text, "world\n");

        let backup_path = PathBuf::from(&result.backup_files[0]);
        let backup_text = tokio::fs::read_to_string(&backup_path).await.unwrap();
        assert_eq!(backup_text, "hello\n");
    }

    #[tokio::test]
    async fn apply_workspace_edit_rejects_sha256_mismatch_without_writing() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();
        let canonical = file_path.canonicalize().unwrap();

        let mut expected = HashMap::new();
        expected.insert(
            canonical.to_string_lossy().to_string(),
            "deadbeef".to_string(),
        );

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let err = apply_workspace_edit(root, &changes, Some(&expected), true, ".bak")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"));

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, ".bak");
        assert!(!backup_path.exists());
    }

    #[tokio::test]
    async fn apply_workspace_edit_rolls_back_and_removes_backup_on_apply_error() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 999,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 999,
                    character: 0,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let _err = apply_workspace_edit(root, &changes, None, true, ".bak")
            .await
            .unwrap_err();

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, ".bak");
        assert!(!backup_path.exists());
    }

    #[tokio::test]
    async fn apply_workspace_edit_refuses_writes_outside_workspace_root() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let outside = tempdir().unwrap();
        let file_path = outside.path().join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let err = apply_workspace_edit(root, &changes, None, true, ".bak")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside workspace root"));

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, ".bak");
        assert!(!backup_path.exists());
    }

    #[tokio::test]
    async fn apply_workspace_edit_rejects_backup_suffix_with_path_separator() {
        let root_dir = tempdir().unwrap();
        let root = root_dir.path();

        let file_path = root.join("a.rs");
        tokio::fs::write(&file_path, "hello\n").await.unwrap();

        let canonical = file_path.canonicalize().unwrap();

        let edit = lspi_lsp::LspTextEdit {
            range: lspi_lsp::LspRange {
                start: lspi_lsp::LspPosition {
                    line: 0,
                    character: 0,
                },
                end: lspi_lsp::LspPosition {
                    line: 0,
                    character: 5,
                },
            },
            new_text: "world".to_string(),
        };

        let mut changes: HashMap<String, Vec<lspi_lsp::LspTextEdit>> = HashMap::new();
        changes.insert(file_uri(&canonical), vec![edit]);

        let err = apply_workspace_edit(root, &changes, None, true, "/../evil")
            .await
            .unwrap_err();
        assert!(err.to_string().contains("backup_suffix"));

        let current_text = tokio::fs::read_to_string(&canonical).await.unwrap();
        assert_eq!(current_text, "hello\n");

        let backup_path = expected_backup_path(&canonical, "/../evil");
        assert!(!backup_path.exists());
    }
}
