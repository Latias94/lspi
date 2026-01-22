use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

pub async fn resolve_pyright_command() -> Result<String> {
    if let Ok(value) = std::env::var("LSPI_PYRIGHT_COMMAND")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    Ok("pyright-langserver".to_string())
}

pub async fn resolve_basedpyright_command() -> Result<String> {
    if let Ok(value) = std::env::var("LSPI_BASEDPYRIGHT_COMMAND")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    Ok("basedpyright-langserver".to_string())
}

pub async fn preflight_pyright(command: &str) -> Result<()> {
    for args in [
        ["--version"].as_slice(),
        ["--help"].as_slice(),
        ["-h"].as_slice(),
    ] {
        let output = Command::new(command)
            .args(args)
            .output()
            .await
            .with_context(|| format!("failed to run `{command} {}`", args.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
    }

    Err(anyhow!(
        "pyright-langserver is not available on PATH. Install Pyright (e.g. `npm i -g pyright`) and ensure `pyright-langserver` is runnable, or set LSPI_PYRIGHT_COMMAND / LSPI_BASEDPYRIGHT_COMMAND."
    ))
}
