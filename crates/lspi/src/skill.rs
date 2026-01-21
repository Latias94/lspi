use std::fs;
use std::path::Path;

use anyhow::Context;

const SKILL_MD: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/skills/lspi/SKILL.md"));
const SKILL_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/skills/lspi/SKILL.toml"
));

pub(crate) fn install_skill(dest_dir: &Path, force: bool) -> anyhow::Result<()> {
    if dest_dir.exists() && !force {
        anyhow::bail!(
            "destination already exists: {} (use --force to overwrite)",
            dest_dir.display()
        );
    }

    fs::create_dir_all(dest_dir)
        .with_context(|| format!("failed to create skill dir: {}", dest_dir.display()))?;

    let md_path = dest_dir.join("SKILL.md");
    fs::write(&md_path, SKILL_MD.as_bytes())
        .with_context(|| format!("failed to write: {}", md_path.display()))?;

    let toml_path = dest_dir.join("SKILL.toml");
    fs::write(&toml_path, SKILL_TOML.as_bytes())
        .with_context(|| format!("failed to write: {}", toml_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn embedded_skill_matches_repo_skill_copy() -> anyhow::Result<()> {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let repo_md = fs::read_to_string(repo_root.join(".codex/skills/lspi/SKILL.md"))?;
        let repo_toml = fs::read_to_string(repo_root.join(".codex/skills/lspi/SKILL.toml"))?;

        assert_eq!(repo_md, SKILL_MD);
        assert_eq!(repo_toml, SKILL_TOML);
        Ok(())
    }

    #[test]
    fn install_creates_files() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let dest = tmp.path().join("lspi-skill");

        install_skill(&dest, false)?;
        assert!(dest.join("SKILL.md").is_file());
        assert!(dest.join("SKILL.toml").is_file());

        Ok(())
    }

    #[test]
    fn install_refuses_overwrite_without_force() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let dest = tmp.path().join("lspi-skill");

        install_skill(&dest, false)?;
        let err = install_skill(&dest, false).unwrap_err();
        assert!(err.to_string().contains("destination already exists"));

        Ok(())
    }
}
