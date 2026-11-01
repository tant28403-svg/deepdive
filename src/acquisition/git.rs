use crate::acquisition::url::RepoUrl;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn safe_clone(
    repo: &RepoUrl,
    dest: &Path,
    branch: Option<&str>,
    submodules: bool,
) -> Result<PathBuf> {
    let branch = branch.or(repo.branch.as_deref());
    let clone_url = repo.clone_url();

    // Ensure dest parent exists.
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("create dest parent")?;
    }

    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--no-checkout")
        .arg("--filter=blob:none")
        .arg(&clone_url)
        .arg(dest);

    // Disable hooks & filters.
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd.env("GIT_LFS_SKIP_SMUDGE", "1");

    let out = cmd.output().context("run git clone")?;
    if !out.status.success() {
        anyhow::bail!("git clone failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    // Disable hooks in the cloned repo.
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    run_git(dest, &["config", "core.hooksPath", null_device])?;
    run_git(dest, &["config", "filter.lfs.skipSmudge", "true"])?;

    // Checkout.
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut co = Command::new("git");
    co.current_dir(dest)
        .arg("-c")
        .arg(format!("core.hooksPath={}", null_device))
        .arg("checkout");
    if let Some(b) = branch {
        co.arg(b);
    }
    let out = co.output().context("run git checkout")?;
    if !out.status.success() {
        // Try default branch.
        let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let out2 = Command::new("git")
            .current_dir(dest)
            .args(["-c", &format!("core.hooksPath={}", null_device), "checkout"])
            .output()
            .context("run git checkout default")?;
        if !out2.status.success() {
            anyhow::bail!(
                "git checkout failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // Submodules only when explicitly requested.
    if submodules {
        run_git(dest, &["submodule", "update", "--init", "--recursive"])?;
    }

    // Subdir handling: if repo.subdir set, adjust dest to subdir.
    if let Some(sub) = &repo.subdir {
        let sub_path = dest.join(sub);
        if sub_path.exists() {
            return Ok(sub_path);
        }
    }
    Ok(dest.to_path_buf())
}

fn run_git(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .context("run git")?;
    if !out.status.success() {
        anyhow::bail!("{}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}
