use anyhow::{Context, Result};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Extract a zip archive safely into `dest`, rejecting path traversal.
pub fn extract_zip(archive: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive).context("open archive")?;
    let mut zip = zip::ZipArchive::new(file).context("read zip")?;
    fs::create_dir_all(dest).context("create dest")?;
    let dest_canon = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).context("read entry")?;
        let name = entry.name().to_string();
        // Reject absolute paths and traversal.
        let entry_path = Path::new(&name);
        if entry_path.is_absolute() {
            anyhow::bail!("absolute path in archive: {}", name);
        }
        let mut safe = PathBuf::new();
        for comp in entry_path.components() {
            match comp {
                Component::Normal(c) => safe.push(c),
                Component::CurDir => {}
                _ => anyhow::bail!("path traversal in archive: {}", name),
            }
        }
        let out_path = dest.join(&safe);
        // Ensure within dest.
        if let Ok(canon) = out_path.canonicalize() {
            if !canon.starts_with(&dest_canon) {
                anyhow::bail!("path escapes dest: {}", name);
            }
        }
        if entry.is_dir() {
            fs::create_dir_all(&out_path).context("create dir")?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).context("create parent")?;
            }
            let mut outfile = fs::File::create(&out_path).context("create file")?;
            std::io::copy(&mut entry, &mut outfile).context("extract file")?;
        }
    }
    Ok(())
}
