use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Walk a root directory, respecting .gitignore, returning file paths.
pub fn walk_files(root: &Path, max_size: u64) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false) // scan hidden files too
        .git_ignore(true)
        .git_global(false)
        .filter_entry(|e| {
            // Skip .git directory entirely - it contains 500+ internal files
            // that are not user code and produce false positives
            let name = e.file_name().to_string_lossy();
            name != ".git"
        })
        .build();
    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(meta) = path.metadata() {
            if meta.len() > max_size * 1024 * 1024 {
                continue;
            }
        }
        out.push(path.to_path_buf());
    }
    out
}
