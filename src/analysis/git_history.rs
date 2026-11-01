use crate::analysis::secrets;
use crate::analysis::source;
use crate::types::{Finding, Severity};
use std::path::Path;
use std::process::Command;

pub fn scan_git_history(repo_path: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(["log", "-p", "--all", "--no-color"])
        .output();
    let Ok(output) = output else {
        return out;
    };
    if !output.status.success() {
        return out;
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let mut current_file = String::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            current_file = rest.to_string();
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if added.starts_with("+++") {
                continue;
            }
            // Run secret + dangerous API detectors on the added line.
            let line_content = added;
            let fake_path = Path::new(&current_file);
            let mut fs = secrets::scan(fake_path, line_content);
            for f in &mut fs {
                f.message = format!("[git-history] {}", f.message);
                f.tags.push("git-history".to_string());
            }
            out.extend(fs);
            let mut fd = source::scan(fake_path, line_content);
            for f in &mut fd {
                f.message = format!("[git-history] {}", f.message);
                f.tags.push("git-history".to_string());
            }
            out.extend(fd);
        }
    }
    // Dedup by (rule, snippet).
    let mut seen = std::collections::HashSet::new();
    out.retain(|f| {
        let key = format!("{}|{}", f.rule, f.snippet.clone().unwrap_or_default());
        seen.insert(key)
    });
    // Limit noise: only keep high+ severity for history.
    out.retain(|f| f.severity >= Severity::High);
    out
}
