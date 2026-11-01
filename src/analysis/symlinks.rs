use crate::types::{Finding, Location, Severity};
use std::fs;
use std::path::{Path, PathBuf};

fn finding(
    path: &Path,
    rule: &str,
    severity: Severity,
    message: String,
    snippet: Option<String>,
) -> Finding {
    Finding {
        id: format!("{}-{}", rule, path.display()),
        severity,
        confidence: 0.9,
        rule: rule.to_string(),
        category: "filesystem".to_string(),
        location: Location {
            path: path.display().to_string(),
            line: None,
            column: None,
        },
        message,
        snippet,
        tags: vec!["symlink".to_string()],
    }
}

/// Walk a scan root and report symlinks that escape it, are broken, or loop.
pub fn scan_root(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let canonical_root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(false)
        .follow_links(false)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(path) else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let target = match fs::read_link(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let target_display = target.display().to_string();

        if target.is_absolute() {
            let resolved = fs::canonicalize(path);
            let inside = resolved
                .as_ref()
                .map(|r| r.starts_with(&canonical_root))
                .unwrap_or(false);
            if !inside {
                out.push(finding(
                    path,
                    "symlink.absolute-escape",
                    Severity::High,
                    format!(
                        "Symlink points to an absolute path outside the scan root: {}",
                        target_display
                    ),
                    Some(target_display),
                ));
            }
            continue;
        }

        if !is_safe_relative(&target) {
            out.push(finding(
                path,
                "symlink.path-escape",
                Severity::High,
                format!(
                    "Symlink target escapes the scan root via relative path: {}",
                    target_display
                ),
                Some(target_display),
            ));
            continue;
        }

        // Broken link: target does not resolve.
        if fs::metadata(path).is_err() {
            out.push(finding(
                path,
                "symlink.broken",
                Severity::Low,
                format!("Broken symlink (target missing): {}", target_display),
                Some(target_display),
            ));
        }
    }
    out
}

fn is_safe_relative(target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: i32 = 0;
    for component in target.components() {
        match component {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

/// Resolve the final target of a symlink chain without following it indefinitely.
#[allow(dead_code)]
pub fn resolve_chain(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    for _ in 0..16 {
        let meta = fs::symlink_metadata(&current).ok()?;
        if !meta.file_type().is_symlink() {
            return Some(current);
        }
        let target = fs::read_link(&current).ok()?;
        current = if target.is_absolute() {
            target
        } else {
            current.parent().unwrap_or(Path::new(".")).join(target)
        };
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_targets_are_bounded() {
        assert!(is_safe_relative(Path::new("sub/../file")));
        assert!(is_safe_relative(Path::new("sub/file")));
        assert!(!is_safe_relative(Path::new("../outside")));
        assert!(!is_safe_relative(Path::new("sub/../../outside")));
        assert!(!is_safe_relative(Path::new("/etc/passwd")));
    }

    #[cfg(unix)]
    #[test]
    fn flags_escaping_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        fs::create_dir(&root).unwrap();
        let outside = dir.path().join("outside.txt");
        fs::write(&outside, b"secret").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink("../outside.txt", root.join("relative-escape")).unwrap();
        let findings = scan_root(&root);
        assert!(findings.iter().any(|f| f.rule == "symlink.absolute-escape"));
        assert!(findings.iter().any(|f| f.rule == "symlink.path-escape"));
    }
}
