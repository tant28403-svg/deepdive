use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// A point-in-time view of the files under a root.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub root: String,
    pub files: BTreeMap<String, FileMeta>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileMeta {
    pub sha256: String,
    pub size: u64,
}

/// Added/removed/changed paths between two snapshots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub created: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub bytes_added: u64,
    pub bytes_removed: u64,
}

impl SnapshotDiff {
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.created.is_empty() && self.modified.is_empty() && self.deleted.is_empty()
    }
}

pub fn capture(root: &Path) -> Snapshot {
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;

    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let (sha256, size) = match std::fs::read(path) {
            Ok(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                (format!("{:x}", hasher.finalize()), bytes.len() as u64)
            }
            Err(_) => (String::new(), 0),
        };
        files.insert(rel, FileMeta { sha256, size });
    }

    Snapshot {
        root: root.to_string_lossy().to_string(),
        files,
    }
}

pub fn diff(before: &Snapshot, after: &Snapshot) -> SnapshotDiff {
    let mut out = SnapshotDiff::default();
    for (path, meta) in &after.files {
        match before.files.get(path) {
            None => {
                out.created.push(path.clone());
                out.bytes_added += meta.size;
            }
            Some(prev) if prev.sha256 != meta.sha256 => {
                out.modified.push(path.clone());
                out.bytes_added += meta.size.saturating_sub(prev.size);
                out.bytes_removed += prev.size.saturating_sub(meta.size);
            }
            _ => {}
        }
    }
    for (path, meta) in &before.files {
        if !after.files.contains_key(path) {
            out.deleted.push(path.clone());
            out.bytes_removed += meta.size;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_created_modified_and_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), "keep").unwrap();
        std::fs::write(dir.path().join("change.txt"), "one").unwrap();
        std::fs::write(dir.path().join("gone.txt"), "gone").unwrap();

        let before = capture(dir.path());

        std::fs::write(dir.path().join("change.txt"), "two").unwrap();
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();
        std::fs::write(dir.path().join("new.txt"), "new").unwrap();

        let after = capture(dir.path());
        let diff = diff(&before, &after);

        assert_eq!(diff.created, vec!["new.txt"]);
        assert_eq!(diff.modified, vec!["change.txt"]);
        assert_eq!(diff.deleted, vec!["gone.txt"]);
        assert!(!diff.is_empty());
    }

    #[test]
    fn identical_snapshots_are_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        let before = capture(dir.path());
        let after = capture(dir.path());
        assert!(diff(&before, &after).is_empty());
    }
}
