use crate::analysis::scan;
use crate::types::{Finding, Location, Severity};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};

/// Maximum nesting depth for containers (plan §4).
const MAX_DEPTH: usize = 5;
/// Maximum total uncompressed bytes examined from one top-level archive.
const MAX_TOTAL_BYTES: u64 = 100 * 1024 * 1024;
/// Maximum size of a single extracted entry.
const MAX_ENTRY_BYTES: u64 = 50 * 1024 * 1024;
/// Entries larger than this with a compression ratio above `MAX_RATIO` look like bombs.
const BOMB_MIN_SIZE: u64 = 10 * 1024 * 1024;
const MAX_RATIO: u64 = 100;

#[derive(Debug, Clone, Copy)]
enum Container {
    Zip,
    Tar,
    Gzip,
}

struct Budget {
    remaining: u64,
    seen: HashSet<[u8; 32]>,
    limit_hit: bool,
}

impl Budget {
    fn new() -> Self {
        Self {
            remaining: MAX_TOTAL_BYTES,
            seen: HashSet::new(),
            limit_hit: false,
        }
    }

    fn take(&mut self, bytes: u64) -> bool {
        if bytes > self.remaining {
            self.limit_hit = true;
            return false;
        }
        self.remaining -= bytes;
        true
    }

    fn is_new(&mut self, data: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(data).into();
        self.seen.insert(digest)
    }
}

fn push(
    out: &mut Vec<Finding>,
    path: &Path,
    rule: &str,
    severity: Severity,
    message: String,
    snippet: Option<String>,
    tags: &[&str],
) {
    out.push(Finding {
        id: format!("{}-{}", rule, path.display()),
        severity,
        confidence: 0.85,
        rule: rule.to_string(),
        category: "archive".to_string(),
        location: Location {
            path: path.display().to_string(),
            line: None,
            column: None,
        },
        message,
        snippet,
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
}

fn detect_container(bytes: &[u8]) -> Option<Container> {
    if bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07)
    {
        return Some(Container::Zip);
    }
    if bytes.len() >= 2 && bytes[0] == 0x1F && bytes[1] == 0x8B {
        return Some(Container::Gzip);
    }
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return Some(Container::Tar);
    }
    None
}

/// Return true when a relative entry name stays inside the extraction root.
fn is_safe_relative(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let normalized = name.replace('\\', "/");
    let path = Path::new(&normalized);
    if path.is_absolute() {
        return false;
    }
    path.components().all(|c| {
        !matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

fn is_office_archive(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase()
            .as_str(),
        "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "odt" | "ods" | "odp"
    )
}

/// Scan an archive (zip/tar/gzip) recursively, including nested containers.
pub fn scan(path: &Path, bytes: &[u8]) -> Vec<Finding> {
    if is_office_archive(path) {
        // Office containers are analysed by the document module, not carved here.
        return Vec::new();
    }
    let mut budget = Budget::new();
    let mut out = Vec::new();
    if detect_container(bytes).is_none() {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if matches!(
            ext.as_str(),
            "7z" | "rar" | "xz" | "bz2" | "cab" | "iso" | "deb" | "rpm"
        ) {
            push(
                &mut out,
                path,
                "archive.unsupported-format",
                Severity::Low,
                format!(
                    "{} archive detected but not extracted (only zip/tar/gzip are supported)",
                    ext.to_uppercase()
                ),
                None,
                &["archive", "unsupported"],
            );
        }
        return out;
    }
    scan_container(path, bytes, 0, &mut budget, &mut out);
    if budget.limit_hit {
        push(
            &mut out,
            path,
            "archive.size-limit",
            Severity::Medium,
            format!(
                "Archive exceeds the {} MB uncompressed scan budget; remaining entries were skipped",
                MAX_TOTAL_BYTES / (1024 * 1024)
            ),
            None,
            &["archive", "limit"],
        );
    }
    out
}

fn scan_container(
    path: &Path,
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
    out: &mut Vec<Finding>,
) {
    if depth >= MAX_DEPTH {
        push(
            out,
            path,
            "archive.depth-exceeded",
            Severity::Medium,
            format!(
                "Archive nesting exceeds {} levels; deeper entries were not scanned",
                MAX_DEPTH
            ),
            None,
            &["archive", "depth"],
        );
        return;
    }
    match detect_container(bytes) {
        Some(Container::Zip) => scan_zip(path, bytes, depth, budget, out),
        Some(Container::Tar) => scan_tar(path, bytes, depth, budget, out),
        Some(Container::Gzip) => scan_gzip(path, bytes, depth, budget, out),
        None => {}
    }
}

fn scan_zip(path: &Path, bytes: &[u8], depth: usize, budget: &mut Budget, out: &mut Vec<Finding>) {
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        push(
            out,
            path,
            "archive.unreadable",
            Severity::Low,
            "Archive could not be parsed as a zip file".to_string(),
            None,
            &["archive", "zip"],
        );
        return;
    };
    for i in 0..zip.len() {
        let Ok(mut entry) = zip.by_index(i) else {
            continue;
        };
        let name = entry.name().to_string();
        if name.ends_with('/') || entry.is_dir() {
            continue;
        }
        if !is_safe_relative(&name) {
            push(
                out,
                path,
                "archive.path-traversal",
                Severity::Critical,
                format!("Zip entry escapes the extraction root: {}", name),
                Some(name.clone()),
                &["archive", "zip", "traversal"],
            );
        }

        // Unix symlink entries store the target path as their data.
        let mode = entry.unix_mode().unwrap_or(0);
        if mode & 0o170000 == 0o120000 {
            let mut target = String::new();
            let _ = entry.read_to_string(&mut target);
            if !is_safe_relative(&target) || Path::new(&target).is_absolute() {
                push(
                    out,
                    path,
                    "archive.symlink-escape",
                    Severity::High,
                    format!("Zip symlink '{}' points outside the archive root", name),
                    Some(target),
                    &["archive", "zip", "symlink"],
                );
            }
            continue;
        }

        let size = entry.size();
        let compressed = entry.compressed_size().max(1);
        if size > BOMB_MIN_SIZE && size / compressed > MAX_RATIO {
            push(
                out,
                path,
                "archive.zip-bomb",
                Severity::High,
                format!(
                    "Zip entry '{}' expands {}x ({} bytes) — possible zip bomb",
                    name,
                    size / compressed,
                    size
                ),
                None,
                &["archive", "zip", "bomb"],
            );
        }
        if size > MAX_ENTRY_BYTES {
            push(
                out,
                path,
                "archive.entry-too-large",
                Severity::Medium,
                format!("Zip entry '{}' is {} bytes; skipped", name, size),
                None,
                &["archive", "zip", "limit"],
            );
            continue;
        }
        if !budget.take(size) {
            continue;
        }
        let mut data = Vec::with_capacity(size as usize);
        if entry.read_to_end(&mut data).is_err() {
            continue;
        }
        process_entry(path, &name, data, depth, budget, out);
    }
}

fn scan_tar(path: &Path, bytes: &[u8], depth: usize, budget: &mut Budget, out: &mut Vec<Finding>) {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let Ok(entries) = archive.entries() else {
        push(
            out,
            path,
            "archive.unreadable",
            Severity::Low,
            "Archive could not be parsed as a tar file".to_string(),
            None,
            &["archive", "tar"],
        );
        return;
    };
    for entry in entries.flatten() {
        let header = entry.header();
        let entry_type = header.entry_type();
        let size = header.size().unwrap_or(0);
        let Ok(entry_path) = entry.path() else {
            continue;
        };
        let name = entry_path.to_string_lossy().replace('\\', "/");

        if name.is_empty() {
            continue;
        }
        if !is_safe_relative(&name) {
            push(
                out,
                path,
                "archive.path-traversal",
                Severity::Critical,
                format!("Tar entry escapes the extraction root: {}", name),
                Some(name.clone()),
                &["archive", "tar", "traversal"],
            );
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            let target = entry
                .link_name()
                .ok()
                .flatten()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if !is_safe_relative(&target) || Path::new(&target).is_absolute() {
                push(
                    out,
                    path,
                    "archive.symlink-escape",
                    Severity::High,
                    format!("Tar link '{}' points outside the archive root", name),
                    Some(target),
                    &["archive", "tar", "symlink"],
                );
            }
            continue;
        }
        if !entry_type.is_file() {
            continue;
        }
        if size > MAX_ENTRY_BYTES {
            push(
                out,
                path,
                "archive.entry-too-large",
                Severity::Medium,
                format!("Tar entry '{}' is {} bytes; skipped", name, size),
                None,
                &["archive", "tar", "limit"],
            );
            continue;
        }
        if !budget.take(size) {
            continue;
        }
        let mut data = Vec::with_capacity(size as usize);
        if entry.take(MAX_ENTRY_BYTES).read_to_end(&mut data).is_err() {
            continue;
        }
        process_entry(path, &name, data, depth, budget, out);
    }
}

fn scan_gzip(path: &Path, bytes: &[u8], depth: usize, budget: &mut Budget, out: &mut Vec<Finding>) {
    let mut decoder = flate2::read::GzDecoder::new(Cursor::new(bytes)).take(MAX_ENTRY_BYTES);
    let mut data = Vec::new();
    if decoder.read_to_end(&mut data).is_err() {
        push(
            out,
            path,
            "archive.unreadable",
            Severity::Low,
            "Gzip stream could not be decompressed".to_string(),
            None,
            &["archive", "gzip"],
        );
        return;
    }
    if !budget.take(data.len() as u64) {
        return;
    }
    // A .tar.gz usually decompresses to a tar stream.
    if detect_container(&data).is_some() {
        scan_container(path, &data, depth + 1, budget, out);
        return;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "decompressed".to_string());
    let name = name.strip_suffix(".gz").unwrap_or(&name).to_string();
    process_entry(path, &name, data, depth, budget, out);
}

fn process_entry(
    parent: &Path,
    name: &str,
    data: Vec<u8>,
    depth: usize,
    budget: &mut Budget,
    out: &mut Vec<Finding>,
) {
    if !budget.is_new(&data) {
        return;
    }
    let entry_path = PathBuf::from(format!("{}!{}", parent.display(), name));

    if detect_container(&data).is_some() {
        push(
            out,
            &entry_path,
            "archive.nested",
            Severity::Low,
            format!(
                "Nested archive at depth {} ({} bytes) — contents were scanned",
                depth + 1,
                data.len()
            ),
            Some(name.to_string()),
            &["archive", "nested"],
        );
    }

    // Reuse the normal byte scanner, then recurse into containers ourselves.
    out.extend(scan::scan_bytes(&entry_path, &data));
    if detect_container(&data).is_some() {
        scan_container(&entry_path, &data, depth + 1, budget, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default();
            for (name, data) in entries {
                writer.start_file(*name, options).unwrap();
                writer.write_all(data).unwrap();
            }
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn scans_nested_archive_contents() {
        let inner = make_zip(&[("payload.js", b"eval(atob('ZXZhbA=='));")]);
        let outer = make_zip(&[("bundle.zip", inner.as_slice())]);
        let findings = scan(Path::new("outer.zip"), &outer);
        assert!(findings.iter().any(|f| f.rule == "archive.nested"));
        assert!(findings
            .iter()
            .any(|f| f.rule.contains("dangerous") || f.rule.contains("obfuscation")));
    }

    #[test]
    fn detects_path_traversal() {
        let bytes = make_zip(&[("../escape.sh", b"echo hi")]);
        let findings = scan(Path::new("evil.zip"), &bytes);
        assert!(findings.iter().any(|f| f.rule == "archive.path-traversal"));
    }

    #[test]
    fn skips_office_archives() {
        let bytes = make_zip(&[("word/document.xml", b"<xml/>")]);
        let findings = scan(Path::new("report.docx"), &bytes);
        assert!(findings.is_empty());
    }
}
