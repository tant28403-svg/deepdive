//! Lockfile integrity, dependency-confusion, and manifest-drift checks.
//!
//! These checks are static and offline: they reason about the metadata already
//! present in lockfiles and registry configuration instead of querying upstream
//! hashes.

use crate::types::{Finding, Location, Severity};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[allow(clippy::too_many_arguments)]
fn push(
    out: &mut Vec<Finding>,
    path: &Path,
    line: Option<usize>,
    rule: &str,
    severity: Severity,
    confidence: f32,
    message: String,
    snippet: Option<String>,
    tags: &[&str],
) {
    let path_str = path.display().to_string();
    let suffix = line.map(|l| format!("-{}", l)).unwrap_or_default();
    out.push(Finding {
        id: format!("{}-{}{}", rule, path_str, suffix),
        severity,
        confidence,
        rule: rule.to_string(),
        category: "dependencies".to_string(),
        location: Location {
            path: path_str,
            line,
            column: None,
        },
        message,
        snippet: snippet.map(|s| s.chars().take(200).collect()),
        tags: tags.iter().map(|t| t.to_string()).collect(),
    });
}

fn truncate(value: &str) -> String {
    value.trim().chars().take(160).collect()
}

fn line_of(content: &str, needle: &str) -> Option<usize> {
    content
        .lines()
        .position(|line| line.contains(needle))
        .map(|i| i + 1)
}

/// Read a file, returning an empty string when it is unreadable.
fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Scan every file in the tree that carries dependency metadata.
pub fn scan(files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut npmrc = NpmRegistryConfig::default();

    // Registry configuration applies to every manifest in the tree.
    for file in files {
        let name = file_name(file);
        if name == ".npmrc" || name == ".yarnrc" || name == ".yarnrc.yml" {
            npmrc.merge(&read(file));
        }
    }
    if !npmrc.is_empty() {
        out.extend(npmrc.findings(files));
    }

    for file in files {
        let name = file_name(file);
        let content = read(file);
        if content.is_empty() {
            continue;
        }
        match name.as_str() {
            "package-lock.json" | "npm-shrinkwrap.json" => {
                out.extend(scan_package_lock(file, &content));
            }
            "yarn.lock" => out.extend(scan_yarn_lock(file, &content)),
            "pnpm-lock.yaml" => out.extend(scan_pnpm_lock(file, &content)),
            "Cargo.lock" => out.extend(scan_cargo_lock(file, &content)),
            "requirements.txt" => out.extend(scan_requirements(file, &content)),
            "go.sum" => {}
            _ => {}
        }
    }

    // Pair manifests with their lockfiles for drift and confusion checks.
    if let Some((manifest, lock)) = find_pair(files, "package.json", "package-lock.json") {
        out.extend(scan_npm_confusion(
            &manifest,
            &lock,
            &read(&manifest),
            &read(&lock),
            &npmrc,
        ));
        out.extend(scan_npm_manifest_drift(
            &manifest,
            &lock,
            &read(&manifest),
            &read(&lock),
        ));
    }
    if let Some((manifest, sum)) = find_pair(files, "go.mod", "go.sum") {
        out.extend(scan_go_drift(
            &manifest,
            &sum,
            &read(&manifest),
            &read(&sum),
        ));
    }
    if let Some((manifest, lock)) = find_pair(files, "Pipfile", "Pipfile.lock") {
        out.extend(scan_pipfile_drift(
            &manifest,
            &lock,
            &read(&manifest),
            &read(&lock),
        ));
    }

    out
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase()
}

fn find_pair(files: &[PathBuf], manifest: &str, lock: &str) -> Option<(PathBuf, PathBuf)> {
    let manifest_path = files
        .iter()
        .find(|f| file_name(f) == manifest)?
        .to_path_buf();
    let lock_path = files.iter().find(|f| file_name(f) == lock)?;
    // Prefer a lockfile in the same directory as the manifest.
    let same_dir = files
        .iter()
        .find(|f| file_name(f) == lock && f.parent() == manifest_path.parent())
        .unwrap_or(lock_path);
    Some((manifest_path, same_dir.to_path_buf()))
}

// ---------------------------------------------------------------------------
// npm registry configuration and dependency confusion
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct NpmRegistryConfig {
    default_registry: Option<String>,
    scoped: BTreeMap<String, String>,
    always_auth: bool,
    strict_ssl: bool,
}

impl Default for NpmRegistryConfig {
    fn default() -> Self {
        Self {
            default_registry: None,
            scoped: BTreeMap::new(),
            always_auth: false,
            strict_ssl: true,
        }
    }
}

impl NpmRegistryConfig {
    fn is_empty(&self) -> bool {
        self.default_registry.is_none() && self.scoped.is_empty()
    }

    fn merge(&mut self, content: &str) {
        for line in content.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_lowercase();
            let value = value.trim().trim_matches('"').to_string();
            if key == "registry" || key == "npmregistryserver" {
                self.default_registry = Some(value);
            } else if key == "always-auth" || key == "npmalwaysauth" {
                self.always_auth = value.eq_ignore_ascii_case("true");
            } else if key == "strict-ssl" || key == "enablestrictssl" {
                self.strict_ssl = !value.eq_ignore_ascii_case("false");
            } else if let Some(scope) = key.strip_suffix(":registry") {
                if scope.starts_with('@') {
                    self.scoped.insert(scope.to_string(), value);
                }
            }
        }
    }

    fn is_private_registry(url: &str) -> bool {
        let lower = url.to_lowercase();
        !lower.is_empty()
            && !lower.contains("registry.npmjs.org")
            && !lower.contains("registry.yarnpkg.com")
    }

    fn scoped_url(&self, scope: &str) -> Option<&str> {
        self.scoped.get(scope).map(|s| s.as_str())
    }

    fn findings(&self, files: &[PathBuf]) -> Vec<Finding> {
        let mut out = Vec::new();
        let Some(path) = files
            .iter()
            .find(|f| matches!(file_name(f).as_str(), ".npmrc" | ".yarnrc" | ".yarnrc.yml"))
        else {
            return out;
        };
        for (scope, url) in &self.scoped {
            if url.to_lowercase().starts_with("http://") {
                push(
                    &mut out,
                    path,
                    None,
                    "deps.insecure-registry",
                    Severity::High,
                    0.9,
                    format!("Registry for {} uses plain HTTP: {}", scope, url),
                    Some(truncate(url)),
                    &["npm", "registry", "tls"],
                );
            }
            if Self::is_private_registry(url) && !self.always_auth {
                push(
                    &mut out,
                    path,
                    None,
                    "deps.registry-missing-auth",
                    Severity::Medium,
                    0.75,
                    format!(
                        "Private registry for {} is configured without always-auth; tokens may leak to a fallback",
                        scope
                    ),
                    Some(truncate(&format!("{}={}", scope, url))),
                    &["npm", "registry", "dependency-confusion"],
                );
            }
        }
        if !self.strict_ssl {
            push(
                &mut out,
                path,
                None,
                "deps.insecure-registry",
                Severity::High,
                0.85,
                "npm strict-ssl is disabled".to_string(),
                Some("strict-ssl=false".to_string()),
                &["npm", "registry", "tls"],
            );
        }
        out
    }
}

fn scan_npm_confusion(
    manifest: &Path,
    lock: &Path,
    manifest_content: &str,
    lock_content: &str,
    registry: &NpmRegistryConfig,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(manifest_json) = serde_json::from_str::<serde_json::Value>(manifest_content) else {
        return out;
    };
    let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(lock_content) else {
        return out;
    };
    let packages = lock_json.get("packages").and_then(|v| v.as_object());

    let mut declared = BTreeMap::new();
    for key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(deps) = manifest_json.get(key).and_then(|v| v.as_object()) {
            for (name, spec) in deps {
                declared.insert(name.clone(), spec.as_str().unwrap_or("").to_string());
            }
        }
    }

    for (name, spec) in &declared {
        let Some(scope) = name.split('/').next().filter(|s| s.starts_with('@')) else {
            continue;
        };
        let Some(url) = registry.scoped_url(scope) else {
            continue;
        };
        if !NpmRegistryConfig::is_private_registry(url) {
            continue;
        }
        // A private scope resolved from the public registry is the classic
        // dependency-confusion setup.
        let resolved = packages
            .and_then(|pkgs| pkgs.get(&format!("node_modules/{}", name)))
            .and_then(|entry| entry.get("resolved"))
            .and_then(|v| v.as_str());
        match resolved {
            Some(url)
                if url.contains("registry.npmjs.org") || url.contains("registry.yarnpkg.com") =>
            {
                push(
                    &mut out,
                    lock,
                    line_of(lock_content, name),
                    "deps.dependency-confusion",
                    Severity::Critical,
                    0.9,
                    format!(
                        "Private-scope package '{}' resolves from the public npm registry ({}); a public package could shadow the internal one",
                        name, url
                    ),
                    Some(truncate(spec)),
                    &["npm", "dependency-confusion", "supply-chain"],
                );
            }
            None => {
                push(
                    &mut out,
                    manifest,
                    line_of(manifest_content, name),
                    "deps.dependency-confusion",
                    Severity::Medium,
                    0.6,
                    format!(
                        "Private-scope package '{}' is declared but has no lockfile resolution; verify it cannot fall back to the public registry",
                        name
                    ),
                    Some(truncate(spec)),
                    &["npm", "dependency-confusion", "supply-chain"],
                );
            }
            _ => {}
        }
    }
    out
}

fn scan_npm_manifest_drift(
    manifest: &Path,
    lock: &Path,
    manifest_content: &str,
    lock_content: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(manifest_json) = serde_json::from_str::<serde_json::Value>(manifest_content) else {
        return out;
    };
    let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(lock_content) else {
        return out;
    };
    let packages = lock_json.get("packages").and_then(|v| v.as_object());
    let legacy = lock_json.get("dependencies").and_then(|v| v.as_object());

    let mut declared = BTreeMap::new();
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(deps) = manifest_json.get(key).and_then(|v| v.as_object()) {
            for (name, spec) in deps {
                declared.insert(name.clone(), spec.as_str().unwrap_or("").to_string());
            }
        }
    }

    for (name, spec) in &declared {
        match items_version(packages, legacy, name) {
            None => {
                push(
                    &mut out,
                    manifest,
                    line_of(manifest_content, name),
                    "deps.manifest-drift",
                    Severity::Medium,
                    0.75,
                    format!(
                        "package.json declares '{}' but package-lock.json has no matching entry",
                        name
                    ),
                    Some(truncate(spec)),
                    &["npm", "lockfile", "drift"],
                );
            }
            Some(locked) => {
                // Only exact pins can be compared without a semver engine.
                if is_exact_version(spec) && locked != *spec {
                    push(
                        &mut out,
                        lock,
                        line_of(lock_content, &format!("\"{}\"", locked)),
                        "deps.manifest-drift",
                        Severity::Medium,
                        0.7,
                        format!(
                            "package.json pins '{}' to {} but the lockfile resolved {}",
                            name, spec, locked
                        ),
                        Some(truncate(spec)),
                        &["npm", "lockfile", "drift"],
                    );
                }
            }
        }
    }
    out
}

fn items_version(
    packages: Option<&serde_json::Map<String, serde_json::Value>>,
    legacy: Option<&serde_json::Map<String, serde_json::Value>>,
    name: &str,
) -> Option<String> {
    if let Some(packages) = packages {
        let suffix = format!("node_modules/{}", name);
        for (key, value) in packages {
            if key == &suffix || key.ends_with(&format!("/{}", suffix)) {
                if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                    return Some(version.to_string());
                }
            }
        }
    }
    legacy
        .and_then(|deps| deps.get(name))
        .and_then(|value| value.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn is_exact_version(spec: &str) -> bool {
    !spec.is_empty()
        && !spec.contains(['^', '~', '*', '>', '<', '|', ':', '/', ' '])
        && spec.chars().next().is_some_and(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// package-lock.json
// ---------------------------------------------------------------------------

fn scan_package_lock(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        push(
            &mut out,
            path,
            None,
            "deps.invalid-lockfile",
            Severity::Medium,
            0.9,
            "Lockfile is not valid JSON; integrity metadata cannot be trusted".to_string(),
            None,
            &["npm", "lockfile"],
        );
        return out;
    };

    let lock_version = value
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if lock_version < 2 {
        push(
            &mut out,
            path,
            line_of(content, "lockfileVersion"),
            "deps.lockfile-outdated",
            Severity::Low,
            0.7,
            format!(
                "package-lock.json uses lockfileVersion {} (integrity metadata is weaker than v2/v3)",
                lock_version
            ),
            None,
            &["npm", "lockfile"],
        );
    }

    let mut entries: Vec<(String, &serde_json::Value)> = Vec::new();
    if let Some(packages) = value.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            if !key.is_empty() {
                entries.push((key.clone(), entry));
            }
        }
    } else if let Some(deps) = value.get("dependencies").and_then(|v| v.as_object()) {
        for (key, entry) in deps {
            entries.push((key.clone(), entry));
        }
    }

    for (name, entry) in entries {
        let resolved = entry.get("resolved").and_then(|v| v.as_str());
        let integrity = entry.get("integrity").and_then(|v| v.as_str());
        let is_link = entry.get("link").and_then(|v| v.as_bool()) == Some(true);
        let is_local = resolved.is_some_and(|r| {
            r.starts_with("file:") || r.starts_with("link:") || r.starts_with('.')
        });
        if is_link || is_local {
            continue;
        }
        if let Some(resolved) = resolved {
            if resolved.to_lowercase().starts_with("http://") {
                push(
                    &mut out,
                    path,
                    line_of(content, resolved),
                    "deps.insecure-resolution",
                    Severity::High,
                    0.9,
                    format!("Package '{}' is downloaded over plain HTTP", name),
                    Some(truncate(resolved)),
                    &["npm", "lockfile", "tls"],
                );
            } else if is_git_url(resolved) && !has_git_commit(resolved) {
                push(
                    &mut out,
                    path,
                    line_of(content, resolved),
                    "deps.unpinned-git-dependency",
                    Severity::Medium,
                    0.8,
                    format!("Package '{}' resolves to an unpinned git reference", name),
                    Some(truncate(resolved)),
                    &["npm", "lockfile", "git"],
                );
            }
        }
        if resolved.is_some() && integrity.is_none() {
            push(
                &mut out,
                path,
                line_of(content, &format!("\"{}\"", name)),
                "deps.lockfile-missing-integrity",
                Severity::Medium,
                0.75,
                format!("Package '{}' has no integrity hash in the lockfile", name),
                Some(truncate(&name)),
                &["npm", "lockfile", "integrity"],
            );
        }
        if let Some(integrity) = integrity {
            if !is_valid_integrity(integrity) {
                push(
                    &mut out,
                    path,
                    line_of(content, integrity),
                    "deps.tampered-integrity",
                    Severity::High,
                    0.8,
                    format!("Package '{}' has a malformed integrity hash", name),
                    Some(truncate(integrity)),
                    &["npm", "lockfile", "integrity"],
                );
            }
        }
    }
    out
}

fn is_git_url(value: &str) -> bool {
    let lower = value.to_lowercase();
    lower.starts_with("git+")
        || lower.starts_with("git:")
        || lower.starts_with("github:")
        || lower.starts_with("https://github.com/")
        || lower.starts_with("ssh://git@")
}

fn has_git_commit(value: &str) -> bool {
    if let Some((_, fragment)) = value.split_once('#') {
        return fragment.len() >= 7 && fragment.chars().all(|c| c.is_ascii_hexdigit());
    }
    false
}

fn is_valid_integrity(value: &str) -> bool {
    let valid_prefix = ["sha512-", "sha384-", "sha256-", "sha1-"];
    if !valid_prefix.iter().any(|p| value.starts_with(p)) {
        return false;
    }
    let payload = value.split_once('-').map(|(_, p)| p).unwrap_or("");
    payload.len() >= 20
        && payload
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

// ---------------------------------------------------------------------------
// yarn.lock / pnpm-lock.yaml
// ---------------------------------------------------------------------------

fn scan_yarn_lock(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let blocks = split_blocks(content, |line| {
        !line.starts_with(' ') && line.ends_with(':')
    });
    for (start, block) in blocks {
        let name = block
            .lines()
            .next()
            .unwrap_or("")
            .trim_end_matches(':')
            .trim_matches('"')
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();
        if name.is_empty() {
            continue;
        }
        let resolved = block.lines().find_map(|line| {
            line.trim()
                .strip_prefix("resolved ")
                .map(|v| v.trim().trim_matches('"').to_string())
        });
        let has_integrity = block
            .lines()
            .any(|line| line.trim().starts_with("integrity "));
        if let Some(resolved) = &resolved {
            if resolved.to_lowercase().starts_with("http://") {
                push(
                    &mut out,
                    path,
                    Some(start + 1),
                    "deps.insecure-resolution",
                    Severity::High,
                    0.9,
                    format!("Package '{}' is downloaded over plain HTTP", name),
                    Some(truncate(resolved)),
                    &["yarn", "lockfile", "tls"],
                );
            } else if is_git_url(resolved) && !has_git_commit(resolved) {
                push(
                    &mut out,
                    path,
                    Some(start + 1),
                    "deps.unpinned-git-dependency",
                    Severity::Medium,
                    0.8,
                    format!("Package '{}' resolves to an unpinned git reference", name),
                    Some(truncate(resolved)),
                    &["yarn", "lockfile", "git"],
                );
            }
        }
        if resolved.is_some() && !has_integrity {
            push(
                &mut out,
                path,
                Some(start + 1),
                "deps.lockfile-missing-integrity",
                Severity::Low,
                0.6,
                format!("Package '{}' has no integrity hash in yarn.lock", name),
                Some(truncate(&name)),
                &["yarn", "lockfile", "integrity"],
            );
        }
    }
    out
}

fn scan_pnpm_lock(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let lower = line.to_lowercase();
        if lower.contains("tarball:") && lower.contains("http://") {
            let value = lower.split("tarball:").nth(1).unwrap_or("").trim();
            push(
                &mut out,
                path,
                Some(i + 1),
                "deps.insecure-resolution",
                Severity::High,
                0.9,
                "pnpm resolves a package over plain HTTP".to_string(),
                Some(truncate(value.trim_matches(|c| c == '"' || c == '\''))),
                &["pnpm", "lockfile", "tls"],
            );
        }
        if lower.trim_start().starts_with("lockfileversion:") {
            let version = line
                .split_once(':')
                .map(|(_, v)| v.trim().trim_matches('"'))
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            if version < 6 {
                push(
                    &mut out,
                    path,
                    Some(i + 1),
                    "deps.lockfile-outdated",
                    Severity::Low,
                    0.6,
                    format!(
                        "pnpm lockfileVersion {} is outdated and lacks modern integrity data",
                        version
                    ),
                    Some(truncate(line)),
                    &["pnpm", "lockfile"],
                );
            }
        }
    }
    out
}

/// Split a line-oriented file into blocks that start when `is_start` matches.
/// Returns (zero-based start line, block text) pairs.
fn split_blocks(content: &str, is_start: impl Fn(&str) -> bool) -> Vec<(usize, String)> {
    let mut blocks = Vec::new();
    let mut start = 0usize;
    let mut current = String::new();
    for (i, line) in content.lines().enumerate() {
        if is_start(line) {
            if !current.is_empty() {
                blocks.push((start, std::mem::take(&mut current)));
            }
            start = i;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        blocks.push((start, current));
    }
    blocks
}

// ---------------------------------------------------------------------------
// Cargo.lock
// ---------------------------------------------------------------------------

fn scan_cargo_lock(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut name = String::new();
    let mut has_checksum = false;
    let mut source = String::new();
    let mut version = String::new();
    let mut block_start = 0usize;

    let finish = |out: &mut Vec<Finding>,
                  name: &str,
                  version: &str,
                  source: &str,
                  has_checksum: bool,
                  block_start: usize| {
        if name.is_empty() {
            return;
        }
        if source.starts_with("registry+") || source.starts_with("sparse+") {
            if !has_checksum {
                push(
                    out,
                    path,
                    Some(block_start + 1),
                    "deps.lockfile-missing-integrity",
                    Severity::Medium,
                    0.8,
                    format!(
                        "Crate '{} {}' has no checksum in Cargo.lock; tampering cannot be detected",
                        name, version
                    ),
                    Some(truncate(&format!("{} {}", name, version))),
                    &["cargo", "lockfile", "integrity"],
                );
            }
            if source.to_lowercase().starts_with("registry+http://") {
                push(
                    out,
                    path,
                    Some(block_start + 1),
                    "deps.insecure-resolution",
                    Severity::High,
                    0.9,
                    format!("Crate '{}' resolves from a plain-HTTP registry", name),
                    Some(truncate(source)),
                    &["cargo", "lockfile", "tls"],
                );
            }
        } else if source.starts_with("git+") && !has_git_commit(source) {
            push(
                out,
                path,
                Some(block_start + 1),
                "deps.unpinned-git-dependency",
                Severity::Medium,
                0.8,
                format!("Crate '{}' depends on an unpinned git source", name),
                Some(truncate(source)),
                &["cargo", "lockfile", "git"],
            );
        }
    };

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            finish(
                &mut out,
                &name,
                &version,
                &source,
                has_checksum,
                block_start,
            );
            name.clear();
            version.clear();
            source.clear();
            has_checksum = false;
            block_start = i;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name = ") {
            name = rest.trim().trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version = ") {
            version = rest.trim().trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("source = ") {
            source = rest.trim().trim_matches('"').to_string();
        } else if trimmed.starts_with("checksum = ") {
            has_checksum = true;
        }
    }
    finish(
        &mut out,
        &name,
        &version,
        &source,
        has_checksum,
        block_start,
    );
    out
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

fn scan_requirements(path: &Path, content: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("--extra-index-url") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "deps.dependency-confusion",
                Severity::High,
                0.85,
                "requirements.txt adds an extra package index; a dependency-confusion package can shadow PyPI".to_string(),
                Some(truncate(trimmed)),
                &["pypi", "dependency-confusion", "supply-chain"],
            );
        }
        if (lower.starts_with("--index-url") || lower.starts_with("-i "))
            && lower.contains("http://")
        {
            push(
                &mut out,
                path,
                Some(i + 1),
                "deps.insecure-resolution",
                Severity::High,
                0.9,
                "Package index uses plain HTTP".to_string(),
                Some(truncate(trimmed)),
                &["pypi", "tls"],
            );
        }
        if lower.starts_with("--trusted-host") {
            push(
                &mut out,
                path,
                Some(i + 1),
                "deps.insecure-registry",
                Severity::Medium,
                0.8,
                "pip disables TLS verification for a package host".to_string(),
                Some(truncate(trimmed)),
                &["pypi", "tls"],
            );
        }
    }
    out
}

// ---------------------------------------------------------------------------
// go and Pipfile drift
// ---------------------------------------------------------------------------

fn scan_go_drift(
    manifest: &Path,
    sum: &Path,
    manifest_content: &str,
    sum_content: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let known: BTreeSet<String> = sum_content
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let name = parts.next()?;
            let version = parts.next()?.trim_end_matches("/go.mod");
            Some(format!("{}@{}", name, version))
        })
        .collect();

    let mut in_require = false;
    for (i, line) in manifest_content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "require (" {
            in_require = true;
            continue;
        }
        if in_require && trimmed == ")" {
            in_require = false;
            continue;
        }
        let dependency = if in_require {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        if dependency.starts_with("//") {
            continue;
        }
        let mut parts = dependency.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        if !known.contains(&format!("{}@{}", name, version)) {
            push(
                &mut out,
                sum,
                None,
                "deps.manifest-drift",
                Severity::Medium,
                0.7,
                format!(
                    "go.mod requires {} {} but go.sum has no checksum for it",
                    name, version
                ),
                Some(truncate(&format!("{} {}", name, version))),
                &["go", "lockfile", "drift"],
            );
            let _ = manifest;
            let _ = i;
        }
    }
    out
}

fn scan_pipfile_drift(
    manifest: &Path,
    lock: &Path,
    manifest_content: &str,
    lock_content: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Ok(lock_json) = serde_json::from_str::<serde_json::Value>(lock_content) else {
        return out;
    };
    let locked: BTreeSet<String> = ["default", "develop"]
        .iter()
        .filter_map(|section| lock_json.get(*section).and_then(|v| v.as_object()))
        .flat_map(|obj| obj.keys().cloned())
        .collect();

    let mut section = String::new();
    for (i, line) in manifest_content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_lowercase();
            continue;
        }
        if section != "packages" && section != "dev-packages" {
            continue;
        }
        let name = trimmed.split('=').next().unwrap_or("").trim();
        if name.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !locked.contains(name) {
            push(
                &mut out,
                lock,
                Some(i + 1),
                "deps.manifest-drift",
                Severity::Medium,
                0.7,
                format!(
                    "Pipfile lists '{}' but Pipfile.lock has no matching entry",
                    name
                ),
                Some(truncate(trimmed)),
                &["pypi", "lockfile", "drift"],
            );
        }
    }
    let _ = manifest;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule.as_str()).collect()
    }

    #[test]
    fn flags_http_and_missing_integrity_in_package_lock() {
        let content = r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/evil": {
      "version": "1.0.0",
      "resolved": "http://registry.example/evil-1.0.0.tgz"
    },
    "node_modules/ok": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}"#;
        let findings = scan_package_lock(Path::new("package-lock.json"), content);
        assert!(rules(&findings).contains(&"deps.insecure-resolution"));
        assert!(rules(&findings).contains(&"deps.lockfile-missing-integrity"));
    }

    #[test]
    fn flags_unpinned_git_and_bad_integrity() {
        let content = r#"{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/a": {
      "version": "0.1.0",
      "resolved": "git+https://github.com/x/a.git",
      "integrity": "md5-abc"
    }
  }
}"#;
        let findings = scan_package_lock(Path::new("package-lock.json"), content);
        assert!(rules(&findings).contains(&"deps.unpinned-git-dependency"));
        assert!(rules(&findings).contains(&"deps.tampered-integrity"));
    }

    #[test]
    fn detects_public_resolution_of_private_scope() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let lock = dir.path().join("package-lock.json");
        std::fs::write(
            &manifest,
            r#"{ "dependencies": { "@corp/internal": "^1.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            &lock,
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@corp/internal": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/@corp/internal/-/internal-1.0.0.tgz",
      "integrity": "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }
  }
}"#,
        )
        .unwrap();
        let mut registry = NpmRegistryConfig::default();
        registry.merge("@corp:registry=https://npm.corp.example\n");
        let findings =
            scan_npm_confusion(&manifest, &lock, &read(&manifest), &read(&lock), &registry);
        assert!(rules(&findings).contains(&"deps.dependency-confusion"));
    }

    #[test]
    fn detects_manifest_drift() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("package.json");
        let lock = dir.path().join("package-lock.json");
        std::fs::write(
            &manifest,
            r#"{ "dependencies": { "missing": "1.0.0", "pinned": "1.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            &lock,
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/pinned": { "version": "2.0.0" }
  }
}"#,
        )
        .unwrap();
        let findings = scan_npm_manifest_drift(&manifest, &lock, &read(&manifest), &read(&lock));
        assert_eq!(
            rules(&findings)
                .iter()
                .filter(|r| **r == "deps.manifest-drift")
                .count(),
            2
        );
    }

    #[test]
    fn flags_cargo_missing_checksum_and_git_ref() {
        let content = r#"
[[package]]
name = "a"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "b"
version = "0.1.0"
source = "git+https://github.com/x/b.git"

[[package]]
name = "c"
version = "0.2.0"
source = "git+https://github.com/x/c.git#0123456789abcdef0123456789abcdef01234567"
"#;
        let findings = scan_cargo_lock(Path::new("Cargo.lock"), content);
        let rules = rules(&findings);
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "deps.lockfile-missing-integrity")
                .count(),
            1
        );
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "deps.unpinned-git-dependency")
                .count(),
            1
        );
    }

    #[test]
    fn flags_extra_index_url_and_insecure_index() {
        let content = "--index-url http://pypi.example/simple\n--extra-index-url https://pypi.org/simple\n--trusted-host pypi.example\n";
        let findings = scan_requirements(Path::new("requirements.txt"), content);
        let rules = rules(&findings);
        assert!(rules.contains(&"deps.insecure-resolution"));
        assert!(rules.contains(&"deps.dependency-confusion"));
        assert!(rules.contains(&"deps.insecure-registry"));
    }

    #[test]
    fn flags_yarn_insecure_and_missing_integrity() {
        let content = "\"evil@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"http://registry.example/evil.tgz\"\n\n\"ok@^1.0.0\":\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/ok/-/ok-1.0.0.tgz\"\n  integrity sha512-abc\n";
        let findings = scan_yarn_lock(Path::new("yarn.lock"), content);
        let rules = rules(&findings);
        assert!(rules.contains(&"deps.insecure-resolution"));
        assert!(rules.contains(&"deps.lockfile-missing-integrity"));
    }

    #[test]
    fn flags_go_manifest_drift() {
        let manifest =
            "module x\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.4.0\n)\n";
        let sum = "github.com/a/b v1.2.3 h1:abc\n";
        let findings = scan_go_drift(Path::new("go.mod"), Path::new("go.sum"), manifest, sum);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "deps.manifest-drift");
    }
}
