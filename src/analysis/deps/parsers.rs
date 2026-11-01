use crate::analysis::deps::Dependency;
use std::path::Path;

pub fn parse_npm_lock(content: &str, source: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return out;
    };
    // lockfileVersion 2/3: "packages" with "node_modules/<name>" keys.
    if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
        for (key, val) in pkgs {
            if key.is_empty() {
                continue;
            }
            let name = key.strip_prefix("node_modules/").unwrap_or(key);
            // nested node_modules: take last segment
            let name = name.rsplit("node_modules/").next().unwrap_or(name);
            if name.is_empty() || name == key {
                // skip if no node_modules
                if !key.contains("node_modules") {
                    continue;
                }
            }
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() || version.is_empty() {
                continue;
            }
            out.push(Dependency {
                ecosystem: "npm".to_string(),
                name: name.to_string(),
                version,
                source: source.to_path_buf(),
            });
        }
        return out;
    }
    // lockfileVersion 1: "dependencies"
    if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
        for (name, val) in deps {
            let version = val
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if version.is_empty() {
                continue;
            }
            out.push(Dependency {
                ecosystem: "npm".to_string(),
                name: name.clone(),
                version,
                source: source.to_path_buf(),
            });
        }
    }
    out
}

pub fn parse_cargo_lock(content: &str, source: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
    // Simple TOML-ish parsing: find [[package]] blocks.
    let mut current_name = String::new();
    let mut current_version = String::new();
    let mut in_package = false;
    for line in content.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            if in_package && !current_name.is_empty() {
                out.push(Dependency {
                    ecosystem: "cargo".to_string(),
                    name: current_name.clone(),
                    version: current_version.clone(),
                    source: source.to_path_buf(),
                });
            }
            current_name.clear();
            current_version.clear();
            in_package = true;
            continue;
        }
        if in_package {
            if let Some(rest) = t.strip_prefix("name = ") {
                current_name = rest.trim().trim_matches('"').to_string();
            } else if let Some(rest) = t.strip_prefix("version = ") {
                current_version = rest.trim().trim_matches('"').to_string();
            }
        }
    }
    if in_package && !current_name.is_empty() {
        out.push(Dependency {
            ecosystem: "cargo".to_string(),
            name: current_name,
            version: current_version,
            source: source.to_path_buf(),
        });
    }
    out
}

pub fn parse_requirements(content: &str, source: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        // Split off extras/markers.
        let t = t.split(';').next().unwrap_or(t).trim();
        let t = t.split('[').next().unwrap_or(t).trim();
        // Name and version.
        let mut name = t.to_string();
        let mut version = String::new();
        for sep in ["==", ">=", "<=", "~=", ">", "<", "!="] {
            if let Some(idx) = t.find(sep) {
                name = t[..idx].trim().to_string();
                version = t[idx..].trim().to_string();
                break;
            }
        }
        // If no version, name may include trailing; clean.
        name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        out.push(Dependency {
            ecosystem: "pypi".to_string(),
            name,
            version,
            source: source.to_path_buf(),
        });
    }
    out
}

pub fn parse_go_sum(content: &str, source: &Path) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].to_string();
        let version = parts[1].trim_end_matches("/go.mod").to_string();
        let key = format!("{}@{}", name, version);
        if seen.insert(key) {
            out.push(Dependency {
                ecosystem: "go".to_string(),
                name,
                version,
                source: source.to_path_buf(),
            });
        }
    }
    out
}

/// Collect dependencies from a list of file paths.
pub fn collect_dependencies(files: &[std::path::PathBuf]) -> Vec<Dependency> {
    let mut out = Vec::new();
    for f in files {
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let Ok(content) = std::fs::read_to_string(f) else {
            continue;
        };
        match name {
            "package-lock.json" => out.extend(parse_npm_lock(&content, f)),
            "Cargo.lock" => out.extend(parse_cargo_lock(&content, f)),
            "requirements.txt" => out.extend(parse_requirements(&content, f)),
            "go.sum" => out.extend(parse_go_sum(&content, f)),
            _ => {}
        }
    }
    out
}
