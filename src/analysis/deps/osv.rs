use crate::analysis::deps::Dependency;
use crate::types::{Finding, Location, Severity};

const OSV_URL: &str = "https://api.osv.dev/v1/query";

pub fn query_vulns(ecosystem: &str, name: &str, version: &str) -> Vec<String> {
    let eco = match ecosystem {
        "npm" => "npm",
        "cargo" => "crates.io",
        "pypi" => "PyPI",
        "go" => "Go",
        _ => return vec![],
    };
    let body = serde_json::json!({
        "package": { "name": name, "ecosystem": eco },
        "version": version,
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build();
    let Ok(client) = client else {
        return vec![];
    };
    let resp = client.post(OSV_URL).json(&body).send();
    let Ok(resp) = resp else {
        return vec![];
    };
    let Ok(json) = resp.json::<serde_json::Value>() else {
        return vec![];
    };
    let mut ids = Vec::new();
    if let Some(vulns) = json.get("vulns").and_then(|v| v.as_array()) {
        for v in vulns {
            if let Some(id) = v.get("id").and_then(|i| i.as_str()) {
                ids.push(id.to_string());
            }
        }
    }
    ids
}

pub fn audit_dependencies(deps: &[Dependency], offline: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    // Typosquatting check (offline, always).
    out.extend(typosquat_findings(deps));
    if offline {
        return out;
    }
    for dep in deps {
        let vulns = query_vulns(&dep.ecosystem, &dep.name, &dep.version);
        for v in vulns {
            out.push(Finding {
                id: format!("deps.osv-{}-{}-{}", dep.ecosystem, dep.name, v),
                severity: Severity::High,
                confidence: 0.9,
                rule: "deps.known-vulnerability".to_string(),
                category: "dependency".to_string(),
                location: Location {
                    path: dep.source.display().to_string(),
                    line: None,
                    column: None,
                },
                message: format!("{} {} has known vulnerability {}", dep.name, dep.version, v),
                snippet: None,
                tags: vec![dep.ecosystem.clone()],
            });
        }
    }
    out
}

fn typosquat_findings(deps: &[Dependency]) -> Vec<Finding> {
    let mut out = Vec::new();
    // Top package lists (small samples; expand later).
    let npm_top = [
        "lodash",
        "express",
        "react",
        "axios",
        "moment",
        "chalk",
        "commander",
        "debug",
        "uuid",
        "dotenv",
    ];
    let cargo_top = [
        "serde",
        "tokio",
        "clap",
        "reqwest",
        "anyhow",
        "thiserror",
        "tracing",
        "rayon",
    ];
    let pypi_top = [
        "requests", "numpy", "flask", "django", "pandas", "scipy", "boto3", "urllib3",
    ];

    for dep in deps {
        let top = match dep.ecosystem.as_str() {
            "npm" => &npm_top[..],
            "cargo" => &cargo_top[..],
            "pypi" => &pypi_top[..],
            _ => continue,
        };
        for &popular in top {
            if dep.name == popular {
                continue;
            }
            let d = edit_distance(&dep.name, popular);
            if d == 1 || d == 2 {
                out.push(Finding {
                    id: format!("deps.typosquat-{}-{}", dep.ecosystem, dep.name),
                    severity: Severity::High,
                    confidence: 0.7,
                    rule: "deps.typosquatting".to_string(),
                    category: "dependency".to_string(),
                    location: Location {
                        path: dep.source.display().to_string(),
                        line: None,
                        column: None,
                    },
                    message: format!(
                        "Possible typosquatting: '{}' is close to popular package '{}'",
                        dep.name, popular
                    ),
                    snippet: None,
                    tags: vec![dep.ecosystem.clone()],
                });
                break;
            }
        }
    }
    out
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}
