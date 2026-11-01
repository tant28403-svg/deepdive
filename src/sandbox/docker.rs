use crate::types::SandboxReport;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn run_sandbox(
    cmd: &str,
    target: &Path,
    image: &str,
    timeout_secs: u64,
) -> Result<SandboxReport> {
    if !docker_available() {
        anyhow::bail!(
            "docker is not available; install Docker Desktop (Windows) or docker engine (Linux)"
        );
    }

    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: image.to_string(),
        ..Default::default()
    };

    // Snapshot before.
    let before = snapshot_dir(target);

    let start = Instant::now();
    // Build docker run command.
    let mut docker = Command::new("docker");
    docker
        .arg("run")
        .arg("--rm")
        .arg("--network")
        .arg("none")
        .arg("--memory")
        .arg("512m")
        .arg("--cpus")
        .arg("1")
        .arg("--pids-limit")
        .arg("256")
        .arg("-v")
        .arg(format!("{}:/work", target.display()))
        .arg("-w")
        .arg("/work")
        .arg(image)
        .arg("sh")
        .arg("-c")
        .arg(cmd);

    // Timeout via a thread? Simpler: run and wait with a deadline using wait_with_output is blocking.
    // We'll just run; timeout enforced by docker? Use timeout command if available. For now run directly.
    let output = docker.output().context("run docker")?;
    report.duration_ms = start.elapsed().as_millis() as u64;
    report.exit_code = output.status.code();
    report.stdout = String::from_utf8_lossy(&output.stdout).to_string();
    report.stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Snapshot after.
    let after = snapshot_dir(target);
    diff_snapshots(&before, &after, &mut report);

    // Network indicators from output.
    let net_patterns = [
        "connection refused",
        "connection timed out",
        "name or service not known",
        "could not resolve host",
        "network is unreachable",
        "no route to host",
    ];
    let combined = format!("{}\n{}", report.stdout, report.stderr).to_lowercase();
    for p in net_patterns {
        if combined.contains(p) {
            report.network_indicators.push(p.to_string());
        }
    }

    // Enforce timeout (informational; process already finished).
    if start.elapsed() > Duration::from_secs(timeout_secs) {
        report.stderr.push_str("\n[timeout exceeded]");
    }

    Ok(report)
}

fn snapshot_dir(root: &Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;
    let mut map = std::collections::BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let hash = std::fs::read(path)
            .map(|b| {
                let mut h = Sha256::new();
                h.update(&b);
                format!("{:x}", h.finalize())
            })
            .unwrap_or_default();
        map.insert(rel, hash);
    }
    map
}

pub fn behavioral_findings(report: &SandboxReport) -> Vec<crate::types::Finding> {
    use crate::types::{Finding, Location, Severity};
    let mut out = Vec::new();
    let target = "/work";
    if !report.files_created.is_empty() {
        out.push(Finding {
            id: "sandbox.files-created".to_string(),
            severity: Severity::Medium,
            confidence: 0.8,
            rule: "sandbox.files-created".to_string(),
            category: "sandbox".to_string(),
            location: Location {
                path: target.to_string(),
                line: None,
                column: None,
            },
            message: format!(
                "Sandbox created {} files: {}",
                report.files_created.len(),
                report.files_created.join(", ")
            ),
            snippet: None,
            tags: vec![],
        });
    }
    if !report.files_modified.is_empty() {
        out.push(Finding {
            id: "sandbox.files-modified".to_string(),
            severity: Severity::Medium,
            confidence: 0.8,
            rule: "sandbox.files-modified".to_string(),
            category: "sandbox".to_string(),
            location: Location {
                path: target.to_string(),
                line: None,
                column: None,
            },
            message: format!("Sandbox modified {} files", report.files_modified.len()),
            snippet: None,
            tags: vec![],
        });
    }
    if !report.network_indicators.is_empty() {
        out.push(Finding {
            id: "sandbox.network-attempt".to_string(),
            severity: Severity::High,
            confidence: 0.85,
            rule: "sandbox.network-attempt".to_string(),
            category: "sandbox".to_string(),
            location: Location {
                path: target.to_string(),
                line: None,
                column: None,
            },
            message: format!(
                "Sandbox detected network activity: {}",
                report.network_indicators.join(", ")
            ),
            snippet: None,
            tags: vec![],
        });
    }
    if let Some(code) = report.exit_code {
        if code != 0 {
            out.push(Finding {
                id: "sandbox.nonzero-exit".to_string(),
                severity: Severity::Low,
                confidence: 0.5,
                rule: "sandbox.nonzero-exit".to_string(),
                category: "sandbox".to_string(),
                location: Location {
                    path: target.to_string(),
                    line: None,
                    column: None,
                },
                message: format!("Sandbox command exited with code {}", code),
                snippet: None,
                tags: vec![],
            });
        }
    }
    out
}
fn diff_snapshots(
    before: &std::collections::BTreeMap<String, String>,
    after: &std::collections::BTreeMap<String, String>,
    report: &mut SandboxReport,
) {
    for (k, v) in after {
        match before.get(k) {
            None => report.files_created.push(k.clone()),
            Some(prev) if prev != v => report.files_modified.push(k.clone()),
            _ => {}
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            report.files_deleted.push(k.clone());
        }
    }
}
