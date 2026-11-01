use crate::types::SandboxReport;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

pub fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn firejail_available() -> bool {
    Command::new("firejail")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn run_native(cmd: &str, target: &Path, timeout_secs: u64) -> Result<SandboxReport> {
    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: if bwrap_available() {
            "linux-bwrap".to_string()
        } else {
            "linux-firejail".to_string()
        },
        ..Default::default()
    };

    // Snapshot before.
    let before = snapshot_dir(target);

    let start = std::time::Instant::now();

    let output = if bwrap_available() {
        // bubblewrap: minimal isolated env, no network, bind target read-write.
        Command::new("bwrap")
            .arg("--unshare-all")
            .arg("--unshare-net")
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--tmpfs")
            .arg("/tmp")
            .arg("--ro-bind")
            .arg("/usr")
            .arg("/usr")
            .arg("--ro-bind")
            .arg("/lib")
            .arg("/lib")
            .arg("--ro-bind")
            .arg("/lib64")
            .arg("/lib64")
            .arg("--ro-bind")
            .arg("/bin")
            .arg("/bin")
            .arg("--ro-bind")
            .arg("/sbin")
            .arg("/sbin")
            .arg("--ro-bind")
            .arg("/etc")
            .arg("/etc")
            .arg("--bind")
            .arg(target)
            .arg("/work")
            .arg("--chdir")
            .arg("/work")
            .arg("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .context("run bwrap")?
    } else if firejail_available() {
        Command::new("firejail")
            .arg("--net=none")
            .arg("--private")
            .arg("--whitelist=")
            .arg(target)
            .arg("sh")
            .arg("-c")
            .arg(format!("cd {} && {}", target.display(), cmd))
            .output()
            .context("run firejail")?
    } else {
        anyhow::bail!("no linux sandbox available (install bubblewrap or firejail)");
    };

    report.duration_ms = start.elapsed().as_millis() as u64;
    report.exit_code = output.status.code();
    report.stdout = String::from_utf8_lossy(&output.stdout).to_string();
    report.stderr = String::from_utf8_lossy(&output.stderr).to_string();

    let after = snapshot_dir(target);
    diff_snapshots(&before, &after, &mut report);

    // Network indicators.
    let combined = format!("{}\n{}", report.stdout, report.stderr).to_lowercase();
    for p in [
        "connection refused",
        "network is unreachable",
        "could not resolve host",
        "name or service not known",
    ] {
        if combined.contains(p) {
            report.network_indicators.push(p.to_string());
        }
    }

    // timeout handling (process already done; informational)
    if start.elapsed() > std::time::Duration::from_secs(timeout_secs) {
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
