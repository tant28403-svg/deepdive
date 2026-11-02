use crate::sandbox::policy::{NetworkPolicy, SandboxPolicy};
use crate::sandbox::process;
use crate::sandbox::{snapshot, SandboxError};
use crate::types::SandboxReport;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

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

pub fn run_native(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
) -> Result<SandboxReport, SandboxError> {
    let use_bwrap = bwrap_available();
    if !use_bwrap && !firejail_available() {
        return Err(SandboxError::Unavailable(
            "no linux sandbox available (install bubblewrap or firejail)".to_string(),
        ));
    }

    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: if use_bwrap {
            "linux-bwrap".to_string()
        } else {
            "linux-firejail".to_string()
        },
        backend: if use_bwrap {
            "linux-native".to_string()
        } else {
            "linux-firejail".to_string()
        },
        policy: policy.clone(),
        ..Default::default()
    };
    if policy.network == NetworkPolicy::Capture {
        // Capture proxy is scheduled for stage 20.
        report.telemetry_degraded = true;
    }

    let before = snapshot::capture(target);

    let mut command = if use_bwrap {
        let mut command = Command::new("bwrap");
        if policy.network == NetworkPolicy::Allow {
            command
                .arg("--unshare-user")
                .arg("--unshare-pid")
                .arg("--unshare-uts")
                .arg("--unshare-ipc")
                .arg("--unshare-cgroup-try");
        } else {
            command.arg("--unshare-all");
        }
        command
            .arg("--die-with-parent")
            .arg("--new-session")
            .arg("--cap-drop")
            .arg("ALL")
            .arg("--proc")
            .arg("/proc")
            .arg("--dev")
            .arg("/dev")
            .arg("--tmpfs")
            .arg("/tmp");
        for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"] {
            if std::path::Path::new(dir).exists() {
                command.arg("--ro-bind").arg(dir).arg(dir);
            }
        }
        for path in &policy.writable {
            command.arg("--bind").arg(path).arg(path);
        }
        command
            .arg("--bind")
            .arg(target)
            .arg("/work")
            .arg("--chdir")
            .arg("/work")
            .arg("sh")
            .arg("-c")
            .arg(cmd);
        command
    } else {
        let mut command = Command::new("firejail");
        command.arg("--quiet").arg("--private");
        if policy.network == NetworkPolicy::Allow {
            command.arg("--net=bridge");
        } else {
            command.arg("--net=none");
        }
        command
            .arg(format!("--whitelist={}", target.display()))
            .arg("sh")
            .arg("-c")
            .arg(format!("cd {} && {}", target.display(), cmd));
        command
    };

    if policy.env_scrub {
        command.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            command.env("PATH", path);
        }
    }

    let completed = process::run_with_timeout(
        command,
        Duration::from_secs(policy.timeout_secs.max(1)),
        |_child| {},
    )?;

    report.duration_ms = completed.duration.as_millis() as u64;
    report.timed_out = completed.timed_out;
    report.exit_code = completed.exit_code;
    report.stdout = String::from_utf8_lossy(&completed.stdout).to_string();
    report.stderr = String::from_utf8_lossy(&completed.stderr).to_string();

    let after = snapshot::capture(target);
    let diff = snapshot::diff(&before, &after);
    report.files_created = diff.created;
    report.files_modified = diff.modified;
    report.files_deleted = diff.deleted;

    let combined = format!("{}\n{}", report.stdout, report.stderr).to_lowercase();
    for pattern in [
        "connection refused",
        "network is unreachable",
        "could not resolve host",
        "name or service not known",
    ] {
        if combined.contains(pattern) {
            report.network_indicators.push(pattern.to_string());
        }
    }

    Ok(report)
}
