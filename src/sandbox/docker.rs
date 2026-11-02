use crate::sandbox::policy::{NetworkPolicy, SandboxPolicy};
use crate::sandbox::process;
use crate::sandbox::{snapshot, SandboxError};
use crate::types::SandboxReport;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn run_sandbox(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
) -> Result<SandboxReport, SandboxError> {
    if !docker_available() {
        return Err(SandboxError::Unavailable(
            "docker is not available; install Docker Desktop (Windows) or docker engine (Linux)"
                .to_string(),
        ));
    }

    let image =
        std::env::var("DEEPDIVE_SANDBOX_IMAGE").unwrap_or_else(|_| "ubuntu:22.04".to_string());
    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: image.clone(),
        backend: "docker".to_string(),
        policy: policy.clone(),
        ..Default::default()
    };
    if policy.network == NetworkPolicy::Capture {
        // The capture proxy lands in stage 20; be explicit that it is not active.
        report.telemetry_degraded = true;
    }

    let before = snapshot::capture(target);

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("deepdive-{}-{}", std::process::id(), unique);

    let mut docker = Command::new("docker");
    docker
        .arg("run")
        .arg("--rm")
        .arg("--name")
        .arg(&name)
        .arg("--network")
        .arg(match policy.network {
            NetworkPolicy::None | NetworkPolicy::Capture => "none",
            NetworkPolicy::Allow => "bridge",
        })
        .arg("--memory")
        .arg(format!("{}m", policy.memory_mb))
        .arg("--cpus")
        .arg(format!("{}", policy.cpus))
        .arg("--pids-limit")
        .arg(policy.pids.to_string())
        .arg("--cap-drop")
        .arg("ALL")
        .arg("--security-opt")
        .arg("no-new-privileges");

    if policy.read_only_root {
        docker.arg("--read-only");
        docker.arg("--tmpfs").arg("/tmp");
    }

    for path in &policy.writable {
        docker
            .arg("-v")
            .arg(format!("{}:{}", path.display(), path.display()));
    }

    docker
        .arg("-v")
        .arg(format!("{}:/work", target.display()))
        .arg("-w")
        .arg("/work")
        .arg(&image)
        .arg("sh")
        .arg("-c")
        .arg(cmd);

    if policy.env_scrub {
        docker.env_clear();
    }

    let completed = process::run_with_timeout(
        docker,
        Duration::from_secs(policy.timeout_secs.max(1)),
        |_pid| {},
        |_child| {
            let _ = Command::new("docker").args(["kill", &name]).output();
        },
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
        "connection timed out",
        "name or service not known",
        "could not resolve host",
        "network is unreachable",
        "no route to host",
    ] {
        if combined.contains(pattern) {
            report.network_indicators.push(pattern.to_string());
        }
    }

    Ok(report)
}
