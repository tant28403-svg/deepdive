use crate::sandbox::policy::{NetworkPolicy, SandboxPolicy};
use crate::sandbox::process;
use crate::sandbox::snapshot;
use crate::sandbox::{CaptureContext, SandboxError};
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
    capture: Option<&CaptureContext>,
) -> Result<SandboxReport, SandboxError> {
    // Prefer the native namespaces backend when compiled in. If it cannot start
    // (for example the kernel forbids unprivileged user namespaces), fall back
    // to bubblewrap or firejail when one is installed.
    #[cfg(feature = "native-sandbox")]
    match crate::sandbox::linux::run(policy, cmd, target, capture) {
        Ok(report) => return Ok(report),
        Err(native_err) => {
            if !bwrap_available() && !firejail_available() {
                return Err(native_err);
            }
        }
    }

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
    if policy.network == NetworkPolicy::Capture && capture.is_none() {
        report.telemetry_degraded = true;
    }

    // Resolver file used to point the sandbox at the capture DNS service.
    let resolv = if policy.network == NetworkPolicy::Capture {
        capture
            .and_then(|context| context.dns_addr)
            .and_then(|addr| {
                tempfile::NamedTempFile::new().ok().map(|file| {
                    let _ = std::fs::write(file.path(), format!("nameserver {}\n", addr.ip()));
                    file
                })
            })
    } else {
        None
    };

    let before = snapshot::capture(target);

    let mut command = if use_bwrap {
        let mut command = Command::new("bwrap");
        if policy.network != NetworkPolicy::None {
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
        if let Some(file) = &resolv {
            command
                .arg("--ro-bind")
                .arg(file.path())
                .arg("/etc/resolv.conf");
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
        if policy.network == NetworkPolicy::None {
            command.arg("--net=none");
        } else {
            command.arg("--net=bridge");
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
    if let Some(context) = capture {
        for variable in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
        ] {
            command.env(variable, &context.proxy_url);
        }
        command.env("NO_PROXY", "localhost,127.0.0.1,::1");
    }

    let completed = process::run_with_timeout(
        command,
        Duration::from_secs(policy.timeout_secs.max(1)),
        |_pid| {},
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
