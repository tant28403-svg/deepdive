//! Native Linux sandbox: user/mount/pid/network namespaces, a minimal
//! pivot_root, seccomp-BPF deny list, and best-effort cgroup v2 limits.

pub mod cgroups;
pub mod namespaces;
pub mod seccomp;

use crate::sandbox::policy::{NetworkPolicy, SandboxPolicy};
use crate::sandbox::process;
use crate::sandbox::snapshot;
use crate::sandbox::{CaptureContext, SandboxError};
use crate::types::SandboxReport;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

pub fn run(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
    capture: Option<&CaptureContext>,
) -> Result<SandboxReport, SandboxError> {
    let root = tempfile::tempdir().map_err(SandboxError::Io)?;
    let root_path = root.path().to_path_buf();
    let target_owned = target.to_path_buf();
    let unshare_net = policy.network == NetworkPolicy::None;

    // Point the sandbox resolver at the capture DNS service when active.
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
    let resolv_path = resolv.as_ref().map(|file| file.path().to_path_buf());

    let cgroup = cgroups::create(policy).map(Rc::new);

    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: "linux-native".to_string(),
        backend: "linux-native".to_string(),
        policy: policy.clone(),
        ..Default::default()
    };
    let before = snapshot::capture(target);

    let mut command = Command::new("sh");
    command.arg("-c").arg(cmd);
    if let Some(context) = capture {
        command.env("HTTP_PROXY", &context.proxy_url);
        command.env("HTTPS_PROXY", &context.proxy_url);
        command.env("http_proxy", &context.proxy_url);
        command.env("https_proxy", &context.proxy_url);
        command.env("ALL_PROXY", &context.proxy_url);
        command.env("NO_PROXY", "localhost,127.0.0.1,::1");
    }
    unsafe {
        command.pre_exec(move || {
            namespaces::enter(
                &target_owned,
                &root_path,
                unshare_net,
                resolv_path.as_deref(),
            )?;
            seccomp::apply().map_err(|err| std::io::Error::other(err.to_string()))?;
            Ok(())
        });
    }

    let spawn_group = cgroup.clone();
    let timeout_group = cgroup.clone();
    let completed = process::run_with_timeout(
        command,
        Duration::from_secs(policy.timeout_secs.max(1)),
        move |pid| {
            if let Some(group) = &spawn_group {
                group.add_pid(pid);
            }
        },
        move |_child| {
            if let Some(group) = &timeout_group {
                group.kill();
            }
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
        "network is unreachable",
        "could not resolve host",
        "name or service not known",
    ] {
        if combined.contains(pattern) {
            report.network_indicators.push(pattern.to_string());
        }
    }

    if let Some(group) = &cgroup {
        group.cleanup();
    }

    Ok(report)
}
