pub mod docker;
pub mod error;
#[cfg(all(target_os = "linux", feature = "native-sandbox"))]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod linux_native;
pub mod policy;
pub mod process;
pub mod selftest;
pub mod snapshot;
pub mod telemetry;

#[cfg(windows)]
pub mod proctree;
#[cfg(windows)]
pub mod registry;
#[cfg(windows)]
pub mod windows_native;

pub use error::SandboxError;
pub use policy::{Backend, SandboxPolicy};
pub use selftest::CheckState;

use crate::types::{Finding, Location, SandboxReport, Severity};
use std::path::Path;

/// Pick a backend according to `policy` and run `cmd` against `target`.
pub fn run(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
) -> Result<SandboxReport, SandboxError> {
    match resolve_backend(policy.backend)? {
        Backend::Docker => docker::run_sandbox(policy, cmd, target),
        Backend::Native => run_native(policy, cmd, target),
        Backend::Auto | Backend::None => unreachable!("resolve_backend never returns these"),
    }
}

fn resolve_backend(requested: Backend) -> Result<Backend, SandboxError> {
    match requested {
        Backend::Docker => {
            if docker::docker_available() {
                Ok(Backend::Docker)
            } else {
                Err(SandboxError::Unavailable(
                    "docker is not installed or not running".to_string(),
                ))
            }
        }
        Backend::Native => {
            if native_available() {
                Ok(Backend::Native)
            } else {
                Err(SandboxError::Unavailable(native_hint()))
            }
        }
        Backend::None => Err(SandboxError::Unavailable(
            "sandbox disabled by --sandbox-backend none".to_string(),
        )),
        Backend::Auto => {
            // Decision recorded in the plan (17.12): Docker stays the default
            // until the native backend passes `sandbox selftest`.
            if docker::docker_available() {
                Ok(Backend::Docker)
            } else if native_available() {
                Ok(Backend::Native)
            } else {
                Err(SandboxError::Unavailable(native_hint()))
            }
        }
    }
}

pub fn native_available() -> bool {
    #[cfg(windows)]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        linux_native::bwrap_available() || linux_native::firejail_available()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

fn native_hint() -> String {
    if cfg!(windows) {
        "no usable Windows sandbox backend".to_string()
    } else if cfg!(target_os = "linux") {
        "install bubblewrap or firejail, or use --sandbox-backend docker".to_string()
    } else {
        "native sandboxing is only supported on Windows and Linux".to_string()
    }
}

fn run_native(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
) -> Result<SandboxReport, SandboxError> {
    #[cfg(windows)]
    {
        windows_native::run_native(policy, cmd, target)
    }
    #[cfg(target_os = "linux")]
    {
        linux_native::run_native(policy, cmd, target)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (policy, cmd, target);
        Err(SandboxError::Unsupported(
            "native sandbox is only implemented for Windows and Linux".to_string(),
        ))
    }
}

/// Turn a sandbox run into findings. Shared by every backend so the rules and
/// severities stay consistent.
pub fn behavioral_findings(report: &SandboxReport) -> Vec<Finding> {
    let mut out = Vec::new();
    let target = "/work";
    if !report.files_created.is_empty() {
        out.push(finding(
            "sandbox.files-created",
            Severity::Medium,
            0.8,
            target,
            format!(
                "Sandbox created {} files: {}",
                report.files_created.len(),
                report.files_created.join(", ")
            ),
        ));
    }
    if !report.files_modified.is_empty() {
        out.push(finding(
            "sandbox.files-modified",
            Severity::Medium,
            0.8,
            target,
            format!("Sandbox modified {} files", report.files_modified.len()),
        ));
    }
    if !report.files_deleted.is_empty() {
        out.push(finding(
            "sandbox.files-deleted",
            Severity::Low,
            0.7,
            target,
            format!("Sandbox deleted {} files", report.files_deleted.len()),
        ));
    }
    if !report.network_indicators.is_empty() {
        out.push(finding(
            "sandbox.network-attempt",
            Severity::High,
            0.85,
            target,
            format!(
                "Sandbox detected network activity: {}",
                report.network_indicators.join(", ")
            ),
        ));
    }
    if !report.network_events.is_empty() {
        out.push(finding(
            "sandbox.network-event",
            Severity::High,
            0.85,
            target,
            format!(
                "Sandbox recorded {} network event(s)",
                report.network_events.len()
            ),
        ));
    }
    if !report.registry_changes.is_empty() {
        out.push(finding(
            "sandbox.registry-change",
            Severity::High,
            0.8,
            target,
            format!(
                "Sandbox changed {} registry key(s): {}",
                report.registry_changes.len(),
                report
                    .registry_changes
                    .iter()
                    .map(|c| c.key.as_str())
                    .take(8)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if !report.memory_dumps.is_empty() {
        out.push(finding(
            "sandbox.memory-dump",
            Severity::High,
            0.8,
            target,
            format!("Captured {} memory dump(s)", report.memory_dumps.len()),
        ));
    }
    if let Some(code) = report.exit_code {
        if code != 0 {
            out.push(finding(
                "sandbox.nonzero-exit",
                Severity::Low,
                0.5,
                target,
                format!("Sandbox command exited with code {}", code),
            ));
        }
    }
    if report.timed_out {
        out.push(finding(
            "sandbox.timeout",
            Severity::Low,
            0.6,
            target,
            "Sandbox command exceeded its time limit and was killed".to_string(),
        ));
    }
    if report.telemetry_degraded {
        out.push(finding(
            "sandbox.telemetry-degraded",
            Severity::Info,
            0.9,
            target,
            "Sandbox telemetry is degraded on this backend".to_string(),
        ));
    }
    out
}

fn finding(
    rule: &str,
    severity: Severity,
    confidence: f32,
    path: &str,
    message: String,
) -> Finding {
    Finding {
        id: format!("{}-{}", rule, path),
        severity,
        confidence,
        rule: rule.to_string(),
        category: "sandbox".to_string(),
        location: Location {
            path: path.to_string(),
            line: None,
            column: None,
        },
        message,
        snippet: None,
        tags: vec!["sandbox".to_string()],
    }
}
