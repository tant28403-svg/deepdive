use crate::sandbox::error::SandboxError;
use crate::sandbox::policy::SandboxPolicy;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone)]
pub struct SelftestCheck {
    pub name: String,
    pub state: CheckState,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct SelftestOutcome {
    pub backend: String,
    pub passed: bool,
    pub checks: Vec<SelftestCheck>,
}

/// Run a small set of escape probes through the configured backend.
///
/// The probes prove that the workspace is writable and that writes outside it
/// are confined. A backend that cannot confine filesystem writes is reported as
/// a warning rather than a failure until the native backends land (stage 19).
pub fn run(policy: &SandboxPolicy) -> Result<SelftestOutcome, SandboxError> {
    let workspace = tempfile::tempdir().map_err(SandboxError::Io)?;
    let command = write_probe(workspace.path())?;

    let report = super::run(policy, &command, workspace.path())?;
    let output = format!("{}\n{}", report.stdout, report.stderr);

    let mut checks = Vec::new();

    let started = output.contains("SELFTEST:start");
    checks.push(check(
        "probe started",
        started,
        "sandbox executed the probe command",
    ));

    let inside = output.contains("SELFTEST:inside=ok");
    checks.push(check(
        "workspace writable",
        inside,
        "sandbox could write inside the workspace",
    ));

    let outside_allowed = output.contains("SELFTEST:outside=allowed");
    checks.push(if outside_allowed {
        if cfg!(windows) {
            SelftestCheck {
                name: "filesystem confinement".to_string(),
                state: CheckState::Warn,
                detail: "native Windows backend does not yet confine writes outside the workspace"
                    .to_string(),
            }
        } else {
            SelftestCheck {
                name: "filesystem confinement".to_string(),
                state: CheckState::Fail,
                detail: "write outside the workspace was allowed".to_string(),
            }
        }
    } else {
        SelftestCheck {
            name: "filesystem confinement".to_string(),
            state: CheckState::Pass,
            detail: "write outside the workspace was blocked".to_string(),
        }
    });

    let done = output.contains("SELFTEST:done");
    checks.push(check("probe finished", done, "sandbox command completed"));

    if report.timed_out {
        checks.push(SelftestCheck {
            name: "timeout".to_string(),
            state: CheckState::Fail,
            detail: "the probe hit the sandbox timeout".to_string(),
        });
    }

    let passed = checks.iter().all(|c| c.state != CheckState::Fail);
    Ok(SelftestOutcome {
        backend: report.backend,
        passed,
        checks,
    })
}

/// Write the platform probe script into the workspace and return the command
/// that runs it. Using a script keeps quoting out of the picture so output
/// capture stays reliable on every backend.
fn write_probe(workspace: &Path) -> Result<String, SandboxError> {
    #[cfg(windows)]
    {
        let script = "\
@echo off
echo SELFTEST:start
echo ok> inside.txt
if exist inside.txt (echo SELFTEST:inside=ok) else (echo SELFTEST:inside=fail)
echo x> \"%TEMP%\\deepdive-selftest.txt\" 2>nul && echo SELFTEST:outside=allowed || echo SELFTEST:outside=blocked
echo SELFTEST:done
";
        std::fs::write(workspace.join("probe.cmd"), script).map_err(SandboxError::Io)?;
        Ok("probe.cmd".to_string())
    }
    #[cfg(not(windows))]
    {
        let script = "\
#!/bin/sh
echo SELFTEST:start
echo ok > inside.txt && echo SELFTEST:inside=ok || echo SELFTEST:inside=fail
if echo x > /etc/deepdive-selftest 2>/dev/null; then echo SELFTEST:outside=allowed; rm -f /etc/deepdive-selftest; else echo SELFTEST:outside=blocked; fi
echo SELFTEST:done
";
        std::fs::write(workspace.join("probe.sh"), script).map_err(SandboxError::Io)?;
        Ok("sh probe.sh".to_string())
    }
}

fn check(name: &str, ok: bool, detail: &str) -> SelftestCheck {
    SelftestCheck {
        name: name.to_string(),
        state: if ok {
            CheckState::Pass
        } else {
            CheckState::Fail
        },
        detail: detail.to_string(),
    }
}
