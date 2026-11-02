pub mod docker;
pub mod linux_native;

#[cfg(windows)]
pub mod windows_native;

use crate::types::SandboxReport;
use anyhow::Result;
use std::path::Path;

/// Pick the best available sandbox backend and run `cmd` against `target`.
pub fn run(cmd: &str, target: &Path, timeout_secs: u64) -> Result<SandboxReport> {
    if docker::docker_available() {
        let image =
            std::env::var("DEEPDIVE_SANDBOX_IMAGE").unwrap_or_else(|_| "ubuntu:22.04".to_string());
        return docker::run_sandbox(cmd, target, &image, timeout_secs);
    }
    if cfg!(windows) {
        #[cfg(windows)]
        {
            return windows_native::run_native(cmd, target, timeout_secs);
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("Windows sandbox is not available on this platform");
        }
    }
    if linux_native::bwrap_available() || linux_native::firejail_available() {
        return linux_native::run_native(cmd, target, timeout_secs);
    }
    anyhow::bail!("no sandbox available (install Docker, or bubblewrap/firejail on Linux)")
}
