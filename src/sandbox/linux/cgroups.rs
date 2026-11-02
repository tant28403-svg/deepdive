//! Best-effort cgroup v2 limits for sandboxed runs. When the cgroup tree is not
//! delegated to the user, limits are skipped rather than failing the run.

use crate::sandbox::policy::SandboxPolicy;
use std::path::{Path, PathBuf};

pub struct Cgroup {
    path: PathBuf,
}

pub fn create(policy: &SandboxPolicy) -> Option<Cgroup> {
    let base = Path::new("/sys/fs/cgroup");
    if !base.join("cgroup.controllers").exists() {
        return None;
    }
    let path = base.join(format!("deepdive-{}-{}", std::process::id(), nanos()));
    if std::fs::create_dir_all(&path).is_err() {
        return None;
    }

    let memory_bytes = policy.memory_mb.saturating_mul(1024 * 1024);
    let _ = std::fs::write(path.join("memory.max"), memory_bytes.to_string());
    let _ = std::fs::write(path.join("memory.swap.max"), "0");
    let _ = std::fs::write(path.join("pids.max"), policy.pids.max(1).to_string());
    if policy.cpus > 0.0 {
        let quota = (policy.cpus * 100_000.0).round() as u64;
        let _ = std::fs::write(path.join("cpu.max"), format!("{} 100000", quota));
    }

    Some(Cgroup { path })
}

impl Cgroup {
    /// Move the sandboxed process (and therefore its children) into the group.
    pub fn add_pid(&self, pid: u32) {
        let _ = std::fs::write(self.path.join("cgroup.procs"), pid.to_string());
    }

    /// Kill every process left in the group.
    pub fn kill(&self) {
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
    }

    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
