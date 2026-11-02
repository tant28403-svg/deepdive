#[cfg(windows)]
use crate::sandbox::policy::SandboxPolicy;
#[cfg(windows)]
use crate::sandbox::snapshot;
#[cfg(windows)]
use crate::sandbox::{CaptureContext, SandboxError};
#[cfg(windows)]
use crate::types::SandboxReport;
#[cfg(windows)]
use anyhow::Context;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use std::time::Instant;
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

#[cfg(windows)]
pub fn run_native(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
    capture: Option<&CaptureContext>,
) -> Result<SandboxReport, SandboxError> {
    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: "windows-native".to_string(),
        backend: "windows-native".to_string(),
        policy: policy.clone(),
        // ETW/registry telemetry lands in stage 19.
        telemetry_degraded: true,
        ..Default::default()
    };

    let before = snapshot::capture(target);
    let processes_before = crate::sandbox::proctree::snapshot();
    let registry_before = crate::sandbox::registry::capture_persistence();

    let job = unsafe { CreateJobObjectW(None, None) }.context("CreateJobObject")?;

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.BasicLimitInformation.ActiveProcessLimit = policy.pids.max(1);
    info.ProcessMemoryLimit = policy.memory_mb.saturating_mul(1024 * 1024) as usize;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("SetInformationJobObject")?;
    }

    let full_cmd = {
        let io_dir = tempfile::tempdir().context("create sandbox io dir")?;
        let out_path = io_dir.path().join("stdout.txt");
        let err_path = io_dir.path().join("stderr.txt");
        let full = format!(
            "cmd.exe /c {} > \"{}\" 2> \"{}\"",
            cmd,
            out_path.display(),
            err_path.display()
        );
        (full, io_dir, out_path, err_path)
    };
    let (full_cmd, io_dir, out_path, err_path) = full_cmd;
    let cwd_wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut cmd_wide: Vec<u16> = OsStr::new(&full_cmd).encode_wide().chain(Some(0)).collect();
    let mut environment = environment_block(policy, capture);

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let start = Instant::now();
    unsafe {
        CreateProcessW(
            None,
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_mut_ptr() as *const core::ffi::c_void),
            windows::core::PCWSTR(cwd_wide.as_ptr()),
            &si,
            &mut pi,
        )
        .context("CreateProcessW")?;
    }

    unsafe {
        AssignProcessToJobObject(job, pi.hProcess).context("AssignProcessToJobObject")?;
    }

    unsafe {
        ResumeThread(pi.hThread);
    }

    // Watch the job for short-lived children and dump executable memory while
    // they are still alive.
    let monitor = Monitor::start(pi.dwProcessId);

    let timeout_ms = policy.timeout_secs.saturating_mul(1000) as u32;
    let wait =
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(pi.hProcess, timeout_ms) };
    report.timed_out = wait == windows::Win32::Foundation::WAIT_TIMEOUT;
    if report.timed_out {
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
        }
        report.stderr.push_str("\n[timeout exceeded]");
    }

    let mut code: u32 = 0;
    unsafe {
        let _ = windows::Win32::System::Threading::GetExitCodeProcess(pi.hProcess, &mut code);
    }
    report.exit_code = Some(code as i32);
    report.duration_ms = start.elapsed().as_millis() as u64;
    report.stdout = std::fs::read_to_string(&out_path).unwrap_or_default();
    report.stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
    drop(io_dir);

    // Collect what the monitor saw, then sample the process list while the job
    // is still open so live children are visible before it is torn down.
    let (mut monitored, dumps) = monitor.stop();
    let processes_after = crate::sandbox::proctree::snapshot();
    let mut seen: std::collections::HashSet<u32> = monitored.iter().map(|p| p.pid).collect();
    for process in crate::sandbox::proctree::spawned_since(&processes_before, &processes_after) {
        if seen.insert(process.pid) {
            monitored.push(process);
        }
    }
    report.process_tree = monitored;
    report.memory_dumps = dumps;
    let registry_after = crate::sandbox::registry::capture_persistence();
    report.registry_changes = crate::sandbox::registry::diff(&registry_before, &registry_after);

    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(job);
    }

    let after = snapshot::capture(target);
    let diff = snapshot::diff(&before, &after);
    report.files_created = diff.created;
    report.files_modified = diff.modified;
    report.files_deleted = diff.deleted;

    let combined = format!("{}\n{}", report.stdout, report.stderr).to_lowercase();
    for pattern in [
        "connection refused",
        "connection timed out",
        "no such host",
        "network is unreachable",
        "no route to host",
    ] {
        if combined.contains(pattern) {
            report.network_indicators.push(pattern.to_string());
        }
    }

    Ok(report)
}

/// Polls the process list while a job runs, recording sandbox descendants and
/// dumping executable memory from the ones that are still alive.
#[cfg(windows)]
struct Monitor {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    events: std::sync::Arc<std::sync::Mutex<Vec<crate::sandbox::telemetry::ProcessEvent>>>,
    dumps: std::sync::Arc<std::sync::Mutex<Vec<crate::sandbox::telemetry::MemoryDump>>>,
}

#[cfg(windows)]
impl Monitor {
    fn start(root_pid: u32) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let dumps = Arc::new(Mutex::new(Vec::new()));

        let thread_stop = stop.clone();
        let thread_events = events.clone();
        let thread_dumps = dumps.clone();
        let handle = std::thread::spawn(move || {
            let dir = crate::sandbox::memory::dump_dir();
            let _ = std::fs::create_dir_all(&dir);
            let mut sandbox_pids: std::collections::HashSet<u32> =
                std::collections::HashSet::from([root_pid]);
            let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
            let mut dumped = 0u32;

            while !thread_stop.load(Ordering::Relaxed) {
                let snapshot = crate::sandbox::proctree::snapshot();
                // Expand the sandbox set transitively (children can appear in
                // any order across polls).
                let mut changed = true;
                while changed {
                    changed = false;
                    for process in &snapshot {
                        if let Some(parent) = process.parent_pid {
                            if sandbox_pids.contains(&parent)
                                && !sandbox_pids.contains(&process.pid)
                            {
                                sandbox_pids.insert(process.pid);
                                changed = true;
                            }
                        }
                    }
                }

                for process in &snapshot {
                    if !sandbox_pids.contains(&process.pid)
                        || process.pid == root_pid
                        || !seen.insert(process.pid)
                    {
                        continue;
                    }
                    if let Ok(mut guard) = thread_events.lock() {
                        guard.push(process.clone());
                    }
                    if dumped < 20 {
                        dumped += 1;
                        let found = crate::sandbox::memory::dump_executable_regions(
                            process.pid,
                            &dir,
                            8 * 1024 * 1024,
                        );
                        if !found.is_empty() {
                            if let Ok(mut guard) = thread_dumps.lock() {
                                guard.extend(found);
                            }
                        }
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(75));
            }
        });

        Self {
            stop,
            handle: Some(handle),
            events,
            dumps,
        }
    }

    fn stop(
        mut self,
    ) -> (
        Vec<crate::sandbox::telemetry::ProcessEvent>,
        Vec<crate::sandbox::telemetry::MemoryDump>,
    ) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let events = self
            .events
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        let dumps = self
            .dumps
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        (events, dumps)
    }
}

/// Build a UTF-16 environment block. When scrubbing, only the variables a
/// shell and toolchain need are kept; capture proxy variables are always added.
#[cfg(windows)]
fn environment_block(policy: &SandboxPolicy, capture: Option<&CaptureContext>) -> Vec<u16> {
    const ALWAYS_KEEP: &[&str] = &[
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "COMSPEC",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PROCESSOR_ARCHITECTURE",
    ];

    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| {
            !policy.env_scrub
                || ALWAYS_KEEP
                    .iter()
                    .any(|keep| key.eq_ignore_ascii_case(keep))
        })
        .filter(|(key, _)| !key.to_ascii_uppercase().ends_with("_PROXY"))
        .collect();

    if let Some(context) = capture {
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
        ] {
            vars.push((name.to_string(), context.proxy_url.clone()));
        }
        vars.push((
            "NO_PROXY".to_string(),
            "localhost,127.0.0.1,::1".to_string(),
        ));
    }

    let mut block = Vec::new();
    for (key, value) in vars {
        for unit in format!("{}={}", key, value).encode_utf16() {
            block.push(unit);
        }
        block.push(0);
    }
    block.push(0);
    block
}
