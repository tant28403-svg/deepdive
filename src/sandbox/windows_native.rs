#[cfg(windows)]
use crate::sandbox::policy::SandboxPolicy;
#[cfg(windows)]
use crate::sandbox::snapshot;
#[cfg(windows)]
use crate::sandbox::SandboxError;
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
    CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

#[cfg(windows)]
pub fn run_native(
    policy: &SandboxPolicy,
    cmd: &str,
    target: &Path,
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
            CREATE_SUSPENDED,
            None,
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
