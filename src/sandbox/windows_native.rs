use crate::types::SandboxReport;
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Instant;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
};

pub fn run_native(cmd: &str, target: &Path, timeout_secs: u64) -> Result<SandboxReport> {
    let mut report = SandboxReport {
        command: cmd.to_string(),
        image: "windows-native".to_string(),
        ..Default::default()
    };

    // Snapshot before.
    let before = snapshot_dir(target);

    // Create job object.
    let job = unsafe { CreateJobObjectW(None, None).context("CreateJobObject")? };

    // Set limits.
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.ProcessMemoryLimit = 512 * 1024 * 1024; // 512 MB
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .context("SetInformationJobObject")?;
    }

    // Build command line: cmd /c <cmd>, with working dir = target.
    let full_cmd = format!("cmd.exe /c {}", cmd);
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

    // Assign to job.
    unsafe {
        AssignProcessToJobObject(job, pi.hProcess).context("AssignProcessToJobObject")?;
    }

    // Resume.
    unsafe {
        ResumeThread(pi.hThread);
    }

    // Wait with timeout.
    let timeout_ms = (timeout_secs * 1000) as u32;
    let wait =
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(pi.hProcess, timeout_ms) };
    // WAIT_TIMEOUT = 0x00000102
    if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
        }
        report.stderr.push_str("\n[timeout exceeded]");
    }

    // Exit code.
    let mut code: u32 = 0;
    unsafe {
        let _ = windows::Win32::System::Threading::GetExitCodeProcess(pi.hProcess, &mut code);
    }
    report.exit_code = Some(code as i32);
    report.duration_ms = start.elapsed().as_millis() as u64;

    // Cleanup handles.
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(job);
    }

    // Snapshot after.
    let after = snapshot_dir(target);
    diff_snapshots(&before, &after, &mut report);

    Ok(report)
}

fn snapshot_dir(root: &Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;
    let mut map = std::collections::BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let hash = std::fs::read(path)
            .map(|b| {
                let mut h = Sha256::new();
                h.update(&b);
                format!("{:x}", h.finalize())
            })
            .unwrap_or_default();
        map.insert(rel, hash);
    }
    map
}

fn diff_snapshots(
    before: &std::collections::BTreeMap<String, String>,
    after: &std::collections::BTreeMap<String, String>,
    report: &mut SandboxReport,
) {
    for (k, v) in after {
        match before.get(k) {
            None => report.files_created.push(k.clone()),
            Some(prev) if prev != v => report.files_modified.push(k.clone()),
            _ => {}
        }
    }
    for k in before.keys() {
        if !after.contains_key(k) {
            report.files_deleted.push(k.clone());
        }
    }
}
