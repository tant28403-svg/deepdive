//! Windows process enumeration used to build a coarse process tree for sandbox
//! runs. A full ETW session is scheduled for a later stage; this Toolhelp
//! snapshot already surfaces short-lived child processes through a before/after
//! diff.

#[cfg(windows)]
use crate::sandbox::telemetry::{ProcessEvent, ProcessEventKind};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

#[cfg(windows)]
pub fn snapshot() -> Vec<ProcessEvent> {
    let mut out = Vec::new();
    let handle = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(handle) => handle,
        Err(_) => return out,
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    if unsafe { Process32FirstW(handle, &mut entry) }.is_ok() {
        loop {
            out.push(to_event(&entry));
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if unsafe { Process32NextW(handle, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
    out
}

#[cfg(windows)]
fn to_event(entry: &PROCESSENTRY32W) -> ProcessEvent {
    let end = entry
        .szExeFile
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(entry.szExeFile.len());
    let image = String::from_utf16_lossy(&entry.szExeFile[..end]);
    ProcessEvent {
        pid: entry.th32ProcessID,
        parent_pid: Some(entry.th32ParentProcessID),
        image: Some(image),
        command_line: None,
        kind: ProcessEventKind::Spawn,
        timestamp_ms: 0,
    }
}

/// Processes present in `after` but not in `before`.
#[cfg(windows)]
pub fn spawned_since(before: &[ProcessEvent], after: &[ProcessEvent]) -> Vec<ProcessEvent> {
    let known: std::collections::HashSet<u32> = before.iter().map(|p| p.pid).collect();
    after
        .iter()
        .filter(|p| !known.contains(&p.pid))
        .cloned()
        .collect()
}

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    fn event(pid: u32) -> ProcessEvent {
        ProcessEvent {
            pid,
            ..Default::default()
        }
    }

    #[test]
    fn detects_only_new_pids() {
        let spawned = spawned_since(&[event(1), event(2)], &[event(2), event(3), event(4)]);
        let mut pids: Vec<u32> = spawned.iter().map(|p| p.pid).collect();
        pids.sort_unstable();
        assert_eq!(pids, vec![3, 4]);
    }

    #[test]
    fn snapshot_contains_this_process() {
        let current = std::process::id();
        let procs = snapshot();
        assert!(procs.iter().any(|p| p.pid == current));
    }
}
