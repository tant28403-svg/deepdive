//! Dump executable memory regions of a live sandboxed process so unpacked
//! payloads can be carved and rescanned.

#[cfg(windows)]
use crate::sandbox::telemetry::MemoryDump;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
const DEFAULT_BUDGET: u64 = 8 * 1024 * 1024;

/// Dump committed executable pages (RWX/RX) up to `budget` bytes total.
#[cfg(windows)]
pub fn dump_executable_regions(pid: u32, out_dir: &Path, budget: u64) -> Vec<MemoryDump> {
    use sha2::{Digest, Sha256};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut dumps = Vec::new();
    let Ok(handle) =
        (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) })
    else {
        return dumps;
    };

    // First pass: collect executable regions, largest first, so the budget is
    // spent on the most interesting pages.
    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut address = 0usize;
    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                handle,
                Some(address as *const core::ffi::c_void),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let base = info.BaseAddress as usize;
        let size = info.RegionSize;
        let executable = info.State == MEM_COMMIT
            && matches!(
                info.Protect,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );
        if executable && size >= 4096 {
            regions.push((base, size));
        }
        let next = base.saturating_add(size);
        if next <= address {
            break;
        }
        address = next;
    }
    regions.sort_by_key(|region| std::cmp::Reverse(region.1));

    let budget = if budget == 0 { DEFAULT_BUDGET } else { budget };
    let mut remaining = budget;
    for (base, size) in regions.into_iter().take(5) {
        if remaining == 0 {
            break;
        }
        let take = size.min(remaining as usize);
        let mut buffer = vec![0u8; take];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                base as *const core::ffi::c_void,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                take,
                Some(&mut read),
            )
        }
        .is_ok();
        if !ok || read == 0 {
            continue;
        }
        buffer.truncate(read);
        let path = out_dir.join(format!("mem-{}-{:x}.bin", pid, base));
        if std::fs::write(&path, &buffer).is_err() {
            continue;
        }
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        dumps.push(MemoryDump {
            pid,
            address: format!("0x{:x}", base),
            size: read as u64,
            path: path.to_string_lossy().to_string(),
            sha256: format!("{:x}", hasher.finalize()),
            reason: "executable-region".to_string(),
        });
        remaining = remaining.saturating_sub(read as u64);
    }

    let _ = unsafe { CloseHandle(handle) };
    dumps
}

/// Persistent directory for memory dumps.
#[cfg(windows)]
pub fn dump_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("deepdive-memdumps")
}
