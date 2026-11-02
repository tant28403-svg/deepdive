//! seccomp-BPF deny list. The filter is installed last, after namespaces and
//! mounts are set up, so the setup syscalls are still available.

use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

/// Syscalls that a sandboxed build/test run should never need. Blocking these
/// stops the obvious escapes (new mounts, namespaces, kernel modules, tracing
/// other processes) while leaving normal toolchains working.
fn denied_syscalls() -> Vec<i64> {
    use libc::*;
    let candidates = [
        SYS_mount,
        SYS_umount2,
        SYS_ptrace,
        SYS_kexec_load,
        SYS_kexec_file_load,
        SYS_init_module,
        SYS_finit_module,
        SYS_delete_module,
        SYS_bpf,
        SYS_perf_event_open,
        SYS_userfaultfd,
        SYS_io_uring_setup,
        SYS_io_uring_enter,
        SYS_io_uring_register,
        SYS_setns,
        SYS_unshare,
        SYS_add_key,
        SYS_keyctl,
        SYS_request_key,
        SYS_open_by_handle_at,
        SYS_name_to_handle_at,
        SYS_process_vm_readv,
        SYS_process_vm_writev,
        SYS_personality,
        SYS_quotactl,
        SYS_acct,
        SYS_reboot,
        SYS_swapon,
        SYS_swapoff,
        SYS_fanotify_init,
        SYS_lookup_dcookie,
        SYS_settimeofday,
        SYS_adjtimex,
        SYS_clock_adjtime,
    ];
    candidates.to_vec()
}

fn target_arch() -> seccompiler::TargetArch {
    #[cfg(target_arch = "x86_64")]
    {
        seccompiler::TargetArch::x86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        seccompiler::TargetArch::aarch64
    }
}

pub fn apply() -> Result<(), Box<dyn std::error::Error>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for syscall in denied_syscalls() {
        rules.insert(syscall, vec![]);
    }

    let filter: seccompiler::BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch(),
    )?
    .try_into()?;

    seccompiler::apply_filter(&filter)?;
    Ok(())
}
