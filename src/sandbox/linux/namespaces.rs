//! Namespace, mount, and privilege setup for the native Linux sandbox.
//!
//! All of this runs inside `Command::pre_exec`, i.e. in the forked child just
//! before `exec`. Any failure aborts the spawn, which lets the caller fall back
//! to bubblewrap/firejail.

use caps::{clear, set, CapSet, Capability};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, getgid, getuid, pivot_root, setgid, setuid, Uid};
use std::io::Error;
use std::path::Path;

/// Enter the namespaces, build the new root, and drop privileges.
pub fn enter(
    target: &Path,
    root: &Path,
    unshare_net: bool,
    resolv: Option<&Path>,
) -> Result<(), Error> {
    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWIPC;
    if unshare_net {
        flags |= CloneFlags::CLONE_NEWNET;
    }
    unshare(flags).map_err(io_err)?;

    map_ids()?;
    setgid(nix::unistd::Gid::from_raw(0)).map_err(io_err)?;
    setuid(Uid::from_raw(0)).map_err(io_err)?;

    setup_root(target, root, resolv)?;

    Ok(())
}

/// Map the calling user to root inside the new user namespace.
fn map_ids() -> Result<(), Error> {
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    // Writing "deny" is required before gid_map for unprivileged users.
    let _ = std::fs::write("/proc/self/setgroups", "deny");
    std::fs::write("/proc/self/uid_map", format!("0 {} 1", uid))?;
    std::fs::write("/proc/self/gid_map", format!("0 {} 1", gid))?;
    Ok(())
}

/// Build a minimal root at `root` and pivot into it.
fn setup_root(target: &Path, root: &Path, resolv: Option<&Path>) -> Result<(), Error> {
    // Stop mount events escaping into the host namespace.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(io_err)?;

    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(io_err)?;

    for dir in [
        "usr", "lib", "lib64", "bin", "sbin", "etc", "dev", "proc", "tmp", "work", "oldroot",
    ] {
        let _ = std::fs::create_dir_all(root.join(dir));
    }

    // Read-only binds of the system toolchain.
    for dir in ["usr", "lib", "lib64", "bin", "sbin", "etc"] {
        let source = Path::new("/").join(dir);
        if !source.exists() {
            continue;
        }
        let dest = root.join(dir);
        mount(
            Some(&source),
            &dest,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(io_err)?;
        mount(
            Some(&source),
            &dest,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(io_err)?;
    }

    if let Some(resolv) = resolv {
        let target = root.join("etc/resolv.conf");
        if target.exists() {
            mount(
                Some(resolv),
                &target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(io_err)?;
        }
    }

    if Path::new("/dev").exists() {
        let dev_dest = root.join("dev");
        mount(
            Some("/dev"),
            &dev_dest,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(io_err)?;
    }
    let proc_dest = root.join("proc");
    mount(
        Some("proc"),
        &proc_dest,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(io_err)?;
    let tmp_dest = root.join("tmp");
    mount(
        Some("tmpfs"),
        &tmp_dest,
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(io_err)?;

    // The scanned workspace, writable.
    let work_dest = root.join("work");
    mount(
        Some(target),
        &work_dest,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(io_err)?;

    let old_root = root.join("oldroot");
    pivot_root(root, &old_root).map_err(io_err)?;
    chdir("/")?;
    let _ = umount2("/oldroot", MntFlags::MNT_DETACH);

    // No new privileges and no capabilities.
    set_no_new_privs();
    drop_capabilities();

    Ok(())
}

fn set_no_new_privs() {
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
}

fn drop_capabilities() {
    // Clear all capability sets using the caps crate.
    // CapSet::Effective, CapSet::Permitted, CapSet::Inheritable are the three sets.
    let _ = clear(CapSet::Effective);
    let _ = clear(CapSet::Permitted);
    let _ = clear(CapSet::Inheritable);
    // Apply the cleared sets to the current process
    let _ = set(None, CapSet::Effective);
    let _ = set(None, CapSet::Permitted);
    let _ = set(None, CapSet::Inheritable);
}

fn io_err(err: nix::Error) -> Error {
    Error::other(err.to_string())
}
