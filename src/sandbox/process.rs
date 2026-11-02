use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub struct Completed {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub duration: Duration,
}

/// Spawn a command, capture its output through temp files, and kill it once the
/// deadline passes. `on_timeout` runs before the kill so callers can tear down
/// containers or process groups.
pub fn run_with_timeout<F>(
    mut command: Command,
    timeout: Duration,
    mut on_timeout: F,
) -> std::io::Result<Completed>
where
    F: FnMut(&mut Child),
{
    let io_dir = tempfile::tempdir()?;
    let out_path = io_dir.path().join("stdout");
    let err_path = io_dir.path().join("stderr");
    let out_file = File::create(&out_path)?;
    let err_file = File::create(&err_path)?;

    command
        .stdout(Stdio::from(out_file))
        .stderr(Stdio::from(err_file));

    let start = Instant::now();
    let mut child = command.spawn()?;
    let mut timed_out = false;

    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            on_timeout(&mut child);
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let status = child.try_wait()?;
    let exit_code = status.and_then(|s| s.code());

    Ok(Completed {
        exit_code,
        stdout: read_file(&out_path),
        stderr: read_file(&err_path),
        timed_out,
        duration: start.elapsed(),
    })
}

fn read_file(path: &std::path::Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Ok(mut file) = File::open(path) {
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.read_to_end(&mut bytes);
    }
    bytes
}
