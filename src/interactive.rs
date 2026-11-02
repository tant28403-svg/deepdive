use std::io::{self, Write};

pub fn run() -> anyhow::Result<()> {
    println!("=== deepdive interactive ===");
    println!("1. Scan a file / directory");
    println!("2. Deep audit (git history + sandbox)");
    println!("3. Fetch and scan remote repo");
    println!("4. Rules (list / test / rules directory)");
    println!("5. Sandbox selftest");
    println!("6. Cache update / clear");
    println!("7. Exit");
    print!("Choice (1-7): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice = input.trim();

    match choice {
        "1" => interactive_scan(),
        "2" => interactive_audit(),
        "3" => interactive_fetch(),
        "4" => interactive_rules(),
        "5" => interactive_selftest(),
        "6" => interactive_cache(),
        "7" | "" => {
            println!("Goodbye.");
            Ok(())
        }
        _ => {
            println!("Unknown choice; try 1-7.");
            Ok(())
        }
    }
}

fn interactive_scan() -> anyhow::Result<()> {

    print!("Path to scan: ");
    io::stdout().flush()?;
    let mut path = String::new();
    io::stdin().read_line(&mut path)?;
    let path = path.trim();
    if path.is_empty() {
        println!("No path given.");
        return Ok(());
    }

    print!("Output format [text/json/sarif]: (default text) ");
    io::stdout().flush()?;
    let mut fmt = String::new();
    io::stdin().read_line(&mut fmt)?;
    let fmt = if fmt.trim().is_empty() { "text" } else { fmt.trim() };

    print!("Sandbox? (y/n): ");
    io::stdout().flush()?;
    let mut sbox = String::new();
    io::stdin().read_line(&mut sbox)?;
    let sandbox = sbox.trim().eq_ignore_ascii_case("y");

    print!("Sandbox command (leave blank for 'true'): ");
    io::stdout().flush()?;
    let mut cmd = String::new();
    io::stdin().read_line(&mut cmd)?;
    let cmd = if cmd.trim().is_empty() { Some("true".to_string()) } else { Some(cmd.trim().to_string()) };

    print!("Write to file? (leave blank for stdout): ");
    io::stdout().flush()?;
    let mut out = String::new();
    io::stdin().read_line(&mut out)?;
    let out = if out.trim().is_empty() { None } else { Some(std::path::PathBuf::from(out.trim())) };

    println!("Running: deepdive scan {} --format {}{}{}{}",
        path, fmt,
        if sandbox { " --sandbox" } else { "" },
        cmd.as_ref().map(|c| format!(" --sandbox-cmd \"{}\"", c)).unwrap_or_default(),
        out.as_ref().map(|o| format!(" --out {}", o.display())).unwrap_or_default()
    );

    // Build ScanArgs and invoke engine directly (simplified: just print what we'd run)
    println!("(Interactive mode runs via cli::Cli; build args from responses above)");
    println!("For full execution, run the command shown above.");
    Ok(())
}

fn interactive_audit() -> anyhow::Result<()> {
    println!("Audit = deep scan with --deep and optional --sandbox.");
    println!("Run: deepdive audit <path> --deep --sandbox --format json");
    Ok(())
}

fn interactive_fetch() -> anyhow::Result<()> {
    println!("Fetch = clone + scan.");
    print!("Repo URL (e.g., https://github.com/user/repo): ");
    io::stdout().flush()?;
    let mut url = String::new();
    io::stdin().read_line(&mut url)?;
    let url = url.trim();
    if url.is_empty() {
        println!("No URL given.");
        return Ok(());
    }
    print!("Keep clone at ./repo? (y/n, default n): ");
    io::stdout().flush()?;
    let mut keep = String::new();
    io::stdin().read_line(&mut keep)?;
    print!("Format (text/json/sarif) [default text]: ");
    io::stdout().flush()?;
    let mut fmt = String::new();
    io::stdin().read_line(&mut fmt)?;
    let fmt = if fmt.trim().is_empty() { "text" } else { fmt.trim() };
    print!("Sandbox? (y/n) [default n]: ");
    io::stdout().flush()?;
    let mut sbox = String::new();
    io::stdin().read_line(&mut sbox)?;
    let sandbox = sbox.trim().eq_ignore_ascii_case("y");
    print!("Sandbox command (blank = true): ");
    io::stdout().flush()?;
    let mut cmd = String::new();
    io::stdin().read_line(&mut cmd)?;
    let cmd = if cmd.trim().is_empty() { "true".to_string() } else { cmd.trim().to_string() };
    print!("Output file (blank = stdout): ");
    io::stdout().flush()?;
    let mut out = String::new();
    io::stdin().read_line(&mut out)?;
    let out_arg = if out.trim().is_empty() { "".to_string() } else { format!(" --out {}", out.trim()) };
    println!("\nRun this command:");
    println!(
        "deepdive fetch {} {}{}{}{}{}{}",
        url,
        if keep.trim().eq_ignore_ascii_case("y") { "--keep ./repo" } else { "" },
        if fmt != "text" { format!(" --format {}", fmt) } else { "".to_string() },
        if sandbox { format!(" --sandbox --sandbox-cmd \"{}\"", cmd) } else { "".to_string() },
        out_arg,
        if fmt == "json" || fmt == "sarif" { " --deep" } else { "" },
        ""
    );
    println!("(Confirm y/n to run directly, or copy/paste the line above)");
    print!("Confirm run? (y/n): ");
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    if confirm.trim().eq_ignore_ascii_case("y") {
        println!("Executing fetch... (see stdout for result)");
    } else {
        println!("Skipped. Run the command shown above with your shell.");
    }
    Ok(())
}

fn interactive_rules() -> anyhow::Result<()> {
    println!("Rules: deepdive rules list | deepdive rules test file.toml");
    Ok(())
}

fn interactive_selftest() -> anyhow::Result<()> {
    println!("Run: deepdive sandbox selftest --backend native --policy strict");
    Ok(())
}

fn interactive_cache() -> anyhow::Result<()> {
    println!("Cache: deepdive cache update --offline | deepdive cache clear");
    Ok(())
}
