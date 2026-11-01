use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "deepdive",
    version,
    about = "Reverse-engineer and safety-check repos/files before running them."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a local file or directory.
    Scan {
        /// Path to file or directory.
        path: PathBuf,
        /// Output format.
        #[arg(short, long, default_value = "text")]
        format: String,
        /// Write report to file.
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Minimum severity to report.
        #[arg(long, default_value = "info")]
        min_severity: String,
        /// Skip network queries.
        #[arg(long)]
        offline: bool,
        /// Include git history scan.
        #[arg(long)]
        deep: bool,
        /// Run in sandbox after static scan.
        #[arg(long)]
        sandbox: bool,
        /// Fail CI if severity reached.
        #[arg(long)]
        fail_on: Option<String>,
        /// Command to run in sandbox.
        #[arg(long)]
        sandbox_cmd: Option<String>,
        /// Skip files larger than this (MB).
        #[arg(long, default_value = "100")]
        max_size: u64,
        /// Parallelism.
        #[arg(long)]
        threads: Option<usize>,
        /// Extra rules file.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Disable colored output.
        #[arg(long)]
        no_color: bool,
    },
    /// Safely clone a remote repo, then scan it.
    Fetch {
        /// Repository URL.
        url: String,
        /// Branch to checkout.
        #[arg(long)]
        branch: Option<String>,
        /// Subdirectory to scan.
        #[arg(long)]
        path: Option<String>,
        /// Keep cloned repo at this path.
        #[arg(long)]
        keep: Option<PathBuf>,
        /// Clone submodules.
        #[arg(long)]
        submodules: bool,
    },
    /// Deep scan (history + optional sandbox).
    Audit {
        /// Path or URL.
        target: String,
        /// Sandbox command to run.
        #[arg(long)]
        sandbox_cmd: Option<String>,
        /// Run in sandbox after static scan.
        #[arg(long)]
        sandbox: bool,
        /// Fail CI if severity reached.
        #[arg(long)]
        fail_on: Option<String>,
    },
    /// Manage detection rules.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Manage offline cache.
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Generate shell completions.
    Completions {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print version.
    Version,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    List,
    Test { file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum CacheAction {
    Update,
    Clear,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Commands::Scan {
                path,
                max_size,
                format,
                out,
                min_severity,
                offline,
                deep,
                sandbox,
                sandbox_cmd,
                threads,
                rules,
                fail_on,
                no_color: _,
            } => {
                if let Some(n) = threads {
                    let _ = rayon::ThreadPoolBuilder::new()
                        .num_threads(n)
                        .build_global();
                }
                use crate::analysis::file_type;
                use crate::analysis::scan;
                use crate::analysis::walker;
                use crate::risk;
                use crate::types::{Finding, Severity};
                use std::collections::BTreeMap;

                let files = walker::walk_files(&path, max_size);
                let mut all_findings: Vec<Finding> = Vec::new();
                if path.is_dir() {
                    all_findings.extend(crate::analysis::symlinks::scan_root(&path));
                }
                let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                for f in &files {
                    let ft = file_type::detect(f);
                    *counts.entry(ft.as_str()).or_insert(0) += 1;
                    let findings = scan::read_and_scan(f);
                    all_findings.extend(findings);
                }

                // Dependency audit.
                let deps = crate::analysis::deps::collect_dependencies(&files);
                if !deps.is_empty() {
                    let dep_findings = crate::analysis::deps::audit_dependencies(&deps, offline);
                    all_findings.extend(dep_findings);
                }

                // Custom rules.
                if let Some(rp) = &rules {
                    let r = crate::analysis::rules::load_rules_file(rp);
                    for f in &files {
                        if let Ok(content) = std::fs::read_to_string(f) {
                            let rf = crate::analysis::rules::scan_with_rules(f, &content, &r);
                            all_findings.extend(rf);
                        }
                    }
                }

                // Git history (deep mode).
                if deep {
                    let hist = crate::analysis::git_history::scan_git_history(&path);
                    all_findings.extend(hist);
                }

                // Sandbox (opt-in).
                if sandbox || sandbox_cmd.is_some() {
                    let cmd = sandbox_cmd.clone().unwrap_or_else(|| "true".to_string());
                    let result = if crate::sandbox::docker::docker_available() {
                        let image = std::env::var("DEEPDIVE_SANDBOX_IMAGE")
                            .unwrap_or_else(|_| "ubuntu:22.04".to_string());
                        crate::sandbox::docker::run_sandbox(&cmd, &path, &image, 300)
                    } else if cfg!(windows) {
                        #[cfg(windows)]
                        {
                            crate::sandbox::windows_native::run_native(&cmd, &path, 300)
                        }
                        #[cfg(not(windows))]
                        {
                            Err(anyhow::anyhow!(
                                "Windows sandbox not available on this platform"
                            ))
                        }
                    } else if crate::sandbox::linux_native::bwrap_available()
                        || crate::sandbox::linux_native::firejail_available()
                    {
                        crate::sandbox::linux_native::run_native(&cmd, &path, 300)
                    } else {
                        Err(anyhow::anyhow!(
                            "no sandbox available (install docker, or bubblewrap/firejail on Linux)"
                        ))
                    };
                    match result {
                        Ok(report) => {
                            all_findings
                                .extend(crate::sandbox::docker::behavioral_findings(&report));
                            println!();
                            println!("[sandbox] image: {}", report.image);
                            println!("[sandbox] exit code: {:?}", report.exit_code);
                            println!("[sandbox] duration: {} ms", report.duration_ms);
                            println!("[sandbox] files created: {}", report.files_created.len());
                            println!("[sandbox] files modified: {}", report.files_modified.len());
                            println!(
                                "[sandbox] network indicators: {}",
                                report.network_indicators.len()
                            );
                            if !report.stdout.is_empty() {
                                println!("[sandbox stdout]\n{}", report.stdout);
                            }
                            if !report.stderr.is_empty() {
                                println!("[sandbox stderr]\n{}", report.stderr);
                            }
                        }
                        Err(e) => {
                            eprintln!("[sandbox] failed: {}", e);
                        }
                    }
                }

                // Filter by min_severity for reporting.
                let min_sev = match min_severity.to_lowercase().as_str() {
                    "critical" => Some(crate::types::Severity::Critical),
                    "high" => Some(crate::types::Severity::High),
                    "medium" => Some(crate::types::Severity::Medium),
                    "low" => Some(crate::types::Severity::Low),
                    _ => None,
                };
                if let Some(ms) = min_sev {
                    all_findings.retain(|f| f.severity >= ms);
                }

                let score = risk::score(&all_findings);
                let v = risk::verdict(score, &all_findings);

                if format == "json" {
                    let json = serde_json::to_string_pretty(&serde_json::json!({
                        "files_scanned": files.len(),
                        "risk_score": score,
                        "verdict": v.as_str(),
                        "findings": all_findings,
                    }))?;
                    if let Some(o) = out {
                        std::fs::write(o, json)?;
                    } else {
                        println!("{}", json);
                    }
                } else if format == "sarif" {
                    let s = crate::reporting::sarif::render(
                        &all_findings,
                        files.len(),
                        env!("CARGO_PKG_VERSION"),
                    );
                    if let Some(o) = out {
                        std::fs::write(o, s)?;
                    } else {
                        println!("{}", s);
                    }
                } else {
                    println!("deepdive scan: {}", path.display());
                    println!("files scanned: {}", files.len());
                    for (k, vv) in &counts {
                        println!("  {:<12} {}", k, vv);
                    }
                    println!();
                    println!("VERDICT: {}  (risk score {}/100)", v.as_str(), score);
                    println!();
                    let mut sorted = all_findings.clone();
                    sorted.sort_by_key(|a| std::cmp::Reverse(a.severity));
                    for f in &sorted {
                        println!(
                            "[{}] {} - {}",
                            f.severity.as_str().to_uppercase(),
                            f.rule,
                            f.location.path
                        );
                        if let Some(line) = f.location.line {
                            println!("  line {}: {}", line, f.message);
                        } else {
                            println!("  {}", f.message);
                        }
                        if let Some(snip) = &f.snippet {
                            println!("  > {}", snip);
                        }
                    }
                    println!();
                    let mut c = BTreeMap::new();
                    for f in &all_findings {
                        *c.entry(f.severity).or_insert(0usize) += 1;
                    }
                    println!(
                        "Summary: critical={}, high={}, medium={}, low={}, info={}",
                        c.get(&Severity::Critical).unwrap_or(&0),
                        c.get(&Severity::High).unwrap_or(&0),
                        c.get(&Severity::Medium).unwrap_or(&0),
                        c.get(&Severity::Low).unwrap_or(&0),
                        c.get(&Severity::Info).unwrap_or(&0),
                    );
                }
                // Exit code.
                let code = if let Some(threshold) = &fail_on {
                    let thr = match threshold.to_lowercase().as_str() {
                        "critical" => crate::types::Severity::Critical,
                        "high" => crate::types::Severity::High,
                        "medium" => crate::types::Severity::Medium,
                        "low" => crate::types::Severity::Low,
                        _ => crate::types::Severity::Info,
                    };
                    if all_findings.iter().any(|f| f.severity >= thr) {
                        2
                    } else {
                        0
                    }
                } else {
                    match v {
                        crate::types::Verdict::Safe => 0,
                        crate::types::Verdict::Review => 1,
                        _ => 2,
                    }
                };
                std::process::exit(code);
            }
            Commands::Fetch {
                url,
                branch,
                path: subdir,
                keep,
                submodules: _,
            } => {
                use crate::acquisition::git::safe_clone;
                use crate::acquisition::url::RepoUrl;

                let repo = RepoUrl::parse(&url)?;
                let dest = if let Some(k) = keep {
                    k.clone()
                } else {
                    std::env::temp_dir().join(format!("deepdive-{}", repo.repo))
                };
                println!("Cloning {} ...", repo.full_name());
                let scanned_path = safe_clone(&repo, &dest, branch.as_deref())?;
                println!("Cloned to {}", dest.display());

                // Now scan.
                // Reuse scan logic by invoking a recursive scan via analysis.
                use crate::analysis::file_type;
                use crate::analysis::scan;
                use crate::analysis::walker;
                use crate::risk;
                use crate::types::Finding;
                use std::collections::BTreeMap;

                let files = walker::walk_files(&scanned_path, 100);
                let mut all_findings: Vec<Finding> = Vec::new();
                if scanned_path.is_dir() {
                    all_findings.extend(crate::analysis::symlinks::scan_root(&scanned_path));
                }
                let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                for f in &files {
                    let ft = file_type::detect(f);
                    *counts.entry(ft.as_str()).or_insert(0) += 1;
                    all_findings.extend(scan::read_and_scan(f));
                }
                let deps = crate::analysis::deps::collect_dependencies(&files);
                if !deps.is_empty() {
                    all_findings.extend(crate::analysis::deps::audit_dependencies(&deps, false));
                }
                let score = risk::score(&all_findings);
                let v = risk::verdict(score, &all_findings);
                println!("files scanned: {}", files.len());
                println!("VERDICT: {}  (risk score {}/100)", v.as_str(), score);
                println!("Summary: {} findings", all_findings.len());
                let _ = subdir;
                Ok(())
            }
            Commands::Audit {
                target,
                sandbox_cmd,
                fail_on: _,
                sandbox: _,
            } => {
                use crate::analysis::file_type;
                use crate::analysis::scan;
                use crate::analysis::walker;
                use crate::risk;
                use crate::types::Finding;
                use std::collections::BTreeMap;
                use std::path::PathBuf;

                let path = PathBuf::from(&target);
                if !path.exists() {
                    println!("audit: target not found locally: {}", target);
                    println!("Hint: use 'deepdive fetch <url>' first, or pass a local path.");
                    return Ok(());
                }
                let files = walker::walk_files(&path, 100);
                let mut all_findings: Vec<Finding> = Vec::new();
                if path.is_dir() {
                    all_findings.extend(crate::analysis::symlinks::scan_root(&path));
                }
                let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
                for f in &files {
                    let ft = file_type::detect(f);
                    *counts.entry(ft.as_str()).or_insert(0) += 1;
                    all_findings.extend(scan::read_and_scan(f));
                }
                let deps = crate::analysis::deps::collect_dependencies(&files);
                if !deps.is_empty() {
                    all_findings.extend(crate::analysis::deps::audit_dependencies(&deps, false));
                }

                if let Some(cmd) = &sandbox_cmd {
                    let result = if crate::sandbox::docker::docker_available() {
                        let image = std::env::var("DEEPDIVE_SANDBOX_IMAGE")
                            .unwrap_or_else(|_| "ubuntu:22.04".to_string());
                        crate::sandbox::docker::run_sandbox(cmd, &path, &image, 300)
                    } else if cfg!(windows) {
                        #[cfg(windows)]
                        {
                            crate::sandbox::windows_native::run_native(cmd, &path, 300)
                        }
                        #[cfg(not(windows))]
                        {
                            Err(anyhow::anyhow!(
                                "Windows sandbox not available on this platform"
                            ))
                        }
                    } else if crate::sandbox::linux_native::bwrap_available()
                        || crate::sandbox::linux_native::firejail_available()
                    {
                        crate::sandbox::linux_native::run_native(cmd, &path, 300)
                    } else {
                        Err(anyhow::anyhow!(
                            "no sandbox available (install docker, or bubblewrap/firejail on Linux)"
                        ))
                    };
                    match result {
                        Ok(report) => {
                            all_findings
                                .extend(crate::sandbox::docker::behavioral_findings(&report));
                            println!("[sandbox] exit code: {:?}", report.exit_code);
                            println!("[sandbox] files created: {}", report.files_created.len());
                            println!("[sandbox] files modified: {}", report.files_modified.len());
                            if !report.network_indicators.is_empty() {
                                println!(
                                    "[sandbox] network: {}",
                                    report.network_indicators.join(", ")
                                );
                            }
                        }
                        Err(e) => eprintln!("[sandbox] failed: {}", e),
                    }
                }

                let score = risk::score(&all_findings);
                let v = risk::verdict(score, &all_findings);
                println!("deepdive audit: {}", path.display());
                println!("files scanned: {}", files.len());
                println!("VERDICT: {}  (risk score {}/100)", v.as_str(), score);
                println!("Summary: {} findings", all_findings.len());
                Ok(())
            }
            Commands::Rules { .. } => {
                println!("rules: not yet implemented");
                Ok(())
            }
            Commands::Cache { .. } => {
                println!("cache: not yet implemented");
                Ok(())
            }
            Commands::Completions { shell } => {
                use clap::CommandFactory;
                let mut cmd = Cli::command();
                clap_complete::generate(shell, &mut cmd, "deepdive", &mut std::io::stdout());
                Ok(())
            }
            Commands::Version => {
                println!("deepdive {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}
