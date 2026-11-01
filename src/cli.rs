use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::engine;

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

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Output format: text, json, or sarif.
    #[arg(short, long, default_value = "text")]
    pub format: String,
    /// Write the report to a file instead of stdout.
    #[arg(short, long)]
    pub out: Option<PathBuf>,
    /// Minimum severity to report (display only; verdict still uses all findings).
    #[arg(long, default_value = "info")]
    pub min_severity: String,
    /// Skip network queries (uses the local cache).
    #[arg(long)]
    pub offline: bool,
    /// Include git history scanning.
    #[arg(long)]
    pub deep: bool,
    /// Run the target in a sandbox after the static scan.
    #[arg(long)]
    pub sandbox: bool,
    /// Command to run in the sandbox (never invented by deepdive).
    #[arg(long)]
    pub sandbox_cmd: Option<String>,
    /// Skip files larger than this (MB).
    #[arg(long, default_value_t = 100)]
    pub max_size: u64,
    /// Parallelism (defaults to the number of CPUs).
    #[arg(long)]
    pub threads: Option<usize>,
    /// Extra TOML rules file.
    #[arg(long)]
    pub rules: Option<PathBuf>,
    /// Exit with code 2 if any finding reaches this severity.
    #[arg(long)]
    pub fail_on: Option<String>,
    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,
    /// Emit a Software Bill of Materials instead of a scan report.
    #[arg(long, value_name = "FORMAT", value_parser = ["cyclonedx", "spdx"])]
    pub sbom: Option<String>,
}

impl From<&ScanArgs> for engine::Options {
    fn from(args: &ScanArgs) -> Self {
        engine::Options {
            format: args.format.clone(),
            out: args.out.clone(),
            min_severity: args.min_severity.clone(),
            offline: args.offline,
            deep: args.deep,
            sandbox: args.sandbox,
            sandbox_cmd: args.sandbox_cmd.clone(),
            max_size: args.max_size,
            threads: args.threads,
            rules: args.rules.iter().cloned().collect(),
            fail_on: args.fail_on.clone(),
            no_color: args.no_color,
            sbom: args.sbom.clone(),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a local file or directory.
    Scan {
        /// Path to file or directory.
        path: PathBuf,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Safely clone a remote repo, then scan it.
    Fetch {
        /// Repository URL.
        url: String,
        /// Branch to checkout.
        #[arg(long)]
        branch: Option<String>,
        /// Subdirectory to scan (relative to the repository root).
        #[arg(long)]
        path: Option<String>,
        /// Keep the cloned repo at this path.
        #[arg(long)]
        keep: Option<PathBuf>,
        /// Clone submodules (disabled by default).
        #[arg(long)]
        submodules: bool,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Deep scan (git history + optional sandbox).
    Audit {
        /// Local path or repository URL.
        target: String,
        /// Keep the cloned repo at this path (URL targets only).
        #[arg(long)]
        keep: Option<PathBuf>,
        #[command(flatten)]
        opts: ScanArgs,
    },
    /// Manage detection rules.
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Manage the offline cache.
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
    /// List built-in rule ids and user rules.
    List,
    /// Validate a TOML rule file and show its rules.
    Test { file: PathBuf },
}

#[derive(Subcommand, Debug)]
pub enum CacheAction {
    /// Create the cache directory and describe what is cached.
    Update,
    /// Delete all cached data.
    Clear,
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Commands::Scan { path, opts } => {
                let code = engine::execute(&path, &engine::Options::from(&opts))?;
                std::process::exit(code);
            }
            Commands::Fetch {
                url,
                branch,
                path,
                keep,
                submodules,
                opts,
            } => {
                let (scanned, temp) = clone_repo(&url, branch.as_deref(), &keep, submodules)?;
                let target = match path {
                    Some(subdir) => {
                        let joined = scanned.join(&subdir);
                        if !joined.exists() {
                            anyhow::bail!("subdirectory not found in repository: {}", subdir);
                        }
                        joined
                    }
                    None => scanned,
                };
                let code = engine::execute(&target, &engine::Options::from(&opts))?;
                if let Some(dir) = temp {
                    drop(dir);
                }
                std::process::exit(code);
            }
            Commands::Audit { target, keep, opts } => {
                let local = PathBuf::from(&target);
                let (scan_path, temp) = if local.exists() {
                    (local, None)
                } else {
                    clone_repo(&target, None, &keep, false)?
                };
                if !scan_path.exists() {
                    anyhow::bail!(
                        "target not found locally or as a repository URL: {}",
                        target
                    );
                }
                let mut options = engine::Options::from(&opts);
                options.deep = true;
                let code = engine::execute(&scan_path, &options)?;
                if let Some(dir) = temp {
                    drop(dir);
                }
                std::process::exit(code);
            }
            Commands::Rules { action } => run_rules(action),
            Commands::Cache { action } => run_cache(action),
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

fn clone_repo(
    url: &str,
    branch: Option<&str>,
    keep: &Option<PathBuf>,
    submodules: bool,
) -> Result<(PathBuf, Option<tempfile::TempDir>)> {
    use crate::acquisition::git::safe_clone;
    use crate::acquisition::url::RepoUrl;

    let repo = RepoUrl::parse(url)?;
    let (dest, temp) = match keep {
        Some(path) => (path.clone(), None),
        None => {
            let temp = tempfile::tempdir().context("create temp clone dir")?;
            (temp.path().join(&repo.repo), Some(temp))
        }
    };
    println!("Cloning {} ...", repo.full_name());
    let scanned = safe_clone(&repo, &dest, branch, submodules)?;
    println!("Cloned to {}", dest.display());
    Ok((scanned, temp))
}

fn run_rules(action: RulesAction) -> Result<()> {
    use crate::analysis::rules;
    use crate::analysis::sigma;
    use crate::analysis::yara;
    use crate::config;

    match action {
        RulesAction::List => {
            println!("Built-in rules ({}):", rules::builtin_rule_ids().len());
            for id in rules::builtin_rule_ids() {
                println!("  {}", id);
            }
            println!();
            println!(
                "YARA support: {}",
                if yara::YaraRules::available() {
                    "enabled"
                } else {
                    "not compiled (rebuild with --features yara)"
                }
            );
            if let Some(dir) = config::rules_dir() {
                println!();
                println!("User rules directory: {}", dir.display());
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        let ext = path
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("")
                            .to_lowercase();
                        match ext.as_str() {
                            "toml" => {
                                let custom = rules::load_rules_file(&path);
                                println!("  {} ({} TOML rule(s))", path.display(), custom.len());
                                for rule in &custom {
                                    println!("    - {}", rule.name);
                                }
                            }
                            "yml" | "yaml" => match sigma::load_file(&path) {
                                Ok(custom) => {
                                    println!(
                                        "  {} ({} Sigma rule(s))",
                                        path.display(),
                                        custom.len()
                                    );
                                    for rule in &custom {
                                        println!("    - {}", rule.title);
                                    }
                                }
                                Err(err) => println!("  {} (invalid: {})", path.display(), err),
                            },
                            "yar" | "yara" => {
                                match yara::YaraRules::compile(std::slice::from_ref(&path)) {
                                    Ok(compiled) => println!(
                                        "  {} ({} YARA rule(s))",
                                        path.display(),
                                        compiled.len()
                                    ),
                                    Err(err) => println!("  {} (invalid: {})", path.display(), err),
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        }
        RulesAction::Test { file } => {
            if !file.is_file() {
                anyhow::bail!("rules file not found: {}", file.display());
            }
            let ext = file
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            match ext.as_str() {
                "yar" | "yara" => {
                    if !yara::YaraRules::available() {
                        anyhow::bail!(
                            "YARA support is not compiled in; rebuild with --features yara"
                        );
                    }
                    let compiled = yara::YaraRules::compile(std::slice::from_ref(&file))?;
                    if compiled.is_empty() {
                        anyhow::bail!("no YARA rules parsed from {}", file.display());
                    }
                    println!("{}: {} YARA rule(s)", file.display(), compiled.len());
                    println!("OK: YARA rules compile");
                    Ok(())
                }
                "yml" | "yaml" => {
                    let parsed = sigma::load_file(&file)?;
                    if parsed.is_empty() {
                        anyhow::bail!("no Sigma rules parsed from {}", file.display());
                    }
                    println!("{}: {} Sigma rule(s)", file.display(), parsed.len());
                    for rule in &parsed {
                        println!(
                            "  {} [{}] condition: {}",
                            rule.title,
                            rule.level.as_str(),
                            rule.condition
                        );
                    }
                    println!("OK: Sigma rules parse");
                    Ok(())
                }
                _ => {
                    let parsed = rules::load_rules_file(&file);
                    if parsed.is_empty() {
                        anyhow::bail!(
                            "no rules parsed from {} (expected [[rules]] entries or a rule array)",
                            file.display()
                        );
                    }
                    let errors = rules::validate_rules(&parsed);
                    println!("{}: {} TOML rule(s)", file.display(), parsed.len());
                    for rule in &parsed {
                        println!(
                            "  {} [{}] {} pattern(s)",
                            rule.name,
                            rule.severity,
                            rule.patterns.len()
                        );
                    }
                    if errors.is_empty() {
                        println!("OK: all patterns compile");
                        Ok(())
                    } else {
                        for error in &errors {
                            eprintln!("ERROR: {}", error);
                        }
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

fn run_cache(action: CacheAction) -> Result<()> {
    use crate::config;

    let dir = config::cache_dir().context("could not determine cache directory")?;
    match action {
        CacheAction::Update => {
            std::fs::create_dir_all(&dir)?;
            println!("cache directory: {}", dir.display());
            println!(
                "OSV query results are cached automatically; run an online scan to populate it."
            );
            println!("Use --offline to read from this cache without network access.");
            Ok(())
        }
        CacheAction::Clear => {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)?;
                println!("cleared {}", dir.display());
            } else {
                println!("cache is already empty ({})", dir.display());
            }
            Ok(())
        }
    }
}
