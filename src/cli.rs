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
    pub async fn run(self) -> Result<()> {
        match self.command {
            Commands::Scan { .. } => {
                println!("scan: not yet implemented");
                Ok(())
            }
            Commands::Fetch { .. } => {
                println!("fetch: not yet implemented");
                Ok(())
            }
            Commands::Audit { .. } => {
                println!("audit: not yet implemented");
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
            Commands::Version => {
                println!("deepdive {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}
