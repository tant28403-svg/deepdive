#![allow(dead_code)]

mod acquisition;
mod analysis;
mod cli;
mod config;
mod engine;
mod reporting;
mod risk;
mod sandbox;
mod types;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::Cli;

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();
    cli.run()
}
