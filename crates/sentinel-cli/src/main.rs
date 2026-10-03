mod audit;
mod diff;
mod explain;
mod rules;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::audit::audit;
use crate::diff::diff;
use crate::explain::explain;
use crate::rules::rules;
use crate::tui::run as run_tui;

#[derive(Parser)]
#[command(name = "sentinel")]
#[command(about = "Fast, offline-first AI code auditor CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Audit { path: String },
    Diff,
    Explain { finding_id: String },
    Rules,
    Tui,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit { path } => audit(path),
        Commands::Diff => diff(),
        Commands::Explain { finding_id } => explain(finding_id),
        Commands::Rules => rules(),
        Commands::Tui => run_tui(),
    }
}
