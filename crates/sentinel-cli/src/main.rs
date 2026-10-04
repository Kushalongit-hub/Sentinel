mod audit;
mod diff;
mod explain;
mod rules;
mod scan;
mod tui;
use clap::{Args, Parser, Subcommand, ValueEnum};
use sentinel_core::Severity;
use std::path::PathBuf;
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Sarif,
}
#[derive(Debug, Clone, Args)]
pub struct ScanArgs {
    #[arg(long, value_enum, default_value = "terminal")]
    pub format: OutputFormat,
    #[arg(long, default_value = "info")]
    pub threshold: Severity,
    #[arg(long)]
    pub external_scanners: bool,
    #[arg(long)]
    pub semgrep_config: Option<PathBuf>,
    #[arg(long,default_value_t=60,value_parser=clap::value_parser!(u64).range(1..))]
    pub scanner_timeout: u64,
    #[arg(long)]
    pub db: Option<PathBuf>,
}
impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            format: OutputFormat::Terminal,
            threshold: Severity::Info,
            external_scanners: false,
            semgrep_config: None,
            scanner_timeout: 60,
            db: None,
        }
    }
}
#[derive(Parser)]
#[command(name = "sentinel", about = "Offline-first code auditor")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Audit {
        path: String,
        #[command(flatten)]
        options: ScanArgs,
    },
    Diff {
        #[command(flatten)]
        options: ScanArgs,
        #[arg(long, conflicts_with = "unstaged")]
        staged: bool,
        #[arg(long)]
        unstaged: bool,
        #[arg(long)]
        tracked_only: bool,
    },
    Explain {
        finding_id: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    Rules,
    Tui,
}
fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Audit { path, options } => audit::audit_with_options(path, options),
        Commands::Diff {
            options,
            staged,
            unstaged,
            tracked_only,
        } => diff::diff_with_options(options, staged, unstaged, tracked_only),
        Commands::Explain {
            finding_id,
            project,
            db,
        } => explain::explain_at(finding_id, project, db),
        Commands::Rules => rules::rules(),
        Commands::Tui => tui::run(),
    };
    let code = match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[error] {e:#}");
            2
        }
    };
    std::process::exit(code);
}
