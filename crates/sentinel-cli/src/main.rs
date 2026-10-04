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
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum AiProvider {
    #[default]
    Local,
    Nim,
    Both,
}
#[derive(Debug, Clone, Args)]
pub struct AiArgs {
    #[arg(long, value_enum, default_value = "local")]
    pub provider: AiProvider,
    #[arg(long)]
    pub local_model: Option<String>,
    #[arg(long)]
    pub local_endpoint: Option<String>,
    #[arg(long)]
    pub nim_model: Option<String>,
    #[arg(long)]
    pub nim_endpoint: Option<String>,
    #[arg(long, default_value = "NVIDIA_API_KEY")]
    pub nim_key_env: String,
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
    pub ai_timeout: u64,
    #[arg(long, default_value_t = 12000, value_parser = clap::value_parser!(u64).range(1024..=65536))]
    pub context_bytes: u64,
    /// Print the exact shared context and messages without contacting a provider.
    #[arg(long)]
    pub context_only: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub question: Option<String>,
}
impl Default for AiArgs {
    fn default() -> Self {
        Self {
            provider: AiProvider::Local,
            local_model: None,
            local_endpoint: None,
            nim_model: None,
            nim_endpoint: None,
            nim_key_env: "NVIDIA_API_KEY".into(),
            ai_timeout: 60,
            context_bytes: 12000,
            context_only: false,
            json: false,
            question: None,
        }
    }
}
#[derive(Parser)]
#[command(name = "sentinel", about = "Offline-first code auditor")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Explain architecture, code behavior, and testing opportunities from project evidence.
    ExplainCodebase {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
        #[command(flatten)]
        ai: AiArgs,
    },
    Rules,
    /// Incrementally build the persistent repository security graph.
    Index {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Show statistics from the latest repository index.
    IndexStatus {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Serve repository-bound security tools to an MCP-compatible agent over stdio.
    Mcp {
        #[arg(long, default_value = ".")]
        repository: PathBuf,
    },
    /// Verify a patch against a saved baseline or Git HEAD.
    Verify {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        base: Option<String>,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Tui {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}
#[derive(Subcommand)]
enum BaselineCommand {
    Create {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}
fn main() {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or_else(|| Commands::Tui {
        path: PathBuf::from("."),
    }) {
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
            ai,
        } => explain::explain_with_ai(finding_id, project, db, ai),
        Commands::ExplainCodebase { path, db, ai } => explain::explain_codebase(path, db, ai),
        Commands::Rules => rules::rules(),
        Commands::Index { path } => (|| -> anyhow::Result<i32> {
            let stats = sentinel_graph::Engine::open(path)?.index()?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
            Ok(if stats.complete { 0 } else { 2 })
        })(),
        Commands::IndexStatus { path } => (|| -> anyhow::Result<i32> {
            println!(
                "{}",
                serde_json::to_string_pretty(&sentinel_graph::Engine::open(path)?.status()?)?
            );
            Ok(0)
        })(),
        Commands::Mcp { repository } => (|| -> anyhow::Result<i32> {
            tokio::runtime::Runtime::new()?.block_on(sentinel_mcp::serve(repository))?;
            Ok(0)
        })(),
        Commands::Verify { path, base } => (|| -> anyhow::Result<i32> {
            let report = sentinel_graph::Engine::open(path)?.verify_patch(base.as_deref())?;
            let code = if !report.comparison.complete {
                2
            } else if report.verdict == sentinel_graph::verification::Verdict::Pass {
                0
            } else {
                1
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(code)
        })(),
        Commands::Baseline {
            command: BaselineCommand::Create { path },
        } => (|| -> anyhow::Result<i32> {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &sentinel_graph::Engine::open(path)?.create_baseline()?
                )?
            );
            Ok(0)
        })(),
        Commands::Tui { path } => tui::run(path),
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
