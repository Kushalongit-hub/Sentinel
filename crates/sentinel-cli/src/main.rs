mod audit;
mod diff;
mod env_config;
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
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..))]
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
    /// General conversation without repository evidence.
    #[arg(long)]
    pub chat: bool,
    #[arg(long, hide = true)]
    pub chat_history: Option<String>,
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
            ai_timeout: 180,
            context_bytes: 12000,
            context_only: false,
            json: false,
            question: None,
            chat: false,
            chat_history: None,
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
    /// Persist, resume and cancel native static scan jobs without executing project code.
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Scan one repository file with rules and cross-function graph evidence.
    ScanFile {
        path: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
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
    /// Plan, validate, retain and export independently reviewed security audits.
    AuditWorkflow {
        #[command(subcommand)]
        command: AuditWorkflowCommand,
    },
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
#[derive(Subcommand)]
enum JobCommand {
    /// List persisted job metadata without refreshing source or running work.
    List {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
    Create {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_attempts: u32,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=3600))]
        max_seconds: u64,
    },
    Resume {
        id: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=100))]
        max_units: u32,
        #[arg(long)]
        recover_interrupted: bool,
    },
    Status {
        id: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
    Cancel {
        id: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
}
#[derive(Subcommand)]
enum AuditWorkflowCommand {
    /// Recover legacy JSON for explicit validation/import; never promotes records.
    ExportLegacy {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Describe retained normalized JSON for a repository-bound audit revision.
    Artifacts {
        revision: String,
        #[arg(long, default_value = ".")]
        project: PathBuf,
    },
    /// List retained revision metadata without asserting historical source freshness.
    History {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100))]
        limit: u32,
    },
    Init {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Add a normally excluded file to the source snapshot (repeatable).
        #[arg(long)]
        include: Vec<String>,
    },
    Validate {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        run: PathBuf,
    },
    Import {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        run: PathBuf,
    },
    Status {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Report {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Skill {
        #[arg(long)]
        output: PathBuf,
    },
}
fn main() {
    if let Err(error) = env_config::load() {
        eprintln!("Configuration error: {error}");
        std::process::exit(2);
    }
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
        Commands::Job { command } => (|| -> anyhow::Result<i32> {
            use sentinel_graph::{jobs::JobState, Engine};
            let (job, executing) = match command {
                JobCommand::List { path, limit } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &Engine::open(path)?.list_scan_jobs(limit as usize)?
                        )?
                    );
                    return Ok(0);
                }
                JobCommand::Create {
                    path,
                    max_attempts,
                    max_seconds,
                } => (
                    Engine::open(path)?.create_scan_job(max_attempts as usize, max_seconds)?,
                    false,
                ),
                JobCommand::Resume {
                    id,
                    project,
                    max_units,
                    recover_interrupted,
                } => (
                    Engine::open(project)?.resume_scan_job(
                        &id,
                        max_units as usize,
                        recover_interrupted,
                    )?,
                    true,
                ),
                JobCommand::Status { id, project } => {
                    (Engine::open(project)?.scan_job_status(&id)?, false)
                }
                JobCommand::Cancel { id, project } => {
                    (Engine::open(project)?.cancel_scan_job(&id)?, false)
                }
            };
            let code = if executing && job.state != JobState::Completed {
                2
            } else {
                0
            };
            println!("{}", serde_json::to_string_pretty(&job)?);
            Ok(code)
        })(),
        Commands::ScanFile { path, project } => (|| -> anyhow::Result<i32> {
            let scan = sentinel_graph::Engine::open(project)?.scan_file(&path)?;
            let code = if scan.report.outcome != sentinel_core::ScanOutcome::Complete {
                2
            } else if scan.report.findings.is_empty() {
                0
            } else {
                1
            };
            println!("{}", serde_json::to_string_pretty(&scan)?);
            Ok(code)
        })(),
        Commands::AuditWorkflow { command } => (|| -> anyhow::Result<i32> {
            use sentinel_graph::{audit_workflow, Engine};
            let value = match command {
                AuditWorkflowCommand::ExportLegacy { path, output } => {
                    serde_json::json!({"output":Engine::open(path)?.export_legacy_audit_run(&output)?,"validated":false,"imported":false})
                }
                AuditWorkflowCommand::Artifacts { revision, project } => {
                    serde_json::to_value(Engine::open(project)?.audit_artifacts(&revision)?)?
                }
                AuditWorkflowCommand::History { path, limit } => {
                    serde_json::to_value(Engine::open(path)?.audit_history(limit as usize)?)?
                }
                AuditWorkflowCommand::Init {
                    path,
                    output,
                    include,
                } => serde_json::to_value(Engine::open(path)?.init_audit_run(&output, include)?)?,
                AuditWorkflowCommand::Validate { path, run } => {
                    let run = Engine::open(path)?.validate_audit_run(&run)?;
                    serde_json::json!({"valid":true,"run_id":run.metadata.run_id,"run_status":run.metadata.run_status,"schema_validation_is_exploit_proof":false})
                }
                AuditWorkflowCommand::Import { path, run } => {
                    serde_json::to_value(Engine::open(path)?.import_audit_run(&run)?)?
                }
                AuditWorkflowCommand::Status { path } => {
                    serde_json::to_value(Engine::open(path)?.audit_status()?)?
                }
                AuditWorkflowCommand::Report { path, output } => {
                    audit_workflow::export_report(&Engine::open(path)?.audit_status()?, &output)?;
                    serde_json::json!({"report":output})
                }
                AuditWorkflowCommand::Skill { output } => {
                    serde_json::json!({"skill":audit_workflow::export_skill(&output)?})
                }
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(0)
        })(),
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
