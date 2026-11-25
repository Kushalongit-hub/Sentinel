use super::job::{Completed, Job, Kind};
use anyhow::{Context, Result};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use sentinel_core::{Finding, ScanReport, Severity};
use sentinel_scanner::rules::Rule;
use std::{path::PathBuf, process::Command, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Overview,
    Findings,
    Rules,
    Ai,
    Intelligence,
}
impl View {
    pub fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Findings => 1,
            Self::Rules => 2,
            Self::Ai => 3,
            Self::Intelligence => 4,
        }
    }
    pub fn from_index(index: usize) -> Self {
        [
            Self::Overview,
            Self::Findings,
            Self::Rules,
            Self::Ai,
            Self::Intelligence,
        ][index % 5]
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edit {
    Project,
    Filter,
    Question,
    LocalModel,
    NimModel,
    Semgrep,
    ExportJson,
    ExportSarif,
}
pub struct Editor {
    pub kind: Edit,
    pub value: String,
}
pub struct App {
    pub project: PathBuf,
    pub view: View,
    pub navigation_focus: bool,
    pub navigation_selected: usize,
    pub report: Option<ScanReport>,
    pub rules: Vec<Rule>,
    pub selected: usize,
    pub rule_selected: usize,
    pub filter: String,
    pub scroll: u16,
    pub provider: usize,
    pub local_model: String,
    pub nim_model: String,
    pub question: String,
    pub ai_finding: Option<String>,
    pub ai_text: String,
    pub chat_history: Vec<sentinel_llm::Message>,
    pub chat_input: String,
    pub chat_context: bool,
    pub chat_follow: bool,
    pub chat_preview: Option<String>,
    pub intelligence_text: String,
    pub audit_history: Option<sentinel_graph::audit_workflow::AuditHistory>,
    pub audit_revision_selected: usize,
    pub static_jobs: Option<sentinel_graph::jobs::JobList>,
    pub static_job_selected: usize,
    pub static_job_detail: bool,
    pub external: bool,
    pub semgrep: String,
    pub threshold: Severity,
    pub editor: Option<Editor>,
    pub help: bool,
    pub help_scroll: u16,
    pub status: String,
    pub status_error: bool,
    pub job: Option<Job>,
    pub cancel_job: Option<Job>,
    pub tick: usize,
}
impl App {
    pub fn new(project: PathBuf) -> Result<Self> {
        let engine = sentinel_scanner::RuleEngine::load_from_embedded_validated()?;
        let mut rules = engine.catalog().cloned().collect::<Vec<_>>();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { project:project.canonicalize()?,view:View::Overview,navigation_focus:true,navigation_selected:0,report:None,rules,selected:0,rule_selected:0,filter:String::new(),scroll:0,provider:0,
            local_model:std::env::var("SENTINEL_LOCAL_MODEL").unwrap_or_else(|_|"qwen/qwen3.5-9b".into()),nim_model:std::env::var("SENTINEL_NIM_MODEL").unwrap_or_else(|_|"z-ai/glm-5.3".into()),
            question:"Explain the architecture, entry points, data flow, and testing opportunities. Cite source evidence.".into(),ai_finding:None,
            intelligence_text:"Persistent security intelligence\n\nPress g to index the repository, or w to verify the patch against a saved baseline / Git HEAD.\n\nPress u to inspect imported audit coverage and source freshness. Detailed graph and context queries are available through the repository-bound MCP server.".into(),
            static_jobs:None,static_job_selected:0,static_job_detail:false,audit_history:None,audit_revision_selected:0,chat_history:vec![],chat_input:String::new(),chat_context:false,chat_follow:true,chat_preview:None,ai_text:"Chat with Sentinel.\n\nType a message and press Enter. Alt+m selects a provider; Alt+p attaches project evidence.\n\nLocal uses your configured LM Studio/Bionic or Ollama server. Cloud runs only NVIDIA NIM. Both runs them concurrently on identical evidence.\n\nAI answers are advisory and do not change scan findings.".into(),external:false,semgrep:String::new(),threshold:Severity::Info,editor:None,help:false,help_scroll:0,
            status:"Ready. Press a to audit this project, or ? for the keyboard guide.".into(),status_error:false,job:None,cancel_job:None,tick:0 })
    }
    pub fn provider_name(&self) -> &'static str {
        ["local", "nim", "both"][self.provider]
    }
    pub fn filtered(&self) -> Vec<usize> {
        let term = self.filter.to_lowercase();
        self.report
            .as_ref()
            .map(|r| {
                r.findings
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| {
                        term.is_empty()
                            || format!(
                                "{} {} {} {}",
                                f.title,
                                f.file.display(),
                                f.severity,
                                f.category
                            )
                            .to_lowercase()
                            .contains(&term)
                    })
                    .map(|(i, _)| i)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn selected_finding(&self) -> Option<&Finding> {
        let index = *self.filtered().get(self.selected)?;
        self.report.as_ref()?.findings.get(index)
    }
    pub fn root(&self) -> PathBuf {
        if self.project.is_file() {
            self.project.parent().unwrap().to_path_buf()
        } else {
            self.project.clone()
        }
    }
    fn notify(&mut self, message: impl Into<String>, error: bool) {
        self.status = message.into();
        self.status_error = error;
    }
    pub fn open_editor(&mut self, kind: Edit) {
        self.navigation_focus = false;
        if self.busy() && kind != Edit::Filter {
            self.notify(
                "Wait for the operation, or press Esc to stop the workers.",
                true,
            );
            return;
        }
        let value = match kind {
            Edit::Project => self.project.to_string_lossy().into(),
            Edit::Filter => self.filter.clone(),
            Edit::Question => self.question.clone(),
            Edit::LocalModel => self.local_model.clone(),
            Edit::NimModel => self.nim_model.clone(),
            Edit::Semgrep => self.semgrep.clone(),
            Edit::ExportJson => self
                .root()
                .join("sentinel-report.json")
                .to_string_lossy()
                .into(),
            Edit::ExportSarif => self
                .root()
                .join("sentinel-report.sarif")
                .to_string_lossy()
                .into(),
        };
        self.editor = Some(Editor { kind, value });
    }
    fn accept_editor(&mut self) -> Result<()> {
        let editor = self.editor.take().unwrap();
        match editor.kind {
            Edit::Project => {
                let path = PathBuf::from(editor.value.trim())
                    .canonicalize()
                    .context("project path does not exist")?;
                self.project = path;
                self.report = None;
                self.audit_history = None;
                self.static_jobs = None;
                self.static_job_selected = 0;
                self.static_job_detail = false;
                self.audit_revision_selected = 0;
                self.intelligence_text = "Project changed. Press h to load audit history.".into();
                self.selected = 0;
                self.ai_finding = None;
                self.scroll = 0;
                self.chat_history.clear();
                self.chat_input.clear();
                self.chat_preview = None;
                self.ai_text = "Project changed. Conversation cleared.".into();
                self.notify("Project updated. Press a to audit.", false);
            }
            Edit::Filter => {
                self.filter = editor.value;
                self.selected = 0;
                self.scroll = 0;
            }
            Edit::Question => {
                if editor.value.trim().is_empty() {
                    anyhow::bail!("question cannot be empty");
                }
                self.chat_input = editor.value.clone();
                self.question = editor.value;
            }
            Edit::LocalModel => self.local_model = editor.value.trim().into(),
            Edit::NimModel => self.nim_model = editor.value.trim().into(),
            Edit::Semgrep => self.semgrep = editor.value.trim().into(),
            Edit::ExportJson | Edit::ExportSarif => {
                let report = self
                    .report
                    .as_ref()
                    .context("run a scan before exporting")?;
                let output = if editor.kind == Edit::ExportJson {
                    sentinel_report::render_json(report)
                } else {
                    sentinel_report::render_sarif(report)
                };
                // Exports must create a new file; existing project files are never overwritten.
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(editor.value.trim())
                    .context("export path must be a new writable file")?;
                file.write_all(output.as_bytes())?;
                self.notify(format!("Exported {}", editor.value), false);
            }
        }
        Ok(())
    }
    pub fn busy(&self) -> bool {
        self.job.is_some() || self.cancel_job.is_some()
    }
    pub fn can_cancel_running_job(&self) -> bool {
        self.cancel_job.is_none()
            && self
                .job
                .as_ref()
                .is_some_and(|job| matches!(job.kind, Kind::JobResume))
    }
    fn start(&mut self, kind: Kind) -> Result<()> {
        let concurrent_cancel = matches!(kind, Kind::JobCancel) && self.can_cancel_running_job();
        if self.busy() && !concurrent_cancel {
            anyhow::bail!("an operation is already running; Esc stops the workers");
        }
        self.navigation_focus = false;
        if matches!(kind, Kind::Explain) {
            self.chat_preview = None;
        }
        if matches!(kind, Kind::Preview) && !self.chat_input.trim().is_empty() {
            self.question = self.chat_input.clone();
        }
        if matches!(kind, Kind::Explain | Kind::Preview) {
            crate::env_config::load()?;
        }
        let root = self.root();
        let mut command = Command::new(std::env::current_exe()?);
        command.current_dir(&root);
        match kind {
            Kind::Audit | Kind::Diff => {
                if matches!(kind, Kind::Audit) {
                    command.arg("audit").arg(&self.project);
                } else {
                    command.arg("diff");
                }
                command.args([
                    "--format",
                    "json",
                    "--threshold",
                    &self.threshold.to_string().to_lowercase(),
                ]);
                if self.external {
                    command.arg("--external-scanners");
                }
                if !self.semgrep.is_empty() {
                    command.arg("--semgrep-config").arg(&self.semgrep);
                }
            }
            Kind::AuditStatus => {
                command.arg("audit-workflow").arg("status").arg(&root);
            }
            Kind::JobStatus | Kind::JobResume | Kind::JobCancel => {
                let job = self
                    .static_jobs
                    .as_ref()
                    .and_then(|jobs| jobs.jobs.get(self.static_job_selected))
                    .context("load static jobs and select a job first")?;
                command
                    .args([
                        "job",
                        match kind {
                            Kind::JobResume => "resume",
                            Kind::JobCancel => "cancel",
                            _ => "status",
                        },
                        &job.id,
                    ])
                    .arg("--project")
                    .arg(&root);
                if matches!(kind, Kind::JobResume) {
                    command.args(["--max-units", "1"]);
                }
            }
            Kind::JobList => {
                command
                    .args(["job", "list"])
                    .arg(&root)
                    .args(["--limit", "20"]);
            }
            Kind::AuditRevision => {
                let revision = self
                    .audit_history
                    .as_ref()
                    .and_then(|history| history.revisions.get(self.audit_revision_selected))
                    .context("load audit history and select a revision first")?;
                command
                    .args(["audit-workflow", "revision", &revision.revision_id])
                    .arg("--project")
                    .arg(&root);
            }
            Kind::AuditHistory => {
                command
                    .args(["audit-workflow", "history"])
                    .arg(&root)
                    .args(["--limit", "20"]);
            }
            Kind::Index | Kind::Verify => {
                command
                    .arg(if matches!(kind, Kind::Index) {
                        "index"
                    } else {
                        "verify"
                    })
                    .arg(&root);
            }
            Kind::Explain | Kind::Preview => {
                if let Some(id) = &self.ai_finding {
                    command.arg("explain").arg(id).arg("--project").arg(&root);
                } else {
                    command.arg("explain-codebase").arg(&root);
                }
                command.args([
                    "--provider",
                    self.provider_name(),
                    "--question",
                    &self.question,
                    "--local-model",
                    &self.local_model,
                    "--json",
                ]);
                if !self.chat_context && self.ai_finding.is_none() {
                    command.arg("--chat");
                }
                command
                    .arg("--chat-history")
                    .arg(serde_json::to_string(&self.chat_history)?);
                if !self.nim_model.is_empty() {
                    command.arg("--nim-model").arg(&self.nim_model);
                }
                if matches!(kind, Kind::Preview) {
                    command.arg("--context-only");
                }
            }
        }
        let worker = Job::spawn(
            command,
            kind,
            Duration::from_secs(
                if matches!(
                    kind,
                    Kind::Audit | Kind::Diff | Kind::Index | Kind::Verify | Kind::JobResume
                ) {
                    600
                } else {
                    210
                },
            ),
        )?;
        if concurrent_cancel {
            self.cancel_job = Some(worker);
        } else {
            self.job = Some(worker);
        }
        self.notify(
            match kind {
                Kind::Audit => "Auditing project...",
                Kind::Diff => "Scanning Git changes...",
                Kind::Explain => "Requesting AI explanations...",
                Kind::Preview => "Building shared context preview...",
                Kind::Index => "Indexing security graph...",
                Kind::Verify => "Verifying patch...",
                Kind::AuditStatus => "Loading audit coverage and source freshness...",
                Kind::AuditHistory => "Loading the latest 20 audit revisions...",
                Kind::AuditRevision => "Loading the selected historical revision...",
                Kind::JobList => "Loading persisted static jobs...",
                Kind::JobStatus => "Loading stored static job details...",
                Kind::JobResume => "Resuming at most one static unit with existing budgets...",
                Kind::JobCancel => "Cancelling the selected static job...",
            },
            false,
        );
        Ok(())
    }
    fn complete(&mut self, completed: Completed) -> Result<()> {
        match completed.kind {
            Kind::JobList => {
                if completed.code != 0 {
                    anyhow::bail!("Job listing failed: {}", safe(&completed.stderr));
                }
                let jobs: sentinel_graph::jobs::JobList =
                    serde_json::from_slice(&completed.stdout)?;
                self.audit_history = None;
                self.static_job_selected = 0;
                self.static_job_detail = false;
                self.intelligence_text = render_jobs(&jobs, 0);
                self.static_jobs = Some(jobs);
                self.navigation_focus = false;
                self.view = View::Intelligence;
                self.scroll = 0;
                self.notify(
                    "Stored jobs loaded; no work resumed and source freshness remains unchecked.",
                    false,
                );
            }
            Kind::JobStatus | Kind::JobResume | Kind::JobCancel => {
                let job: sentinel_graph::jobs::ScanJob = serde_json::from_slice(&completed.stdout)
                    .with_context(|| {
                        format!("Static job command failed: {}", safe(&completed.stderr))
                    })?;
                let selected = self
                    .static_jobs
                    .as_ref()
                    .and_then(|jobs| jobs.jobs.get(self.static_job_selected))
                    .context("static job selection is unavailable")?;
                if selected.id != job.id {
                    anyhow::bail!("static job response differs from the selected job");
                }
                self.static_job_detail = true;
                self.intelligence_text = format!("STATIC JOB DETAILS / STORED STATE\nCompletion is not a clean security verdict. Status/cancel do not check source freshness.\nResume checks source and detector identity; budgets cannot increase.\n r resume one unit / C cancel / o reload jobs\nEsc stops the UI worker; interrupted Running jobs need explicit CLI recovery.\n\n{}", safe(&serde_json::to_string_pretty(&job)?));
                self.view = View::Intelligence;
                self.navigation_focus = false;
                self.scroll = 0;
                self.notify(
                    format!(
                        "Static job state: {:?}. Recorded results remain candidates.",
                        job.state
                    ),
                    matches!(
                        job.state,
                        sentinel_graph::jobs::JobState::Failed
                            | sentinel_graph::jobs::JobState::Stale
                            | sentinel_graph::jobs::JobState::BudgetExhausted
                    ),
                );
            }
            Kind::AuditHistory => {
                if completed.code != 0 {
                    anyhow::bail!("Audit history failed: {}", safe(&completed.stderr));
                }
                let history: sentinel_graph::audit_workflow::AuditHistory =
                    serde_json::from_slice(&completed.stdout)?;
                self.static_jobs = None;
                self.audit_revision_selected = 0;
                self.intelligence_text = render_audit_history(&history, 0);
                self.audit_history = Some(history);
                self.navigation_focus = false;
                self.view = View::Intelligence;
                self.scroll = 0;
                self.notify("Audit history loaded. Historical source freshness is unchecked; u checks the latest audit.", false);
            }
            Kind::AuditRevision => {
                if completed.code != 0 {
                    anyhow::bail!("Audit revision failed: {}", safe(&completed.stderr));
                }
                let detail: sentinel_graph::audit_workflow::AuditRevisionDetail =
                    serde_json::from_slice(&completed.stdout)?;
                let selected = self
                    .audit_history
                    .as_ref()
                    .and_then(|history| history.revisions.get(self.audit_revision_selected))
                    .context("no audit revision selected")?;
                if detail.revision_id != selected.revision_id {
                    anyhow::bail!("audit response does not match the selected revision");
                }
                self.intelligence_text = format!("HISTORICAL IMPORTED AUDIT\nSOURCE FRESHNESS: UNCHECKED\nEXECUTION: UNOBSERVED\nImported attestations; no current security verdict. Press h to return to history.\n\n{}", safe(&serde_json::to_string_pretty(&detail)?));
                self.audit_history = None;
                self.view = View::Intelligence;
                self.navigation_focus = false;
                self.scroll = 0;
                self.notify(
                    "Historical revision loaded. No source refresh or latest revision change.",
                    false,
                );
            }
            Kind::Index | Kind::Verify | Kind::AuditStatus => {
                self.static_jobs = None;
                self.audit_history = None;
                let value: serde_json::Value = serde_json::from_slice(&completed.stdout)
                    .with_context(|| {
                        format!("Security operation failed: {}", safe(&completed.stderr))
                    })?;
                self.intelligence_text = safe(&serde_json::to_string_pretty(&value)?);
                self.view = View::Intelligence;
                self.scroll = 0;
                self.notify(
                    format!(
                        "Security operation complete. Exit {}. Inspect verdict and coverage below.",
                        completed.code
                    ),
                    completed.code != 0,
                );
            }
            Kind::Audit | Kind::Diff => {
                let mut report: ScanReport = serde_json::from_slice(&completed.stdout)
                    .with_context(|| {
                        format!("scan did not return a report: {}", safe(&completed.stderr))
                    })?;
                report.findings.sort_by(|a, b| {
                    b.severity
                        .cmp(&a.severity)
                        .then_with(|| a.file.cmp(&b.file))
                        .then_with(|| a.line.cmp(&b.line))
                });
                let outcome = report.outcome;
                let count = report.findings.len();
                self.report = Some(report);
                self.selected = 0;
                self.scroll = 0;
                self.view = if count > 0 {
                    View::Findings
                } else {
                    View::Overview
                };
                self.notify(format!("{outcome:?}: {count} findings. Exit {}. Scan history saved when persistence succeeded.",completed.code),completed.code==2);
            }
            Kind::Explain | Kind::Preview => {
                if completed.stdout.is_empty() {
                    anyhow::bail!("AI command failed: {}", safe(&completed.stderr));
                }
                let json: serde_json::Value = serde_json::from_slice(&completed.stdout)
                    .with_context(|| format!("AI command failed: {}", safe(&completed.stderr)))?;
                if matches!(completed.kind, Kind::Preview) {
                    self.chat_preview = Some(format!(
                        "SHARED CONTEXT PREVIEW\nNo provider was contacted.\n\n{}",
                        serde_json::to_string_pretty(&json)?
                    ));
                } else {
                    let mut text = format!(
                        "CONTEXT {}\n\n",
                        json["context_id"].as_str().unwrap_or("unknown")
                    );
                    if let Some(responses) = json["responses"].as_array() {
                        for answer in responses {
                            text.push_str(&format!(
                                "{} / {}\n{}\n\n",
                                answer["provider"].as_str().unwrap_or("provider"),
                                answer["model"].as_str().unwrap_or("model"),
                                answer["text"].as_str().unwrap_or("")
                            ));
                        }
                    }
                    if let Some(failures) = json["failures"].as_array() {
                        for failure in failures {
                            text.push_str(&format!(
                                "PROVIDER ERROR: {} - {}\n",
                                failure["provider"].as_str().unwrap_or(""),
                                failure["error"].as_str().unwrap_or("")
                            ));
                        }
                    }
                    if let Some(notes) = json["coverage_notes"].as_array() {
                        for note in notes {
                            text.push_str(&format!(
                                "CONTEXT NOTE: {}\n",
                                note.as_str().unwrap_or("")
                            ));
                        }
                    }
                    self.chat_history.push(sentinel_llm::Message {
                        role: "user".into(),
                        content: self.question.clone(),
                    });
                    if let Some(responses) = json["responses"].as_array() {
                        let answers = responses
                            .iter()
                            .map(|a| {
                                format!(
                                    "{} / {}: {}",
                                    a["provider"].as_str().unwrap_or("provider"),
                                    a["model"].as_str().unwrap_or("model"),
                                    a["text"].as_str().unwrap_or("")
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("\n\n");
                        if !answers.is_empty() {
                            self.chat_history.push(sentinel_llm::Message {
                                role: "assistant".into(),
                                content: if answers.len() <= 8192 {
                                    answers
                                } else {
                                    format!(
                                        "{}\n[Earlier response shortened in conversation context]",
                                        answers.chars().take(1800).collect::<String>()
                                    )
                                },
                            });
                        }
                    }
                    while self.chat_history.len() > 20
                        || serde_json::to_vec(&self.chat_history)?.len() > 12000
                    {
                        self.chat_history.drain(..self.chat_history.len().min(2));
                    }
                    self.chat_follow = true;
                    self.ai_text.push_str(&format!(
                        "\n\nYOU\n{}\n\n{}",
                        safe(&self.question),
                        text
                    ));
                }
                self.ai_text = safe(&self.ai_text);
                if self.ai_text.len() > 128 * 1024 {
                    let start = self
                        .ai_text
                        .char_indices()
                        .find(|(i, _)| *i >= self.ai_text.len() - 128 * 1024)
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.ai_text = format!("[Earlier display omitted]\n{}", &self.ai_text[start..]);
                }
                self.scroll = 0;
                self.view = View::Ai;
                self.notify(
                    if completed.code == 0 {
                        "AI operation complete."
                    } else {
                        "One or more AI providers failed; available answers are preserved."
                    },
                    completed.code != 0,
                );
            }
        }
        Ok(())
    }
    fn finish_cancellation(&mut self, completed: Completed) -> Result<()> {
        let record: sentinel_graph::jobs::ScanJob = serde_json::from_slice(&completed.stdout)
            .with_context(|| {
                format!(
                    "Static job cancellation failed: {}",
                    safe(&completed.stderr)
                )
            })?;
        let cancelled = record.state == sentinel_graph::jobs::JobState::Cancelled;
        // Validate the response identity before stopping the admitted resume worker.
        self.complete(completed)?;
        if cancelled
            && self
                .job
                .as_ref()
                .is_some_and(|job| matches!(job.kind, Kind::JobResume))
        {
            self.job.take();
        }
        Ok(())
    }
    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        let cancellation = self.cancel_job.as_mut().map(Job::poll);
        match cancellation {
            Some(Ok(Some(completed))) => {
                self.cancel_job.take();
                if let Err(e) = self.finish_cancellation(completed) {
                    self.notify(format!("{e:#}"), true);
                }
            }
            Some(Err(e)) => {
                self.cancel_job.take();
                self.notify(format!("{e:#}"), true);
            }
            _ => {}
        }
        let result = self.job.as_mut().map(Job::poll);
        match result {
            Some(Ok(Some(completed))) => {
                self.job.take();
                if let Err(e) = self.complete(completed) {
                    self.notify(format!("{e:#}"), true);
                }
            }
            Some(Err(e)) => {
                self.job.take();
                self.notify(format!("{e:#}"), true);
            }
            _ => {}
        }
    }
    pub fn key(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.cancel_job.take();
            self.job.take();
            return true;
        }
        if self.editor.is_some() {
            match key.code {
                KeyCode::Esc => {
                    self.editor = None;
                }
                KeyCode::Enter => {
                    if let Err(e) = self.accept_editor() {
                        self.notify(format!("{e:#}"), true);
                    }
                }
                KeyCode::Backspace => {
                    self.editor.as_mut().unwrap().value.pop();
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.editor.as_mut().unwrap().value.clear()
                }
                KeyCode::Char(c)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && !c.is_control() =>
                {
                    let value = &mut self.editor.as_mut().unwrap().value;
                    if value.len() + c.len_utf8() <= 4096 {
                        value.push(c);
                    }
                }
                _ => {}
            }
            return false;
        }
        if self.help {
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') => self.help = false,
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(8),
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(8),
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    self.cancel_job.take();
                    self.job.take();
                    return true;
                }
                _ => {}
            }
            return false;
        }
        if self.view == View::Ai
            && !self.navigation_focus
            && key.modifiers.contains(KeyModifiers::CONTROL)
        {
            if key.code == KeyCode::Char('u') {
                self.chat_input.clear();
            }
            return false;
        }
        if self.view == View::Ai
            && !self.navigation_focus
            && !key
                .modifiers
                .intersects(KeyModifiers::ALT | KeyModifiers::CONTROL)
        {
            match key.code {
                KeyCode::Char(c) if !c.is_control() => {
                    if self.chat_input.len() + c.len_utf8() <= 4096 {
                        self.chat_input.push(c);
                    }
                    return false;
                }
                KeyCode::Backspace => {
                    self.chat_input.pop();
                    return false;
                }
                KeyCode::Enter => {
                    if !self.busy() && !self.chat_input.trim().is_empty() {
                        self.question = self.chat_input.clone();
                        match self.start(Kind::Explain) {
                            Ok(()) => self.chat_input.clear(),
                            Err(e) => self.notify(format!("{e:#}"), true),
                        }
                    }
                    return false;
                }
                _ => {}
            }
        }
        if self.view == View::Ai
            && matches!(
                key.code,
                KeyCode::Up | KeyCode::Down | KeyCode::PageUp | KeyCode::PageDown | KeyCode::Home
            )
        {
            self.chat_follow = false;
        }
        if self.view == View::Ai && key.code == KeyCode::End {
            self.chat_follow = true;
            return false;
        }
        if self.view == View::Ai && key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Char('p') if !self.busy() => {
                    self.chat_context = !self.chat_context;
                    self.ai_finding = None;
                    return false;
                }
                KeyCode::Char('r') if !self.busy() => {
                    self.chat_history.clear();
                    self.chat_input.clear();
                    self.chat_preview = None;
                    self.ai_finding = None;
                    self.ai_text = "New conversation.".into();
                    self.scroll = 0;
                    return false;
                }
                _ => {}
            }
        }
        let action: Result<()> = match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.cancel_job.take();
                self.job.take();
                return true;
            }
            KeyCode::Esc => {
                if self.chat_preview.take().is_some() {
                    return false;
                }
                let stopped_cancel = self.cancel_job.take().is_some();
                if self.job.take().is_some() || stopped_cancel {
                    self.notify(
                        "Operation stopped. Scan writes already committed remain in history.",
                        false,
                    );
                } else {
                    if self.filter.is_empty() {
                        self.navigation_focus = true;
                        self.navigation_selected = self.view.index();
                    }
                    self.filter.clear();
                    self.selected = 0;
                }
                Ok(())
            }
            KeyCode::Char('?') => {
                self.help = true;
                self.help_scroll = 0;
                Ok(())
            }
            KeyCode::Tab => {
                self.navigation_focus = !self.navigation_focus;
                self.navigation_selected = self.view.index();
                Ok(())
            }
            KeyCode::BackTab => {
                self.navigation_focus = !self.navigation_focus;
                self.navigation_selected = self.view.index();
                Ok(())
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.view = View::from_index(c as usize - '1' as usize);
                self.navigation_selected = self.view.index();
                self.navigation_focus = false;
                self.scroll = 0;
                Ok(())
            }
            KeyCode::Char('r') if self.view == View::Intelligence && self.static_jobs.is_some() => {
                self.start(Kind::JobResume)
            }
            KeyCode::Char('C') if self.view == View::Intelligence && self.static_jobs.is_some() => {
                self.start(Kind::JobCancel)
            }
            KeyCode::Char('g') => self.start(Kind::Index),
            KeyCode::Char('w') => self.start(Kind::Verify),
            KeyCode::Char('u') => self.start(Kind::AuditStatus),
            KeyCode::Char('h') => self.start(Kind::AuditHistory),
            KeyCode::Char('o') => self.start(Kind::JobList),
            KeyCode::Char('a') => self.start(Kind::Audit),
            KeyCode::Char('d') => self.start(Kind::Diff),
            KeyCode::Char('p') => {
                self.open_editor(Edit::Project);
                Ok(())
            }
            KeyCode::Char('/') => {
                self.open_editor(Edit::Filter);
                self.view = View::Findings;
                Ok(())
            }
            KeyCode::Char('i') => {
                self.open_editor(Edit::Question);
                self.view = View::Ai;
                Ok(())
            }
            KeyCode::Char('l') if self.view == View::Ai => {
                self.open_editor(Edit::LocalModel);
                Ok(())
            }
            KeyCode::Char('n') if self.view == View::Ai => {
                self.open_editor(Edit::NimModel);
                Ok(())
            }
            KeyCode::Char('v') => {
                self.open_editor(Edit::Semgrep);
                Ok(())
            }
            KeyCode::Char('m') if !self.busy() => {
                self.provider = (self.provider + 1) % 3;
                self.notify(format!("AI provider: {}. Cloud context is sent only when you submit an explanation.",self.provider_name()),false);
                Ok(())
            }
            KeyCode::Char('x') if !self.busy() => {
                self.external = !self.external;
                self.notify(
                    format!(
                        "External scanners {} for the next scan.",
                        if self.external { "enabled" } else { "disabled" }
                    ),
                    false,
                );
                Ok(())
            }
            KeyCode::Char('t') if !self.busy() => {
                self.threshold = match self.threshold {
                    Severity::Info => Severity::Low,
                    Severity::Low => Severity::Medium,
                    Severity::Medium => Severity::High,
                    Severity::High => Severity::Critical,
                    Severity::Critical => Severity::Info,
                };
                self.notify(
                    format!(
                        "Next scan exit threshold: {}. All findings remain visible.",
                        self.threshold
                    ),
                    false,
                );
                Ok(())
            }
            KeyCode::Char('c') if !self.busy() => {
                self.navigation_focus = false;
                self.ai_finding = None;
                self.chat_context = true;
                self.question = "Explain the architecture, entry points, data flow, and testing opportunities. Cite source evidence.".into();
                self.chat_input = self.question.clone();
                self.view = View::Ai;
                self.scroll = 0;
                self.notify(
                    "Codebase selected. Enter requests an explanation; Alt+b previews context.",
                    false,
                );
                Ok(())
            }
            KeyCode::Char('e') if self.view == View::Findings && !self.busy() => {
                if let Some(f) = self.selected_finding() {
                    let id = f.id.clone();
                    let title = f.title.clone();
                    self.ai_finding = Some(id);
                    self.question=format!("Explain {title}, relevant code behavior, impact, remediation, and regression tests.");
                    self.chat_input = self.question.clone();
                    self.navigation_focus = false;
                    self.view = View::Ai;
                    self.scroll = 0;
                    self.notify(
                        "Finding selected for explanation. Enter submits; Alt+b previews context.",
                        false,
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("select a finding first"))
                }
            }
            KeyCode::Char('b') if self.view == View::Ai => {
                if self.chat_preview.take().is_some() {
                    Ok(())
                } else {
                    self.start(Kind::Preview)
                }
            }
            KeyCode::Enter if self.navigation_focus => {
                self.view = View::from_index(self.navigation_selected);
                self.navigation_focus = false;
                self.scroll = 0;
                Ok(())
            }
            KeyCode::Enter if self.view == View::Intelligence && self.audit_history.is_some() => {
                self.start(Kind::AuditRevision)
            }
            KeyCode::Enter if self.view == View::Intelligence && self.static_jobs.is_some() => {
                self.start(Kind::JobStatus)
            }
            KeyCode::Enter if self.view == View::Overview => self.start(Kind::Audit),
            KeyCode::Enter if self.view == View::Ai => self.start(Kind::Explain),
            KeyCode::Char('s') => {
                self.open_editor(Edit::ExportJson);
                Ok(())
            }
            KeyCode::Char('S') => {
                self.open_editor(Edit::ExportSarif);
                Ok(())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.navigation_focus {
                    self.navigation_selected = (self.navigation_selected + 1).min(4);
                    return false;
                }
                match self.view {
                    View::Findings => {
                        self.selected =
                            (self.selected + 1).min(self.filtered().len().saturating_sub(1))
                    }
                    View::Rules => {
                        self.rule_selected =
                            (self.rule_selected + 1).min(self.rules.len().saturating_sub(1))
                    }
                    View::Intelligence if self.audit_history.is_some() && !self.busy() => {
                        let history = self.audit_history.as_ref().unwrap();
                        self.audit_revision_selected = (self.audit_revision_selected + 1)
                            .min(history.revisions.len().saturating_sub(1));
                        self.intelligence_text =
                            render_audit_history(history, self.audit_revision_selected);
                        self.scroll = 0;
                    }
                    View::Intelligence
                        if self.static_jobs.is_some()
                            && !self.static_job_detail
                            && !self.busy() =>
                    {
                        let jobs = self.static_jobs.as_ref().unwrap();
                        self.static_job_selected =
                            (self.static_job_selected + 1).min(jobs.jobs.len().saturating_sub(1));
                        self.intelligence_text = render_jobs(jobs, self.static_job_selected);
                        self.scroll = 0;
                    }
                    _ => self.scroll = self.scroll.saturating_add(1),
                }
                if matches!(self.view, View::Findings | View::Rules) {
                    self.scroll = 0;
                }
                Ok(())
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.navigation_focus {
                    self.navigation_selected = self.navigation_selected.saturating_sub(1);
                    return false;
                }
                match self.view {
                    View::Findings => self.selected = self.selected.saturating_sub(1),
                    View::Rules => self.rule_selected = self.rule_selected.saturating_sub(1),
                    View::Intelligence if self.audit_history.is_some() && !self.busy() => {
                        self.audit_revision_selected =
                            self.audit_revision_selected.saturating_sub(1);
                        self.intelligence_text = render_audit_history(
                            self.audit_history.as_ref().unwrap(),
                            self.audit_revision_selected,
                        );
                        self.scroll = 0;
                    }
                    View::Intelligence
                        if self.static_jobs.is_some()
                            && !self.static_job_detail
                            && !self.busy() =>
                    {
                        self.static_job_selected = self.static_job_selected.saturating_sub(1);
                        self.intelligence_text = render_jobs(
                            self.static_jobs.as_ref().unwrap(),
                            self.static_job_selected,
                        );
                        self.scroll = 0;
                    }
                    _ => self.scroll = self.scroll.saturating_sub(1),
                }
                if matches!(self.view, View::Findings | View::Rules) {
                    self.scroll = 0;
                }
                Ok(())
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(10);
                Ok(())
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(10);
                Ok(())
            }
            KeyCode::Home => {
                self.scroll = 0;
                self.selected = 0;
                self.rule_selected = 0;
                if self.view == View::Intelligence {
                    if !self.static_job_detail && !self.busy() {
                        self.static_job_selected = 0;
                        if let Some(jobs) = &self.static_jobs {
                            self.intelligence_text = render_jobs(jobs, 0);
                        }
                    }
                    if !self.busy() {
                        self.audit_revision_selected = 0;
                        if let Some(history) = &self.audit_history {
                            self.intelligence_text = render_audit_history(history, 0);
                        }
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        };
        if let Err(e) = action {
            self.notify(format!("{e:#}"), true);
        }
        false
    }
    pub fn paste(&mut self, text: &str) {
        if self.editor.is_none() && self.view == View::Ai && !self.navigation_focus {
            for c in text.chars().filter(|c| !c.is_control()) {
                if self.chat_input.len() + c.len_utf8() > 4096 {
                    break;
                }
                self.chat_input.push(c);
            }
            return;
        }
        if let Some(editor) = &mut self.editor {
            for c in text.chars().filter(|c| !c.is_control()) {
                if editor.value.len() + c.len_utf8() > 4096 {
                    break;
                }
                editor.value.push(c);
            }
        }
    }
}
fn render_jobs(list: &sentinel_graph::jobs::JobList, selected: usize) -> String {
    let mut text = String::from("STATIC SCAN JOBS / NEWEST FIRST\nSOURCE FRESHNESS: UNCHECKED\nStored state only. Completed does not mean no vulnerabilities or current-source coverage.\nTime budgets are soft checks between work units. No target code or AI is executed.\n\n");
    text.push_str("Arrows / j / k select; Enter details; r resumes one unit; C cancels.\n\n");
    if !list.jobs.is_empty() {
        text.push_str(&format!(
            "Selected job {} of {}\n\n",
            selected + 1,
            list.jobs.len()
        ));
    }
    if let Some(job) = list.jobs.get(selected) {
        text.push_str(&format!("{:?} / {}\n  Created: {}\n  Units recorded: {}/{} | Attempts reserved: {}/{}\n  Elapsed: {} / {} ms | Active file: {}\n  Snapshot: {}\n\n",job.state,safe(&job.id),safe(&job.created_at),job.units_recorded,job.total_files,job.attempts_reserved,job.max_attempts,job.elapsed_ms,job.max_elapsed_ms,safe(job.active_file.as_deref().unwrap_or("none")),safe(&job.source_snapshot)));
    }
    if list.jobs.is_empty() {
        text.push_str("No persisted static jobs in this project.\n");
    }
    if list.has_more {
        text.push_str("More jobs retained. Use sentinel job list --limit 100.\n");
    }
    text.push_str("Inspect: sentinel job status <id>\nResume explicitly: sentinel job resume <id> --max-units 1\nCancel: sentinel job cancel <id>\nRun these commands from this project, or supply --project <path>.\n");
    text
}
fn render_audit_history(
    history: &sentinel_graph::audit_workflow::AuditHistory,
    selected: usize,
) -> String {
    let mut text = String::from("AUDIT REVISION HISTORY\nNewest imports first / at most 20 revisions\n\nSOURCE FRESHNESS: UNCHECKED\nLatest means the current imported revision, not current source or a security verdict.\nReviewer identities and verdicts are imported attestations.\nPress u to check coverage and freshness of the latest audit.\nArrows / j / k select a revision; Enter opens retained details.\n\n");
    if history.revisions.is_empty() {
        text.push_str("No retained audit revisions for this project.\n");
    }
    if !history.revisions.is_empty() {
        text.push_str(&format!(
            "Selected revision {} of {}\n\n",
            selected + 1,
            history.revisions.len()
        ));
    }
    if let Some(revision) = history.revisions.get(selected) {
        text.push_str(&format!(
            "{}{} / {}\n  Imported: {}\n  Revision: {}\n  Source snapshot: {}\n\n",
            if revision.is_latest { "[LATEST] " } else { "" },
            safe(&revision.run_id),
            safe(&revision.run_status),
            safe(&revision.imported_at),
            safe(&revision.revision_id),
            safe(&revision.source_snapshot)
        ));
    }
    if history.has_more {
        text.push_str("More revisions retained. Use sentinel audit-workflow history --limit 100 for a larger bounded list.\n");
    }
    text
}
pub fn safe(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect::<String>()
        .replace('\t', "    ")
}

#[cfg(test)]
mod chat_tests {
    use super::*;
    #[test]
    fn job_browser_labels_stored_state_and_explicit_actions() {
        let empty = sentinel_graph::jobs::JobList {
            jobs: vec![],
            has_more: false,
            source_freshness_checked: false,
        };
        let text = render_jobs(&empty, 0);
        assert!(text.contains("SOURCE FRESHNESS: UNCHECKED"));
        assert!(text.contains("Completed does not mean no vulnerabilities"));
        assert!(text.contains("No persisted static jobs"));
        assert!(text.contains("Resume explicitly"));
    }
    #[test]
    fn audit_history_labels_freshness_and_preserves_revision_identity() {
        use sentinel_graph::audit_workflow::{AuditHistory, AuditRevision};
        let history = AuditHistory {
            revisions: vec![AuditRevision {
                revision_id: "rev-1".into(),
                run_id: "run-1".into(),
                source_snapshot: "sha256:abc".into(),
                run_status: "complete".into(),
                imported_at: "2026-10-07".into(),
                is_latest: true,
            }],
            has_more: true,
            source_freshness_checked: false,
        };
        let rendered = render_audit_history(&history, 0);
        assert!(rendered.contains("SOURCE FRESHNESS: UNCHECKED"));
        assert!(rendered.contains("[LATEST] run-1"));
        assert!(rendered.contains("sha256:abc"));
        assert!(rendered.contains("More revisions retained"));
        let empty = AuditHistory {
            revisions: vec![],
            has_more: false,
            source_freshness_checked: false,
        };
        assert!(render_audit_history(&empty, 0).contains("No retained audit revisions"));
    }
    #[test]
    fn job_selection_and_pending_details_preserve_budgets_and_explicit_actions() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        let jobs = serde_json::json!({"jobs":(0..2).map(|i| serde_json::json!({
            "id":if i == 0 {"a".repeat(64)} else {"b".repeat(64)}, "state":"pending", "created_at":"today",
            "source_snapshot":"snapshot", "units_recorded":0, "total_files":2,
            "attempts_reserved":0, "max_attempts":2, "elapsed_ms":0, "max_elapsed_ms":60000, "active_file":null
        })).collect::<Vec<_>>(), "has_more":false, "source_freshness_checked":false});
        app.complete(Completed {
            kind: Kind::JobList,
            code: 0,
            stdout: serde_json::to_vec(&jobs).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        assert!(!app.navigation_focus);
        for _ in 0..3 {
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert_eq!(app.static_job_selected, 1);
        assert!(app.intelligence_text.contains("Selected job 2 of 2"));
        #[cfg(windows)]
        let mut command = Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/c", "exit", "0"]);
        #[cfg(unix)]
        let mut command = Command::new("sh");
        #[cfg(unix)]
        command.args(["-c", "exit 0"]);
        // An owned, harmless OS child keeps the UI in worker mode; no target code.
        app.job = Some(Job::spawn(command, Kind::JobResume, Duration::from_secs(5)).unwrap());
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.static_job_selected, 1);
        app.job.take();
        let pending = serde_json::json!({"schema_version":1,"id":"b".repeat(64),"project_id":"test",
            "source_snapshot":"snapshot","source_manifest":{"a.py":"hash","b.py":"hash"},"detector_id":"detector",
            "state":"pending","max_attempts":2,"attempts_reserved":1,"max_elapsed_ms":60000,"elapsed_ms":10,
            "active_file":null,"results":[],"notes":[]});
        app.complete(Completed {
            kind: Kind::JobResume,
            code: 2,
            stdout: serde_json::to_vec(&pending).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        assert!(app.static_job_detail);
        assert!(!app.status_error);
        assert!(app
            .intelligence_text
            .contains("Completion is not a clean security verdict"));
        assert!(app.intelligence_text.contains("\"attempts_reserved\": 1"));
        assert!(app.intelligence_text.contains("\"max_attempts\": 2"));
        let mut wrong = pending.clone();
        wrong["id"] = serde_json::json!("a".repeat(64));
        let text = app.intelligence_text.clone();
        assert!(app
            .complete(Completed {
                kind: Kind::JobStatus,
                code: 0,
                stdout: serde_json::to_vec(&wrong).unwrap(),
                stderr: String::new()
            })
            .is_err());
        assert_eq!(app.intelligence_text, text);
        assert_eq!(app.static_job_selected, 1);
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.static_job_selected, 1);
        let empty =
            serde_json::json!({"jobs":[],"has_more":false,"source_freshness_checked":false});
        app.complete(Completed {
            kind: Kind::JobList,
            code: 0,
            stdout: serde_json::to_vec(&empty).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        app.key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(app.job.is_none());
        assert!(app.status_error);
        app.key(KeyEvent::new(KeyCode::Char('C'), KeyModifiers::NONE));
        assert!(app.job.is_none());
        app.editor = Some(Editor {
            kind: Edit::Project,
            value: app.project.to_string_lossy().into(),
        });
        app.accept_editor().unwrap();
        assert!(app.static_jobs.is_none());
        assert!(!app.static_job_detail);
    }

    #[test]
    fn audit_history_selection_is_bounded_and_details_preserve_advisory_labels() {
        use sentinel_graph::audit_workflow::{AuditHistory, AuditRevision};
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        let history = AuditHistory {
            revisions: (0..2)
                .map(|index| AuditRevision {
                    revision_id: if index == 0 {
                        "a".repeat(64)
                    } else {
                        "b".repeat(64)
                    },
                    run_id: format!("run-{index}"),
                    source_snapshot: "snapshot".into(),
                    run_status: "incomplete".into(),
                    imported_at: "today".into(),
                    is_latest: index == 0,
                })
                .collect(),
            has_more: false,
            source_freshness_checked: false,
        };
        app.complete(Completed {
            kind: Kind::AuditHistory,
            code: 0,
            stdout: serde_json::to_vec(&history).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        assert!(!app.navigation_focus);
        assert!(app.intelligence_text.contains("Selected revision 1 of 2"));
        for _ in 0..3 {
            app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        }
        assert_eq!(app.audit_revision_selected, 1);
        assert!(app.intelligence_text.contains("run-1"));
        assert!(!app.intelligence_text.contains("[LATEST] run-0"));
        #[cfg(windows)]
        let mut command = Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/c", "exit", "0"]);
        #[cfg(unix)]
        let mut command = Command::new("sh");
        #[cfg(unix)]
        command.args(["-c", "exit 0"]);
        app.job = Some(Job::spawn(command, Kind::AuditRevision, Duration::from_secs(5)).unwrap());
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.audit_revision_selected, 1);
        app.job.take();
        app.key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
        assert_eq!(app.audit_revision_selected, 0);
        app.key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.audit_revision_selected, 0);
        let run = serde_json::json!({"metadata":{
            "run_id":"run-0", "repo":"test", "target":app.root(), "source_ref":"unknown",
            "source_snapshot":"snapshot", "source_manifest":{}, "include_paths":[], "snapshot_notes":[],
            "profile":"quick", "scope_paths":[], "budget":null, "execution_policy":"imported",
            "upstream_revision":"unknown", "run_status":"incomplete", "selected_companion_files":[],
            "prior_run_paths":[], "shared_file_owners":{}, "incomplete_reason":"no independent review"
        }, "coverage":[], "findings":[], "verification":[]});
        let detail = serde_json::json!({"revision_id":"a".repeat(64), "source_freshness_checked":false, "execution_observed":false, "run":run});
        let mut mismatched = detail.clone();
        mismatched["revision_id"] = serde_json::json!("b".repeat(64));
        let prior_text = app.intelligence_text.clone();
        assert!(app
            .complete(Completed {
                kind: Kind::AuditRevision,
                code: 0,
                stdout: serde_json::to_vec(&mismatched).unwrap(),
                stderr: String::new(),
            })
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        assert_eq!(app.intelligence_text, prior_text);
        assert!(app.audit_history.is_some());
        assert_eq!(app.audit_revision_selected, 0);
        app.complete(Completed {
            kind: Kind::AuditRevision,
            code: 0,
            stdout: serde_json::to_vec(&detail).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        assert!(app.audit_history.is_none());
        assert!(app
            .intelligence_text
            .contains("SOURCE FRESHNESS: UNCHECKED"));
        assert!(app.intelligence_text.contains("EXECUTION: UNOBSERVED"));
        assert!(app.intelligence_text.contains("run-0"));
        assert!(app.intelligence_text.contains("Press h to return"));
        // Empty history never selects or starts an invalid revision read.
        let empty = AuditHistory {
            revisions: vec![],
            has_more: false,
            source_freshness_checked: false,
        };
        app.complete(Completed {
            kind: Kind::AuditHistory,
            code: 0,
            stdout: serde_json::to_vec(&empty).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        app.key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        app.key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.job.is_none());
        assert!(app.status_error);
        app.editor = Some(Editor {
            kind: Edit::Project,
            value: app.project.to_string_lossy().into(),
        });
        app.accept_editor().unwrap();
        assert!(app.audit_history.is_none());
        assert_eq!(app.audit_revision_selected, 0);
        assert!(app.intelligence_text.contains("Project changed"));
    }

    fn owned_idle_worker(kind: Kind) -> Job {
        #[cfg(windows)]
        let mut command = Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/c", "exit", "0"]);
        #[cfg(unix)]
        let mut command = Command::new("sh");
        #[cfg(unix)]
        command.args(["-c", "exit 0"]);
        Job::spawn(command, kind, Duration::from_secs(5)).unwrap()
    }

    fn cancellation_app() -> App {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        let jobs = serde_json::json!({"jobs":[{
            "id":"a".repeat(64), "state":"running", "created_at":"today",
            "source_snapshot":"snapshot", "units_recorded":0, "total_files":2,
            "attempts_reserved":1, "max_attempts":2, "elapsed_ms":0,
            "max_elapsed_ms":60000, "active_file":"a.py"
        }], "has_more":false, "source_freshness_checked":false});
        app.complete(Completed {
            kind: Kind::JobList,
            code: 0,
            stdout: serde_json::to_vec(&jobs).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        app.job = Some(owned_idle_worker(Kind::JobResume));
        app
    }

    fn cancellation_record(state: &str, id: &str) -> Completed {
        let mut record = serde_json::json!({"schema_version":1,"id":id,"project_id":"test",
            "source_snapshot":"snapshot","source_manifest":{"a.py":"hash","b.py":"hash"},
            "detector_id":"detector", "state":state,"max_attempts":2,"attempts_reserved":1,
            "max_elapsed_ms":60000,"elapsed_ms":10,"active_file":"a.py","results":[],"notes":[]});
        if state == "completed" {
            record["active_file"] = serde_json::Value::Null;
            record["attempts_reserved"] = serde_json::json!(2);
            record["results"] = serde_json::json!(["a.py", "b.py"].map(|file| serde_json::json!({
                "file":file, "outcome":sentinel_core::ScanOutcome::Complete, "finding_count":0,
                "finding_ids":[], "omitted_ids":0, "coverage_notes":[]
            })));
        }
        Completed {
            kind: Kind::JobCancel,
            code: 0,
            stdout: serde_json::to_vec(&record).unwrap(),
            stderr: String::new(),
        }
    }

    #[test]
    fn concurrent_cancellation_is_the_only_second_worker_and_escape_stops_both() {
        let mut app = cancellation_app();
        assert!(app.can_cancel_running_job());
        assert!(app.start(Kind::Audit).is_err());
        // The owned unit-test executable stands in for the CLI worker here;
        // persisted cancellation itself is covered by graph/CLI integration tests.
        app.start(Kind::JobCancel).unwrap();
        assert!(app.job.is_some());
        assert!(app.cancel_job.is_some());
        assert!(!app.can_cancel_running_job());
        assert!(app.start(Kind::JobCancel).is_err());
        app.job.take(); // Primary completion must not unlock project/settings changes.
        assert!(app.busy());
        app.open_editor(Edit::Project);
        assert!(app.editor.is_none());
        assert!(app.start(Kind::JobResume).is_err());
        app.job = Some(owned_idle_worker(Kind::JobResume));
        app.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.busy());
    }

    #[test]
    fn acknowledged_cancellation_stops_resume_and_invalid_records_do_not() {
        let mut app = cancellation_app();
        let prior_text = app.intelligence_text.clone();
        assert!(app
            .finish_cancellation(cancellation_record("cancelled", &"b".repeat(64)))
            .is_err());
        assert_eq!(app.intelligence_text, prior_text);
        assert!(app.job.is_some());
        assert!(app
            .finish_cancellation(Completed {
                kind: Kind::JobCancel,
                code: 2,
                stdout: vec![],
                stderr: "cancel failed".into()
            })
            .is_err());
        assert!(app.job.is_some());
        app.finish_cancellation(cancellation_record("cancelled", &"a".repeat(64)))
            .unwrap();
        assert!(!app.busy());
        assert!(app.status.contains("Cancelled"));
        assert!(app.intelligence_text.contains("\"attempts_reserved\": 1"));
        assert!(app.intelligence_text.contains("\"max_attempts\": 2"));
    }

    #[test]
    fn completion_before_cancellation_preserves_the_actual_terminal_state() {
        let mut app = cancellation_app();
        app.finish_cancellation(cancellation_record("completed", &"a".repeat(64)))
            .unwrap();
        assert!(app.job.is_some());
        assert!(app.status.contains("Completed"));
        assert!(!app.status.contains("Cancelled"));
        app.job.take();
        app.finish_cancellation(cancellation_record("cancelled", &"a".repeat(64)))
            .unwrap();
        assert!(app.status.contains("Cancelled"));
    }

    #[test]
    fn responses_are_retained_and_preview_preserves_conversation() {
        let mut app = App::new(std::env::current_dir().unwrap()).unwrap();
        app.question = "Compare these approaches".into();
        #[cfg(windows)]
        let mut command = Command::new("cmd.exe");
        #[cfg(windows)]
        command.args(["/c", "exit", "0"]);
        #[cfg(unix)]
        let mut command = Command::new("sh");
        #[cfg(unix)]
        command.args(["-c", "exit 0"]);
        app.job = Some(Job::spawn(command, Kind::Explain, Duration::from_secs(5)).unwrap());
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        assert_eq!(app.question, "Compare these approaches");
        assert!(!app.chat_context);
        app.view = View::Ai;
        app.navigation_focus = false;
        app.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::ALT));
        assert_eq!(app.question, "Compare these approaches");
        // Drafting the next message is allowed without relabelling the pending answer.
        app.key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(app.chat_input, "x");
        app.job.take();
        let output = serde_json::json!({"context_id":"test", "responses":[{"provider":"ollama","model":"local","text":"First answer"},{"provider":"nvidia-nim","model":"cloud","text":"Second answer"}], "failures":[], "coverage_notes":[]});
        app.complete(Completed {
            kind: Kind::Explain,
            code: 0,
            stdout: serde_json::to_vec(&output).unwrap(),
            stderr: String::new(),
        })
        .unwrap();
        assert_eq!(app.chat_history.len(), 2);
        assert_eq!(app.chat_history[0].content, "Compare these approaches");
        assert!(app.chat_history[1].content.contains("First answer"));
        assert!(app.chat_history[1].content.contains("Second answer"));
        let transcript = app.ai_text.clone();
        app.complete(Completed {
            kind: Kind::Preview,
            code: 0,
            stdout: b"{}".to_vec(),
            stderr: String::new(),
        })
        .unwrap();
        assert!(app.chat_preview.is_some());
        assert_eq!(app.ai_text, transcript);
        assert_eq!(app.chat_history.len(), 2);
    }
}
