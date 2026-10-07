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
    pub intelligence_text: String,
    pub external: bool,
    pub semgrep: String,
    pub threshold: Severity,
    pub editor: Option<Editor>,
    pub help: bool,
    pub help_scroll: u16,
    pub status: String,
    pub status_error: bool,
    pub job: Option<Job>,
    pub tick: usize,
}
impl App {
    pub fn new(project: PathBuf) -> Result<Self> {
        let engine = sentinel_scanner::RuleEngine::load_from_embedded_validated()?;
        let mut rules = engine.catalog().cloned().collect::<Vec<_>>();
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(Self { project:project.canonicalize()?,view:View::Overview,navigation_focus:true,navigation_selected:0,report:None,rules,selected:0,rule_selected:0,filter:String::new(),scroll:0,provider:0,
            local_model:std::env::var("SENTINEL_LOCAL_MODEL").unwrap_or_else(|_|"llama2".into()),nim_model:std::env::var("SENTINEL_NIM_MODEL").unwrap_or_default(),
            question:"Explain the architecture, entry points, data flow, and testing opportunities. Cite source evidence.".into(),ai_finding:None,
            intelligence_text:"Persistent security intelligence\n\nPress g to index the repository, or w to verify the patch against a saved baseline / Git HEAD.\n\nPress u to inspect imported audit coverage and source freshness. Detailed graph and context queries are available through the repository-bound MCP server.".into(),
            ai_text:"Your code, explained.\n\nChoose a provider, inspect the shared context, and ask a question.\n\nLocal runs only Ollama. Cloud runs only NVIDIA NIM. Both runs them concurrently on identical evidence.\n\nAI answers are advisory and do not change scan findings.".into(),external:false,semgrep:String::new(),threshold:Severity::Info,editor:None,help:false,help_scroll:0,
            status:"Ready. Press a to audit this project, or ? for the keyboard guide.".into(),status_error:false,job:None,tick:0 })
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
        if self.job.is_some() && kind != Edit::Filter {
            self.notify("Wait for the operation, or press Esc to cancel it.", true);
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
                self.selected = 0;
                self.ai_finding = None;
                self.scroll = 0;
                self.ai_text = "Project changed. Preview context or ask a new question.".into();
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
    fn start(&mut self, kind: Kind) -> Result<()> {
        if self.job.is_some() {
            anyhow::bail!("an operation is already running; Esc cancels it");
        }
        self.navigation_focus = false;
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
                if !self.nim_model.is_empty() {
                    command.arg("--nim-model").arg(&self.nim_model);
                }
                if matches!(kind, Kind::Preview) {
                    command.arg("--context-only");
                }
            }
        }
        self.job = Some(Job::spawn(
            command,
            kind,
            Duration::from_secs(
                if matches!(kind, Kind::Audit | Kind::Diff | Kind::Index | Kind::Verify) {
                    600
                } else {
                    90
                },
            ),
        )?);
        self.notify(
            match kind {
                Kind::Audit => "Auditing project...",
                Kind::Diff => "Scanning Git changes...",
                Kind::Explain => "Requesting AI explanations...",
                Kind::Preview => "Building shared context preview...",
                Kind::Index => "Indexing security graph...",
                Kind::Verify => "Verifying patch...",
                Kind::AuditStatus => "Loading audit coverage and source freshness...",
            },
            false,
        );
        Ok(())
    }
    fn complete(&mut self, completed: Completed) -> Result<()> {
        match completed.kind {
            Kind::Index | Kind::Verify | Kind::AuditStatus => {
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
                let json: serde_json::Value = serde_json::from_slice(&completed.stdout)
                    .with_context(|| format!("AI command failed: {}", safe(&completed.stderr)))?;
                if matches!(completed.kind, Kind::Preview) {
                    self.ai_text = format!(
                        "SHARED CONTEXT PREVIEW\nNo provider was contacted.\n\n{}",
                        serde_json::to_string_pretty(&json)?
                    );
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
                    self.ai_text = text;
                }
                self.ai_text = safe(&self.ai_text);
                if self.ai_text.len() > 128 * 1024 {
                    let end = self
                        .ai_text
                        .char_indices()
                        .take_while(|(i, _)| *i < 128 * 1024)
                        .last()
                        .map(|(i, _)| i)
                        .unwrap_or(0);
                    self.ai_text.truncate(end);
                    self.ai_text.push_str(
                        "\n\nDisplay truncated. Use the explanation CLI for full output.",
                    );
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
    pub fn tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
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
                    self.job.take();
                    return true;
                }
                _ => {}
            }
            return false;
        }
        let action: Result<()> = match key.code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.job.take();
                return true;
            }
            KeyCode::Esc => {
                if self.job.take().is_some() {
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
            KeyCode::Char('g') => self.start(Kind::Index),
            KeyCode::Char('w') => self.start(Kind::Verify),
            KeyCode::Char('u') => self.start(Kind::AuditStatus),
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
            KeyCode::Char('m') if self.job.is_none() => {
                self.provider = (self.provider + 1) % 3;
                self.notify(format!("AI provider: {}. Cloud context is sent only when you submit an explanation.",self.provider_name()),false);
                Ok(())
            }
            KeyCode::Char('x') if self.job.is_none() => {
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
            KeyCode::Char('t') if self.job.is_none() => {
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
            KeyCode::Char('c') => {
                self.navigation_focus = false;
                self.ai_finding = None;
                self.view = View::Ai;
                self.scroll = 0;
                self.notify(
                    "Codebase selected. Enter requests an explanation; b previews context.",
                    false,
                );
                Ok(())
            }
            KeyCode::Char('e') if self.view == View::Findings => {
                if let Some(f) = self.selected_finding() {
                    let id = f.id.clone();
                    let title = f.title.clone();
                    self.ai_finding = Some(id);
                    self.question=format!("Explain {title}, relevant code behavior, impact, remediation, and regression tests.");
                    self.view = View::Ai;
                    self.scroll = 0;
                    self.notify(
                        "Finding selected for explanation. Enter submits; b previews context.",
                        false,
                    );
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("select a finding first"))
                }
            }
            KeyCode::Char('b') if self.view == View::Ai => self.start(Kind::Preview),
            KeyCode::Enter if self.navigation_focus => {
                self.view = View::from_index(self.navigation_selected);
                self.navigation_focus = false;
                self.scroll = 0;
                Ok(())
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
pub fn safe(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect::<String>()
        .replace('\t', "    ")
}
