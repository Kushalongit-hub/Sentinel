//! Resumable native static scan jobs. No target code or model is executed.
use crate::Engine;
use anyhow::{bail, Context, Result};
use rusqlite::params;
use sentinel_core::{security::identity, ScanOutcome};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Instant};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Running,
    Completed,
    Cancelled,
    Stale,
    BudgetExhausted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitResult {
    pub file: String,
    pub outcome: ScanOutcome,
    pub finding_count: usize,
    pub finding_ids: Vec<String>,
    pub omitted_ids: usize,
    pub coverage_notes: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub schema_version: u32,
    pub id: String,
    pub project_id: String,
    pub source_snapshot: String,
    pub source_manifest: BTreeMap<String, String>,
    pub detector_id: String,
    pub state: JobState,
    pub max_attempts: usize,
    pub attempts_reserved: usize,
    pub max_elapsed_ms: u64,
    pub elapsed_ms: u64,
    pub active_file: Option<String>,
    pub results: Vec<UnitResult>,
    pub notes: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct JobSummary {
    pub id: String,
    pub state: JobState,
    pub created_at: String,
    pub source_snapshot: String,
    pub units_recorded: usize,
    pub total_files: usize,
    pub attempts_reserved: usize,
    pub max_attempts: usize,
    pub elapsed_ms: u64,
    pub max_elapsed_ms: u64,
    pub active_file: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct JobList {
    pub jobs: Vec<JobSummary>,
    pub has_more: bool,
    pub source_freshness_checked: bool,
}
fn encode(job: &ScanJob) -> Result<String> {
    let payload = serde_json::to_string(job)?;
    if payload.len() > 2 * 1024 * 1024 {
        bail!("job record exceeds 2 MiB");
    }
    Ok(payload)
}
fn detector_id() -> String {
    identity((
        env!("CARGO_PKG_VERSION"),
        sentinel_core::security::ANALYSIS_SEMANTICS_REVISION,
        sentinel_scanner::rules::embedded_rule_set_id(),
    ))
}
impl Engine {
    /// Read-only, repository-bound metadata. Listing never indexes, resumes or
    /// infers freshness; a recorded Completed state is not a clean security verdict.
    pub fn list_scan_jobs(&self, limit: usize) -> Result<JobList> {
        if !(1..=100).contains(&limit) {
            bail!("job list limit must be 1..100");
        }
        let tx = self.db.connection().unchecked_transaction()?;
        let rows = {
            let mut stmt = tx.prepare("SELECT job_id,created_at FROM security_jobs WHERE project_id=?1 ORDER BY rowid DESC LIMIT ?2")?;
            let rows = stmt
                .query_map(params![self.project_id, (limit + 1) as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows
        };
        let has_more = rows.len() > limit;
        let mut jobs = Vec::new();
        for (id, created_at) in rows.into_iter().take(limit) {
            let (job, _) = self.load_job(&id)?;
            jobs.push(JobSummary {
                id: job.id,
                state: job.state,
                created_at,
                source_snapshot: job.source_snapshot,
                units_recorded: job.results.len(),
                total_files: job.source_manifest.len(),
                attempts_reserved: job.attempts_reserved,
                max_attempts: job.max_attempts,
                elapsed_ms: job.elapsed_ms,
                max_elapsed_ms: job.max_elapsed_ms,
                active_file: job.active_file,
            });
        }
        tx.commit()?;
        Ok(JobList {
            jobs,
            has_more,
            source_freshness_checked: false,
        })
    }
    fn job_manifest(&self) -> Result<BTreeMap<String, String>> {
        // ponytail: full reconciliation per admission; replace with validated incremental snapshots after large-corpus measurement.
        let stats = self.index()?;
        if !stats.complete {
            bail!("job requires a complete indexed source scope");
        }
        Ok(self
            .snapshot()?
            .files
            .into_iter()
            .map(|file| (file.path, file.content_hash))
            .collect())
    }
    fn load_job(&self, id: &str) -> Result<(ScanJob, String)> {
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid job identity");
        }
        let payload: String = self
            .db
            .connection()
            .query_row(
                "SELECT payload FROM security_jobs WHERE project_id=?1 AND job_id=?2",
                params![self.project_id, id],
                |row| row.get(0),
            )
            .context("job not found in this repository")?;
        if payload.len() > 2 * 1024 * 1024 {
            bail!("job record exceeds 2 MiB");
        }
        let job: ScanJob = serde_json::from_str(&payload)?;
        if job.schema_version != 1
            || job.id != id
            || job.project_id != self.project_id
            || job.source_snapshot != identity(&job.source_manifest)
            || !(1..=100).contains(&job.max_attempts)
            || job.attempts_reserved > job.max_attempts
            || !(1000..=3_600_000).contains(&job.max_elapsed_ms)
        {
            bail!("invalid stored job contract");
        }
        Ok((job, payload))
    }
    fn save_job(&self, job: &ScanJob, previous: &str) -> Result<String> {
        let payload = encode(job)?;
        let changed = self.db.connection().execute(
            "UPDATE security_jobs SET payload=?1 WHERE project_id=?2 AND job_id=?3 AND payload=?4",
            params![payload, self.project_id, job.id, previous],
        )?;
        if changed != 1 {
            bail!("job changed concurrently; reload status before continuing");
        }
        Ok(payload)
    }
    /// Freeze the complete indexed code scope. Attempt/time limits cannot increase on resume.
    pub fn create_scan_job(&self, max_attempts: usize, max_seconds: u64) -> Result<ScanJob> {
        if !(1..=100).contains(&max_attempts) || !(1..=3600).contains(&max_seconds) {
            bail!("job budgets: attempts 1..100, seconds 1..3600");
        }
        let manifest = self.job_manifest()?;
        if manifest.is_empty() {
            bail!("no supported indexed source files");
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let job = ScanJob { schema_version:1, id:identity((&self.project_id,nonce,std::process::id())),
            project_id:self.project_id.clone(), source_snapshot:identity(&manifest),source_manifest:manifest,
            detector_id:detector_id(),state:JobState::Pending,max_attempts,attempts_reserved:0,max_elapsed_ms:max_seconds*1000,
            elapsed_ms:0,active_file:None,results:vec![],notes:vec![
                "Static indexed-code scope only; completion does not confirm vulnerabilities or establish full audit coverage.".into(),
                "Time budget is checked between bounded units, not an OS-enforced worker deadline.".into()] };
        self.db.connection().execute(
            "INSERT INTO security_jobs(project_id,job_id,payload) VALUES (?1,?2,?3)",
            params![self.project_id, job.id, encode(&job)?],
        )?;
        Ok(job)
    }
    /// Status is a stored record; only resume reconciles its source manifest.
    pub fn scan_job_status(&self, id: &str) -> Result<ScanJob> {
        Ok(self.load_job(id)?.0)
    }
    pub fn cancel_scan_job(&self, id: &str) -> Result<ScanJob> {
        let (mut job, previous) = self.load_job(id)?;
        if matches!(job.state, JobState::Pending | JobState::Running) {
            job.state = JobState::Cancelled;
            job.notes.push("Cancelled; an already running static unit may finish, but cannot commit this job's result.".into());
            self.save_job(&job, &previous)?;
        }
        Ok(job)
    }
    /// Reserve before scanning; interruption never refunds a possibly consumed attempt.
    pub fn resume_scan_job(
        &self,
        id: &str,
        max_units: usize,
        recover_interrupted: bool,
    ) -> Result<ScanJob> {
        if !(1..=100).contains(&max_units) {
            bail!("resume units must be 1..100");
        }
        let (mut job, mut previous) = self.load_job(id)?;
        if job.state == JobState::Running {
            if !recover_interrupted {
                bail!("job is running or interrupted; use explicit recovery after stopping its previous worker");
            }
            // Lost worker duration is unknown; conservatively consume the remaining time budget.
            job.state = JobState::BudgetExhausted;
            job.active_file = None;
            job.elapsed_ms = job.max_elapsed_ms;
            job.notes.push("Interrupted attempt retained its reservation; unknown elapsed time exhausted the budget. Create a new job to continue.".into());
            self.save_job(&job, &previous)?;
            return Ok(job);
        }
        if job.state != JobState::Pending {
            return Ok(job);
        }
        if job.detector_id != detector_id() {
            job.state = JobState::Stale;
            job.notes
                .push("Detector identity changed; create a fresh job.".into());
            self.save_job(&job, &previous)?;
            return Ok(job);
        }
        for _ in 0..max_units {
            if job.attempts_reserved >= job.max_attempts || job.elapsed_ms >= job.max_elapsed_ms {
                job.state = JobState::BudgetExhausted;
                self.save_job(&job, &previous)?;
                break;
            }
            let started = Instant::now();
            match self.job_manifest() {
                Ok(manifest) if manifest == job.source_manifest => {}
                _ => {
                    job.state = JobState::Stale;
                    job.notes.push(
                        "Source scope changed or could not be reconciled; create a fresh job."
                            .into(),
                    );
                    self.save_job(&job, &previous)?;
                    break;
                }
            }
            let Some(file) = job
                .source_manifest
                .keys()
                .find(|file| !job.results.iter().any(|r| &r.file == *file))
                .cloned()
            else {
                job.state = JobState::Completed;
                self.save_job(&job, &previous)?;
                break;
            };
            job.active_file = Some(file.clone());
            job.state = JobState::Running;
            job.attempts_reserved += 1;
            previous = self.save_job(&job, &previous)?;
            let scan = self.scan_file(&file);
            job.active_file = None;
            match scan {
                Ok(scan) => {
                    match self.job_manifest() {
                        Ok(manifest) if manifest == job.source_manifest => {}
                        _ => {
                            job.state = JobState::Stale;
                            job.notes.push(
                                "Source changed during the unit; result not admitted.".into(),
                            );
                            self.save_job(&job, &previous)?;
                            break;
                        }
                    }
                    let report = scan.report;
                    let finding_count = report.findings.len();
                    job.state = if report.outcome == ScanOutcome::Complete {
                        JobState::Pending
                    } else {
                        JobState::Failed
                    };
                    job.results.push(UnitResult {
                        file,
                        outcome: report.outcome,
                        finding_count,
                        finding_ids: report
                            .findings
                            .into_iter()
                            .take(500)
                            .map(|f| f.id)
                            .collect(),
                        omitted_ids: finding_count.saturating_sub(500),
                        coverage_notes: report.coverage_notes,
                    });
                }
                Err(error) => {
                    job.state = JobState::Failed;
                    job.notes.push(format!(
                        "Static unit failed: {}",
                        error.to_string().chars().take(500).collect::<String>()
                    ));
                }
            }
            job.elapsed_ms = job
                .elapsed_ms
                .saturating_add(started.elapsed().as_millis().min(u64::MAX as u128) as u64);
            if job.state == JobState::Pending && job.elapsed_ms >= job.max_elapsed_ms {
                job.state = JobState::BudgetExhausted;
            }
            if job.state == JobState::Pending && job.results.len() == job.source_manifest.len() {
                job.state = JobState::Completed;
            }
            previous = self.save_job(&job, &previous)?;
            if job.state != JobState::Pending {
                break;
            }
        }
        Ok(job)
    }
}
