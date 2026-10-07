//! Baseline debt tracking and deterministic patch verification.
use crate::{
    diff::{assess, compare, Assessed, DiffScan},
    Engine,
};
use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension};
use sentinel_core::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Verification {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub regressed_findings: Vec<Finding>,
    #[serde(flatten)]
    pub comparison: DiffScan,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub project_id: String,
    pub findings: usize,
    pub files_assessed: usize,
    pub complete: bool,
    pub duration_ms: u128,
}
impl Engine {
    fn assess_project(&self) -> Result<(Assessed, Vec<String>)> {
        self.index()?;
        let snapshot = self.snapshot()?;
        let mut sources = BTreeMap::new();
        let mut notes = vec![];
        let mut paths = sentinel_ast::walk(self.root.to_str().context("invalid root path")?)?;
        paths.sort_by(|a, b| a.path.cmp(&b.path));
        let mut bytes = 0;
        let mut files = vec![];
        for path in paths {
            if files.len() >= 2000 {
                notes.push("assessment file limit reached (2000)".into());
                break;
            }
            let file = path
                .path
                .strip_prefix(&self.root)?
                .to_string_lossy()
                .replace('\\', "/");
            match self.checked_path(&file).and_then(|p| {
                if std::fs::metadata(&p)?.len() > 1024 * 1024 {
                    anyhow::bail!("source exceeds 1 MiB");
                }
                Ok(std::fs::read_to_string(p)?)
            }) {
                Ok(source) => {
                    bytes += source.len();
                    if bytes > 16 * 1024 * 1024 {
                        notes.push("assessment source budget reached (16 MiB)".into());
                        break;
                    }
                    files.push(file.clone());
                    sources.insert(file, source);
                }
                Err(e) => notes.push(format!("{file}: {e}")),
            }
        }
        let mut result = assess(&self.root, &snapshot, &files, &sources)?;
        if !notes.is_empty() {
            result.complete = false;
            result.notes.extend(notes);
        }
        Ok((result, files))
    }
    /// Freeze current findings as accepted debt. Incomplete evidence cannot create a baseline.
    pub fn create_baseline(&self) -> Result<BaselineSummary> {
        let start = Instant::now();
        let (assessment, files) = self.assess_project()?;
        if !assessment.complete {
            anyhow::bail!(
                "cannot create a baseline from incomplete analysis: {}",
                assessment.notes.join("; ")
            );
        }
        let tx = self.db.connection().unchecked_transaction()?;
        tx.execute("INSERT INTO security_baselines(project_id,payload) VALUES (?1,?2) ON CONFLICT(project_id) DO UPDATE SET payload=excluded.payload,created_at=CURRENT_TIMESTAMP",params![self.project_id,serde_json::to_string(&assessment)?])?;
        tx.execute(
            "UPDATE baseline_findings SET status='resolved' WHERE project_id=?1",
            [&self.project_id],
        )?;
        for (key, finding) in assessment.keys.iter().zip(&assessment.findings) {
            tx.execute("INSERT INTO baseline_findings(project_id,fingerprint,rule,location,status) VALUES (?1,?2,?3,?4,'active') ON CONFLICT(project_id,fingerprint) DO UPDATE SET status='active',location=excluded.location,last_seen=CURRENT_TIMESTAMP",params![self.project_id,key,finding.title,format!("{}:{}",finding.file.display(),finding.line)])?;
        }
        tx.commit()?;
        Ok(BaselineSummary {
            project_id: self.project_id.clone(),
            findings: assessment.findings.len(),
            files_assessed: files.len(),
            complete: true,
            duration_ms: start.elapsed().as_millis(),
        })
    }
    /// Compare with a saved baseline, or Git HEAD when absent. --base explicitly selects Git.
    pub fn verify_patch(&self, base: Option<&str>) -> Result<Verification> {
        let start = Instant::now();
        let saved: Option<String> = if base.is_none() {
            self.db
                .connection()
                .query_row(
                    "SELECT payload FROM security_baselines WHERE project_id=?1",
                    [&self.project_id],
                    |r| r.get(0),
                )
                .optional()?
        } else {
            None
        };
        let mut regressed = vec![];
        let comparison = if let Some(saved) = saved {
            let before: Assessed = serde_json::from_str(&saved)?;
            let (mut after, files) = self.assess_project()?;
            for finding in &before.findings {
                let relative = finding
                    .file
                    .strip_prefix(&self.root)
                    .unwrap_or(&finding.file)
                    .to_string_lossy()
                    .replace('\\', "/");
                if !files.contains(&relative) && finding.file.try_exists().unwrap_or(true) {
                    after.complete = false;
                    after.notes.push(format!("{relative}: previously assessed source is now omitted/unreadable, so resolution is withheld"));
                }
            }
            let mut stmt = self
                .db
                .connection()
                .prepare("SELECT fingerprint,status FROM baseline_findings WHERE project_id=?1")?;
            let states = stmt
                .query_map([&self.project_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<BTreeMap<_, _>, _>>()?;
            let present = after.keys.iter().cloned().collect::<BTreeSet<_>>();
            for (key, finding) in after.keys.iter().zip(&after.findings) {
                if states.get(key).is_some_and(|s| s == "resolved") {
                    regressed.push(finding.clone());
                }
            }
            if after.complete {
                let tx = self.db.connection().unchecked_transaction()?;
                for key in states.keys() {
                    tx.execute("UPDATE baseline_findings SET status=?1,last_seen=CASE WHEN ?1='active' THEN CURRENT_TIMESTAMP ELSE last_seen END WHERE project_id=?2 AND fingerprint=?3",params![if present.contains(key){"active"}else{"resolved"},self.project_id,key])?;
                }
                for (key, finding) in after.keys.iter().zip(&after.findings) {
                    tx.execute("INSERT INTO baseline_findings(project_id,fingerprint,rule,location,status) VALUES (?1,?2,?3,?4,'active') ON CONFLICT(project_id,fingerprint) DO UPDATE SET status='active',location=excluded.location,last_seen=CURRENT_TIMESTAMP",params![self.project_id,key,finding.title,format!("{}:{}",finding.file.display(),finding.line)])?;
                }
                tx.commit()?;
            }
            let changed =
                sentinel_scanner::git::changes(&self.root, Some("HEAD"), false, false, false)
                    .map(|c| c.changed.into_iter().chain(c.deleted).collect())
                    .unwrap_or_default();
            compare(
                &self.root,
                "saved-baseline".into(),
                changed,
                files,
                before,
                after,
                start.elapsed().as_millis(),
            )
        } else {
            self.scan_diff(base)?
        };
        let regression_ids = regressed
            .iter()
            .map(|f| f.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut comparison = comparison;
        comparison
            .unchanged_findings
            .retain(|f| !regression_ids.contains(f.id.as_str()));
        comparison
            .new_findings
            .retain(|f| !regression_ids.contains(f.id.as_str()));
        let added = comparison
            .new_findings
            .iter()
            .chain(&regressed)
            .collect::<Vec<_>>();
        let fail = added
            .iter()
            .any(|f| f.severity >= Severity::High && f.confidence >= 0.5)
            || (comparison.complete
                && comparison
                    .changed_taint_paths
                    .iter()
                    .any(|p| p.confidence != "low"));
        let mut reasons = vec![];
        let detector_changed = comparison
            .before_detector
            .as_ref()
            .zip(comparison.after_detector.as_ref())
            .is_none_or(|(before, after)| before != after);
        let verdict = if fail {
            reasons.push("New or regressed high/critical findings or dangerous taint paths require remediation.".into());
            Verdict::Fail
        } else if !comparison.complete
            || detector_changed
            || comparison.before_snapshot.is_none()
            || comparison.after_snapshot.is_none()
            || !added.is_empty()
            || !comparison.unclassified_findings.is_empty()
        {
            reasons.push(
                "Lower severity, low-confidence, or incomplete evidence requires review.".into(),
            );
            if comparison.before_snapshot.is_none() || comparison.after_snapshot.is_none() {
                reasons.push("A legacy assessment lacks source provenance; create a fresh baseline after reviewing current debt.".into());
            }
            if detector_changed {
                reasons.push("Detector provenance is missing or changed; review a fresh baseline before treating this comparison as PASS.".into());
            }
            Verdict::Warn
        } else {
            reasons.push(
                "No new security regressions were found within the supported analysis scope."
                    .into(),
            );
            Verdict::Pass
        };
        Ok(Verification {
            verdict,
            reasons,
            regressed_findings: regressed,
            comparison,
        })
    }
}
