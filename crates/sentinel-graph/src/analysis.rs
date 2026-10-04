use crate::{select_symbols, Engine, Snapshot, SymbolInfo};
use anyhow::{Context, Result};
use sentinel_core::{security::*, Finding, ScanOutcome, ScanReport, Severity};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScan {
    pub report: ScanReport,
    pub taint: TraceReport,
    pub duration_ms: u128,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub finding: Finding,
    pub what: String,
    pub where_location: Location,
    pub symbol: Option<SymbolInfo>,
    pub why: String,
    pub flow: Vec<TaintPath>,
    pub evidence: Vec<String>,
    pub affected_code: String,
    pub remediation_hints: Vec<String>,
    pub coverage_notes: Vec<String>,
}
/// Convert a traced potential vulnerability to the existing finding/report contract.
pub fn path_finding(root: &std::path::Path, path: &TaintPath) -> Finding {
    let mut finding = Finding {
        id: String::new(),
        severity: Severity::High,
        confidence: if path.confidence == "low" { 0.35 } else { 0.65 },
        category: "interprocedural-taint".into(),
        file: root.join(&path.sink.location.file),
        line: path.sink.location.start_line,
        title: format!("interproc-{}", path.sink_type),
        description: path.evidence.clone(),
        execution_path: path
            .path
            .iter()
            .map(|s| {
                format!(
                    "{} at {}:{}",
                    s.symbol, s.location.file, s.location.start_line
                )
            })
            .collect(),
        affected_components: vec![path.source.symbol.clone(), path.sink.symbol.clone()],
        evidence: vec![format!("flow_id: {}", path.id), path.evidence.clone()],
        recommendation: path.remediation_hint.clone(),
    };
    finding.stabilize_id();
    finding
}
pub(crate) fn trace_snapshot(snapshot: &Snapshot, limits: TraceLimits) -> TraceReport {
    let mut trace =
        sentinel_taint::interprocedural::trace_project(&snapshot.files, &snapshot.edges, limits);
    if !snapshot.stats.complete {
        trace.complete = false;
        trace
            .coverage_notes
            .extend(snapshot.stats.coverage_notes.clone());
    }
    trace
}
impl Engine {
    /// Trace current repository data flow, with explicit bounds and optional target/sink filtering.
    pub fn trace(
        &self,
        target: &str,
        sink: Option<&str>,
        limits: TraceLimits,
    ) -> Result<TraceReport> {
        if !(1..=32).contains(&limits.max_call_depth)
            || !(1..=200).contains(&limits.max_paths)
            || !(1..=100000).contains(&limits.max_nodes_visited)
        {
            anyhow::bail!("trace limits: depth 1..32, paths 1..200, nodes 1..100000");
        }
        let normalized = self.normalized_target(target)?;
        let target = normalized.as_str();
        self.index()?;
        let snapshot = self.snapshot()?;
        let mut trace = trace_snapshot(&snapshot, limits);
        let symbols = select_symbols(&snapshot, target);
        if symbols.is_empty() && !matches!(target, "" | ".") {
            anyhow::bail!("no indexed target matches; use find_symbol to inspect available names");
        }
        let ids = symbols
            .iter()
            .map(|s| s.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        trace.paths.retain(|path| {
            let selected = target.is_empty()
                || target == "."
                || ids.contains(path.source.symbol_id.as_str())
                || ids.contains(path.sink.symbol_id.as_str())
                || path
                    .path
                    .iter()
                    .any(|s| ids.contains(s.symbol_id.as_str()) || s.location.file == target)
                || path.source.operation.contains(target);
            selected && sink.is_none_or(|s| path.sink_type == s)
        });
        Ok(trace)
    }
    /// Scan one in-repository file with existing rules and relevant interprocedural flow evidence.
    pub fn scan_file(&self, path: &str) -> Result<SecurityScan> {
        let started = Instant::now();
        let path = self.checked_path(path)?;
        if !path.is_file() {
            anyhow::bail!("scan_file requires a regular file");
        }
        self.index()?;
        let snapshot = self.snapshot()?;
        let relative = path
            .strip_prefix(&self.root)?
            .to_string_lossy()
            .replace('\\', "/");
        let mut result = sentinel_scanner::run_scan(sentinel_scanner::ScanOptions {
            target: self.root.to_string_lossy().into(),
            files: vec![path.clone()],
            explicit_files: true,
            ..Default::default()
        });
        let mut taint = trace_snapshot(&snapshot, TraceLimits::default());
        taint
            .paths
            .retain(|p| p.path.iter().any(|s| s.location.file == relative));
        result
            .findings
            .extend(taint.paths.iter().map(|p| path_finding(&self.root, p)));
        if !taint.complete {
            result.outcome = ScanOutcome::Incomplete;
            result.coverage_notes.extend(taint.coverage_notes.clone());
        }
        self.db.persist_scan(sentinel_db::ScanRecord {
            id: &result.scan_id,
            target: &self.root,
            report: &result.report(),
            files: &result.files,
            full_scan: false,
        })?;
        Ok(SecurityScan {
            report: result.report(),
            taint,
            duration_ms: started.elapsed().as_millis(),
        })
    }
    /// Explain a finding using rule, location, source excerpt and graph evidence; no model is called.
    pub fn explain_finding(&self, id: &str) -> Result<FindingEvidence> {
        let finding = self
            .db
            .get_finding(id)?
            .context("finding not found in this project")?;
        let file = finding.file.clone();
        let relative = file
            .strip_prefix(&self.root)?
            .to_string_lossy()
            .replace('\\', "/");
        self.index()?;
        let snapshot = self.snapshot()?;
        let symbol = snapshot
            .files
            .iter()
            .flat_map(|f| &f.symbols)
            .filter(|s| {
                s.location.file == relative
                    && s.location.start_line <= finding.line
                    && s.location.end_line >= finding.line
            })
            .min_by_key(|s| s.location.end_line - s.location.start_line)
            .map(SymbolInfo::from);
        let taint = trace_snapshot(&snapshot, TraceLimits::default());
        let flow = taint
            .paths
            .into_iter()
            .filter(|p| {
                p.sink.location.file == relative && p.sink.location.start_line == finding.line
            })
            .take(20)
            .collect();
        let source = self
            .checked_path(&file)
            .and_then(|p| {
                if std::fs::metadata(&p)?.len() > 1024 * 1024 {
                    anyhow::bail!("source exceeds 1 MiB");
                }
                Ok(std::fs::read_to_string(p)?)
            })
            .unwrap_or_default();
        let start = finding.line.saturating_sub(4);
        let affected_code = source
            .lines()
            .enumerate()
            .skip(start)
            .take(7)
            .map(|(i, line)| format!("{}: {}", i + 1, line.chars().take(240).collect::<String>()))
            .collect::<Vec<_>>()
            .join("\n");
        let mut remediation_hints = vec![];
        if !finding.recommendation.is_empty() {
            remediation_hints.push(finding.recommendation.clone());
        }
        if remediation_hints.is_empty() {
            remediation_hints.push("Inspect the triggering rule and validate the relevant API, input trust boundary, and framework behavior before patching.".into());
        }
        let mut coverage_notes = taint.coverage_notes;
        if source.is_empty() {
            coverage_notes.push(
                "Current source excerpt is unavailable; historical finding evidence is preserved."
                    .into(),
            );
        }
        coverage_notes.push("Finding history can predate the current source snapshot; rerun a scan or verification to establish current status.".into());
        Ok(FindingEvidence {
            what: finding.description.clone(),
            where_location: Location {
                file: relative,
                start_line: finding.line,
                end_line: finding.line,
            },
            symbol,
            why: format!(
                "Deterministic rule or analysis {} ({}) produced this occurrence.",
                finding.title, finding.category
            ),
            flow,
            evidence: finding.evidence.clone(),
            affected_code,
            remediation_hints,
            coverage_notes,
            finding,
        })
    }
}
