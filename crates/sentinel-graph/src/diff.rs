//! Security-focused comparison of working-tree changes with an immutable Git ref.
use crate::{
    analysis::{path_finding, trace_snapshot},
    resolve_edges, Engine, IndexStats, Snapshot,
};
use anyhow::Result;
use sentinel_core::evidence::{
    CandidateAssessment, DetectorProvenance, EvidenceRecord, EvidenceSnapshot,
};
use sentinel_core::{security::*, Finding};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffScan {
    pub repository: String,
    pub base_commit: String,
    pub changed_files: Vec<String>,
    pub affected_files: Vec<String>,
    pub new_findings: Vec<Finding>,
    pub resolved_findings: Vec<Finding>,
    pub unchanged_findings: Vec<Finding>,
    pub unclassified_findings: Vec<Finding>,
    pub changed_taint_paths: Vec<TaintPath>,
    pub remaining_taint_paths: Vec<TaintPath>,
    pub complete: bool,
    pub coverage_notes: Vec<String>,
    pub omitted_count: usize,
    pub duration_ms: u128,
    #[serde(default)]
    pub before_snapshot: Option<EvidenceSnapshot>,
    #[serde(default)]
    pub after_snapshot: Option<EvidenceSnapshot>,
    #[serde(default)]
    pub before_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub after_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub before_detector: Option<DetectorProvenance>,
    #[serde(default)]
    pub after_detector: Option<DetectorProvenance>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Assessed {
    pub findings: Vec<Finding>,
    pub keys: Vec<String>,
    pub taint: TraceReport,
    pub complete: bool,
    pub notes: Vec<String>,
    #[serde(default)]
    pub snapshot: Option<EvidenceSnapshot>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub detector: Option<DetectorProvenance>,
}
fn logical_key(
    root: &std::path::Path,
    finding: &Finding,
    sources: &BTreeMap<String, String>,
) -> String {
    let file = finding
        .file
        .strip_prefix(root)
        .unwrap_or(&finding.file)
        .to_string_lossy()
        .replace('\\', "/");
    if let Some(id) = finding
        .evidence
        .iter()
        .find_map(|e| e.strip_prefix("flow_id: "))
    {
        return identity((&file, &finding.title, id));
    }
    let code = sources
        .get(&file)
        .and_then(|s| s.lines().nth(finding.line.saturating_sub(1)))
        .unwrap_or("")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    identity((&file, &finding.title, &finding.category, code))
}

fn bundled(
    root: &std::path::Path,
    files: &[String],
    sources: &BTreeMap<String, String>,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let engine = sentinel_scanner::RuleEngine::load_from_embedded_validated()?;
    let mut findings = vec![];
    let mut notes = vec![];
    for file in files {
        if let Some(source) = sources.get(file) {
            let path = root.join(file);
            let language = sentinel_ast::detect_language(&path).unwrap_or_default();
            match engine.scan_checked(&language, source, &path) {
                Ok(mut hits) => findings.append(&mut hits),
                Err(e) => notes.push(format!("{file}: {e}")),
            }
        }
    }
    Ok((findings, notes))
}
pub(crate) fn assess(
    root: &std::path::Path,
    snapshot: &Snapshot,
    files: &[String],
    sources: &BTreeMap<String, String>,
) -> Result<Assessed> {
    let (mut findings, mut notes) = bundled(root, files, sources)?;
    let rule_sources: BTreeMap<_, _> = files
        .iter()
        .filter_map(|file| {
            sources
                .get(file)
                .map(|source| (file.clone(), identity(source)))
        })
        .collect();
    let graph_sources: BTreeMap<_, _> = snapshot
        .files
        .iter()
        .map(|file| (file.path.clone(), file.content_hash.clone()))
        .collect();
    for (file, rule_hash) in &rule_sources {
        if graph_sources
            .get(file)
            .is_some_and(|graph_hash| graph_hash != rule_hash)
        {
            notes.push(format!(
                "{file}: source changed between graph indexing and rule assessment"
            ));
        }
    }
    let evidence_snapshot = EvidenceSnapshot::new(rule_sources, graph_sources);
    let mut taint = trace_snapshot(snapshot, TraceLimits::default());
    taint
        .paths
        .retain(|p| p.path.iter().any(|s| files.contains(&s.location.file)));
    findings.extend(taint.paths.iter().map(|p| path_finding(root, p)));
    notes.extend(snapshot.stats.coverage_notes.clone());
    notes.extend(taint.coverage_notes.clone());
    let complete = notes.is_empty() && snapshot.stats.complete && taint.complete;
    let keys = findings
        .iter()
        .map(|f| logical_key(root, f, sources))
        .collect();
    let detector = DetectorProvenance {
        engine_version: env!("CARGO_PKG_VERSION").into(),
        rule_set_id: sentinel_scanner::rules::embedded_rule_set_id(),
        semantics_revision: ANALYSIS_SEMANTICS_REVISION,
    };
    let evidence = findings.iter().map(|finding| {
        let file = finding.file.strip_prefix(root).unwrap_or(&finding.file)
            .to_string_lossy().replace('\\', "/");
        let traces: Vec<_> = taint.paths.iter().filter(|path| {
            finding.evidence.iter().any(|item| item == &format!("flow_id: {}", path.id))
        }).cloned().collect();
        EvidenceRecord {
            schema_version: 1,
            finding_id: finding.id.clone(),
            snapshot_id: evidence_snapshot.id.clone(),
            location: Location { file, start_line: finding.line, end_line: finding.line },
            detector: detector.clone(),
            assessment: CandidateAssessment::NeedsValidation,
            confidence_basis: if traces.is_empty() {
                "Syntactic rule match; runtime API identity and exploitability are unverified".into()
            } else {
                "Bounded syntactic interprocedural trace; confidence is heuristic, not a probability".into()
            },
            assumptions: vec!["Graph and rule manifests cover declared analysis scope only".into(),
                "No target code was executed; a match is a candidate, not confirmed exploitation".into()],
            traces,
        }
    }).collect();
    Ok(Assessed {
        findings,
        keys,
        taint,
        complete,
        notes,
        snapshot: Some(evidence_snapshot),
        evidence,
        detector: Some(detector),
    })
}
fn base_snapshot(
    engine: &Engine,
    commit: &str,
) -> Result<(Snapshot, BTreeMap<String, String>, BTreeSet<String>)> {
    let tree = sentinel_scanner::git::read(
        &engine.root,
        &["ls-tree", "-r", "-z", commit],
        4 * 1024 * 1024,
    )?;
    let mut files = vec![];
    let mut tracked = BTreeSet::new();
    let mut sources = BTreeMap::new();
    let mut stats = IndexStats {
        complete: true,
        ..Default::default()
    };
    let mut bytes = 0;
    for item in tree.split('\0').filter(|s| !s.is_empty()) {
        let Some((meta, path)) = item.split_once('\t') else {
            anyhow::bail!("invalid Git tree response");
        };
        if !matches!(meta.split_whitespace().next(), Some("100644" | "100755")) {
            continue;
        }
        tracked.insert(path.to_string());
        if sentinel_ast::detect_language(std::path::Path::new(path)).is_none() {
            continue;
        }
        if files.len() >= 2000 {
            stats.complete = false;
            stats
                .coverage_notes
                .push("baseline file limit reached (2000)".into());
            break;
        }
        match sentinel_scanner::git::source_at(&engine.root, commit, path) {
            Ok(source) => {
                bytes += source.len();
                if bytes > 16 * 1024 * 1024 {
                    stats.complete = false;
                    stats
                        .coverage_notes
                        .push("baseline source budget reached (16 MiB)".into());
                    break;
                }
                match sentinel_ast::security::extract_security_file(
                    &engine.project_id,
                    path,
                    &source,
                ) {
                    Ok(file) => {
                        if !file.notes.is_empty() {
                            stats.complete = false;
                            stats.coverage_notes.extend(file.notes.clone());
                        }
                        files.push(file);
                    }
                    Err(e) => {
                        stats.complete = false;
                        stats.coverage_notes.push(format!("baseline {path}: {e}"));
                    }
                }
                sources.insert(path.into(), source);
            }
            Err(e) => {
                stats.complete = false;
                stats.coverage_notes.push(format!("baseline {path}: {e}"));
            }
        }
    }
    let edges = resolve_edges(&engine.project_id, &files);
    Ok((
        Snapshot {
            files,
            edges,
            stats,
        },
        sources,
        tracked,
    ))
}
pub(crate) fn compare(
    root: &std::path::Path,
    base_commit: String,
    changed_files: Vec<String>,
    affected_files: Vec<String>,
    before: Assessed,
    after: Assessed,
    duration_ms: u128,
) -> DiffScan {
    let mut buckets: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for (key, finding) in before.keys.into_iter().zip(before.findings) {
        buckets.entry(key).or_default().push(finding);
    }
    let complete = before.complete && after.complete;
    let mut new_findings = vec![];
    let mut unchanged_findings = vec![];
    let mut unclassified_findings = vec![];
    for (key, finding) in after.keys.into_iter().zip(after.findings) {
        if buckets.get_mut(&key).and_then(Vec::pop).is_some() {
            unchanged_findings.push(finding);
        } else if before.complete {
            new_findings.push(finding);
        } else {
            unclassified_findings.push(finding);
        }
    }
    let resolved_findings = if complete {
        buckets.into_values().flatten().collect()
    } else {
        vec![]
    };
    let old_paths = before
        .taint
        .paths
        .iter()
        .map(|p| p.id.as_str())
        .collect::<BTreeSet<_>>();
    let changed_taint_paths = after
        .taint
        .paths
        .iter()
        .filter(|p| !old_paths.contains(p.id.as_str()))
        .cloned()
        .collect();
    let remaining_taint_paths = after.taint.paths.clone();
    let mut coverage_notes = before.notes;
    coverage_notes.extend(after.notes);
    if before.snapshot.is_none() {
        coverage_notes.push("Legacy baseline has no typed source manifest; historical evidence was not reconstructed".into());
    }
    if !complete {
        coverage_notes.push("Incomplete comparison: resolution is withheld and absence of new findings cannot establish PASS.".into());
    }
    DiffScan {
        repository: root.to_string_lossy().into(),
        base_commit,
        changed_files,
        affected_files,
        new_findings,
        resolved_findings,
        unchanged_findings,
        unclassified_findings,
        changed_taint_paths,
        remaining_taint_paths,
        complete,
        coverage_notes,
        omitted_count: 0,
        duration_ms,
        before_snapshot: before.snapshot,
        after_snapshot: after.snapshot,
        before_evidence: before.evidence,
        after_evidence: after.evidence,
        before_detector: before.detector,
        after_detector: after.detector,
    }
}
impl Engine {
    /// Compare changed and security-neighbor files with a validated Git ref (HEAD by default).
    /// Changed source is never checked out or executed.
    pub fn scan_diff(&self, base: Option<&str>) -> Result<DiffScan> {
        let start = Instant::now();
        let changes = sentinel_scanner::git::changes(
            &self.root,
            Some(base.unwrap_or("HEAD")),
            false,
            false,
            false,
        )?;
        if changes.root != self.root {
            anyhow::bail!(
                "diff security analysis requires the configured repository to be the Git root"
            );
        }
        self.index()?;
        let current = self.snapshot()?;
        let commit = changes.base_commit.unwrap();
        let (mut baseline, mut old_sources, tracked) = base_snapshot(self, &commit)?;
        let mut affected = changes
            .changed
            .iter()
            .chain(&changes.deleted)
            .cloned()
            .collect::<BTreeSet<_>>();
        // Include call neighbors from both snapshots so removed or introduced edges are covered.
        for snapshot in [&current, &baseline] {
            let changed_ids = snapshot
                .files
                .iter()
                .filter(|f| affected.contains(&f.path))
                .flat_map(|f| &f.symbols)
                .map(|s| s.id.as_str())
                .collect::<BTreeSet<_>>();
            let mut neighbor_ids = BTreeSet::new();
            for edge in snapshot
                .edges
                .iter()
                .filter(|e| e.kind == "CALLS" && e.resolved)
            {
                if changed_ids.contains(edge.from.as_str()) {
                    neighbor_ids.insert(edge.to.as_str());
                }
                if changed_ids.contains(edge.to.as_str()) {
                    neighbor_ids.insert(edge.from.as_str());
                }
            }
            for symbol in snapshot.files.iter().flat_map(|f| &f.symbols) {
                if neighbor_ids.contains(symbol.id.as_str()) {
                    affected.insert(symbol.location.file.clone());
                }
            }
        }
        let affected = affected.into_iter().collect::<Vec<_>>();
        let mut sources = BTreeMap::new();
        let mut current_notes = vec![];
        for file in &affected {
            if let Ok(path) = self.checked_path(file) {
                if sentinel_ast::detect_language(std::path::Path::new(file)).is_some()
                    && !current.files.iter().any(|f| f.path == *file)
                {
                    current_notes.push(format!(
                        "{file}: changed source is outside the current indexed scope"
                    ));
                }
                match std::fs::metadata(&path).and_then(|m| {
                    if m.len() > 1024 * 1024 {
                        Err(std::io::Error::other("source exceeds 1 MiB"))
                    } else {
                        std::fs::read_to_string(&path)
                    }
                }) {
                    Ok(source) => {
                        sources.insert(file.clone(), source);
                    }
                    Err(e) => current_notes.push(format!("{file}: {e}")),
                }
            } else if self.root.join(file).try_exists().unwrap_or(true) {
                current_notes.push(format!(
                    "{file}: path is outside the allowed scope or unreadable"
                ));
            }
            // Non-code changed files can still be covered by explicit text rules.
            if !old_sources.contains_key(file) && tracked.contains(file) {
                match sentinel_scanner::git::source_at(&self.root, &commit, file) {
                    Ok(source) => {
                        old_sources.insert(file.clone(), source);
                    }
                    Err(e) => {
                        baseline.stats.complete = false;
                        baseline
                            .stats
                            .coverage_notes
                            .push(format!("baseline {file}: {e}"));
                    }
                }
            }
        }
        let before = assess(&self.root, &baseline, &affected, &old_sources)?;
        let mut after = assess(&self.root, &current, &affected, &sources)?;
        if !current_notes.is_empty() {
            after.complete = false;
            after.notes.extend(current_notes);
        }
        Ok(compare(
            &self.root,
            commit,
            changes.changed.into_iter().chain(changes.deleted).collect(),
            affected,
            before,
            after,
            start.elapsed().as_millis(),
        ))
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;
    #[test]
    fn changed_source_after_indexing_is_incomplete() {
        let original = "import hashlib\nvalue = hashlib.md5(password)\n";
        let indexed =
            sentinel_ast::security::extract_security_file("test", "main.py", original).unwrap();
        let snapshot = Snapshot {
            files: vec![indexed],
            edges: vec![],
            stats: IndexStats {
                complete: true,
                ..Default::default()
            },
        };
        let sources = BTreeMap::from([(
            "main.py".into(),
            "import hashlib\nvalue = hashlib.sha256(password)\n".into(),
        )]);
        let assessed = assess(
            std::path::Path::new("."),
            &snapshot,
            &["main.py".into()],
            &sources,
        )
        .unwrap();
        assert!(!assessed.complete);
        assert!(assessed
            .notes
            .iter()
            .any(|note| note.contains("source changed")));
    }
}
