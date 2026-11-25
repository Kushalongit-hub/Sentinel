//! Ranked, security-specific context. This is graph retrieval, not generic RAG.
use crate::{analysis::trace_snapshot, select_symbols, validate_limit, Engine, SymbolInfo};
use anyhow::Result;
use sentinel_core::{security::*, Finding};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicableRule {
    pub id: String,
    pub severity: String,
    pub languages: Vec<String>,
    pub message: String,
    pub mode: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ContextEvidence {
    Symbol(SymbolInfo),
    Relationship(SecurityEdge),
    Annotation(Annotation),
    Finding(Finding),
    Rule(ApplicableRule),
    TaintPath(TaintPath),
    ChangedFile { file: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextItem {
    pub relevance_score: u16,
    pub reason_selected: Vec<String>,
    pub evidence: ContextEvidence,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    #[serde(default)]
    pub backend: Option<AnalysisBackendIdentity>,
    #[serde(default)]
    pub source_snapshot: Option<String>,
    pub target: String,
    pub target_symbols: Vec<SymbolInfo>,
    #[serde(default)]
    pub omitted_target_symbols: Option<usize>,
    pub selected_items: Vec<ContextItem>,
    pub omitted_count: usize,
    pub complete: bool,
    pub coverage_notes: Vec<String>,
    pub duration_ms: u128,
}
impl Engine {
    /// Return bounded evidence around a symbol, file, line, or current Git diff.
    pub fn get_security_context(&self, target: &str, max_items: usize) -> Result<SecurityContext> {
        validate_limit(max_items)?;
        let normalized = self.normalized_target(target)?;
        let target = normalized.as_str();
        let start = Instant::now();
        self.index()?;
        let snapshot = self.snapshot()?;
        let mut notes = snapshot.stats.coverage_notes.clone();
        let git = sentinel_scanner::git::changes(&self.root, None, false, false, false).ok();
        let indexed_paths = snapshot
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>();
        let mut diff_scope_complete = true;
        if target == "diff" {
            if let Some(changes) = &git {
                if changes
                    .changed
                    .iter()
                    .any(|path| !indexed_paths.contains(path.as_str()))
                {
                    diff_scope_complete = false;
                    notes.push("Changed paths are outside the current indexed scope; diff context is partial.".into());
                }
                if !changes.deleted.is_empty() {
                    diff_scope_complete = false;
                    notes.push("Deleted paths have no current graph symbols; use scan_diff for baseline evidence.".into());
                }
            } else {
                diff_scope_complete = false;
            }
        }
        let targets = if target == "diff" {
            let changed = git
                .as_ref()
                .map(|g| {
                    g.changed
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            snapshot
                .files
                .iter()
                .flat_map(|f| &f.symbols)
                .filter(|s| changed.contains(s.location.file.as_str()))
                .collect::<Vec<_>>()
        } else {
            select_symbols(&snapshot, target)
        };
        if targets.is_empty() && target != "diff" {
            anyhow::bail!(
                "no indexed symbol/file matches target; use find_symbol to inspect available names"
            );
        }
        if targets.len() > 1 && !snapshot.files.iter().any(|f| f.path == target) && target != "diff"
        {
            notes.push("multiple symbols match the target; use a qualified name, ID, or file:line to narrow the context".into());
        }
        let target_ids = targets
            .iter()
            .map(|s| s.id.as_str())
            .collect::<BTreeSet<_>>();
        let target_files = targets
            .iter()
            .map(|s| s.location.file.as_str())
            .collect::<BTreeSet<_>>();
        let mut scores: BTreeMap<String, (u16, String)> = BTreeMap::new();
        for s in &targets {
            scores.insert(s.id.clone(), (100, "target symbol".into()));
        }
        for s in snapshot.files.iter().flat_map(|f| &f.symbols) {
            if target_files.contains(s.location.file.as_str()) {
                scores
                    .entry(s.id.clone())
                    .or_insert((80, "same file as target".into()));
            }
        }
        for edge in snapshot
            .edges
            .iter()
            .filter(|e| e.kind == "CALLS" && e.resolved)
        {
            if target_ids.contains(edge.from.as_str()) {
                scores
                    .entry(edge.to.clone())
                    .or_insert((70, "direct callee".into()));
            }
            if target_ids.contains(edge.to.as_str()) {
                scores
                    .entry(edge.from.clone())
                    .or_insert((70, "direct caller".into()));
            }
        }
        let files_by_id = snapshot
            .files
            .iter()
            .map(|file| (identity((&self.project_id, &file.path, "file")), file))
            .collect::<BTreeMap<_, _>>();
        for edge in snapshot
            .edges
            .iter()
            .filter(|e| e.kind == "IMPORTS" && e.resolved && target_files.contains(e.file.as_str()))
        {
            // IMPORTS endpoints identify files, not their separate module symbols.
            if let Some(module) = files_by_id.get(&edge.to) {
                for symbol in &module.symbols {
                    scores
                        .entry(symbol.id.clone())
                        .or_insert((50, "imported module dependency".into()));
                }
            }
        }
        let one_hop = scores.keys().cloned().collect::<BTreeSet<_>>();
        for edge in snapshot
            .edges
            .iter()
            .filter(|e| e.kind == "CALLS" && e.resolved)
        {
            if one_hop.contains(&edge.from) {
                scores
                    .entry(edge.to.clone())
                    .or_insert((25, "two-hop call dependency".into()));
            }
            if one_hop.contains(&edge.to) {
                scores
                    .entry(edge.from.clone())
                    .or_insert((25, "two-hop call dependency".into()));
            }
        }
        let mut candidates: BTreeMap<String, ContextItem> = BTreeMap::new();
        let push = |candidates: &mut BTreeMap<String, ContextItem>,
                    key: String,
                    score: u16,
                    reason: &str,
                    evidence: ContextEvidence| {
            candidates
                .entry(key)
                .and_modify(|item| {
                    item.relevance_score = item.relevance_score.max(score);
                    if !item.reason_selected.iter().any(|r| r == reason) {
                        item.reason_selected.push(reason.into());
                    }
                })
                .or_insert_with(|| ContextItem {
                    relevance_score: score,
                    reason_selected: vec![reason.into()],
                    evidence,
                });
        };
        for symbol in snapshot.files.iter().flat_map(|f| &f.symbols) {
            if let Some((score, reason)) = scores.get(&symbol.id) {
                push(
                    &mut candidates,
                    format!("symbol:{}", symbol.id),
                    *score,
                    reason,
                    ContextEvidence::Symbol(SymbolInfo::from(symbol)),
                );
            }
        }
        for edge in &snapshot.edges {
            if scores.contains_key(&edge.from)
                || target_ids.contains(edge.to.as_str())
                || (edge.kind == "IMPORTS" && target_files.contains(edge.file.as_str()))
            {
                let score = if edge.kind == "FLOWS_TO" { 90 } else { 70 };
                push(
                    &mut candidates,
                    format!("edge:{}", identity(edge)),
                    score,
                    if edge.resolved {
                        "AST-resolved security relationship"
                    } else {
                        "unresolved or syntactic relationship; not proof of runtime identity or guard dominance"
                    },
                    ContextEvidence::Relationship(edge.clone()),
                );
            }
        }
        for annotation in snapshot.files.iter().flat_map(|f| &f.annotations) {
            if let Some((score, _)) = scores.get(&annotation.owner) {
                push(
                    &mut candidates,
                    format!("annotation:{}", annotation.id),
                    (*score).max(
                        if matches!(annotation.kind.as_str(), "source" | "sink" | "sanitizer") {
                            90
                        } else {
                            70
                        },
                    ),
                    "security annotation in target neighborhood; API recognition is syntactic",
                    ContextEvidence::Annotation(annotation.clone()),
                );
            }
        }
        let mut trace = trace_snapshot(&snapshot, TraceLimits::default());
        trace
            .paths
            .retain(|p| p.path.iter().any(|s| scores.contains_key(&s.symbol_id)));
        for path in &trace.paths {
            let finding = crate::analysis::path_finding(&self.root, path);
            push(&mut candidates,format!("finding:{}",finding.id),90,"current interprocedural finding in target neighborhood; scan_file persists its ID for explanation",ContextEvidence::Finding(finding));
            push(
                &mut candidates,
                format!("path:{}", path.id),
                90,
                "source-to-sink relationship touches target neighborhood",
                ContextEvidence::TaintPath(path.clone()),
            );
        }
        let related_files = snapshot
            .files
            .iter()
            .filter(|file| {
                file.symbols
                    .iter()
                    .any(|symbol| scores.contains_key(&symbol.id))
            })
            .map(|file| self.root.join(&file.path))
            .collect::<Vec<_>>();
        for finding in self
            .db
            .list_active_findings_for_files(&related_files, 200)?
        {
            push(
                &mut candidates,
                format!("finding:{}", finding.id),
                90,
                "existing finding in target file; scan history may predate current source",
                ContextEvidence::Finding(finding),
            );
        }
        let languages = targets
            .iter()
            .map(|s| s.language.as_str())
            .collect::<BTreeSet<_>>();
        let engine = sentinel_scanner::RuleEngine::load_from_embedded_validated()?;
        for rule in engine.catalog().filter(|r| {
            r.languages
                .iter()
                .any(|l| languages.contains(l.as_str()) || l == "regex")
        }) {
            push(
                &mut candidates,
                format!("rule:{}", rule.id),
                90,
                "rule supports the target language; applicability does not mean the rule triggered",
                ContextEvidence::Rule(ApplicableRule {
                    id: rule.id.clone(),
                    severity: rule.severity().to_string(),
                    languages: rule.languages.clone(),
                    message: rule.message.clone(),
                    mode: rule.mode.clone().unwrap_or_else(|| "search".into()),
                }),
            );
        }
        let mut omitted_changes = 0;
        if let Some(git) = git {
            for (position, file) in git.changed.into_iter().chain(git.deleted).enumerate() {
                if target == "diff" && position >= 200 {
                    omitted_changes += 1;
                    continue;
                }
                if target == "diff"
                    || target_files.contains(file.as_str())
                    || snapshot.files.iter().any(|f| {
                        f.path == file && f.symbols.iter().any(|s| scores.contains_key(&s.id))
                    })
                {
                    push(
                        &mut candidates,
                        format!("changed:{file}"),
                        80,
                        "recent Git change in related file",
                        ContextEvidence::ChangedFile { file },
                    );
                }
            }
        } else {
            notes.push("Git change information unavailable".into());
        }
        notes.extend(trace.coverage_notes);
        notes.push("Security guards are annotations, not proof of authorization correctness. Dynamic dispatch and advanced aliasing require manual review.".into());
        let mut candidates = candidates.into_iter().collect::<Vec<_>>();
        candidates.sort_by(|(ka, a), (kb, b)| {
            b.relevance_score
                .cmp(&a.relevance_score)
                .then_with(|| ka.cmp(kb))
        });
        let omitted_count = candidates.len().saturating_sub(max_items) + omitted_changes;
        Ok(SecurityContext {
            backend: trace.backend,
            source_snapshot: trace.source_snapshot,
            target: target.into(),
            omitted_target_symbols: Some(targets.len().saturating_sub(max_items)),
            target_symbols: targets
                .into_iter()
                .take(max_items)
                .map(SymbolInfo::from)
                .collect(),
            selected_items: candidates
                .into_iter()
                .take(max_items)
                .map(|(_, item)| item)
                .collect(),
            omitted_count,
            complete: snapshot.stats.complete && trace.complete && diff_scope_complete,
            coverage_notes: notes,
            duration_ms: start.elapsed().as_millis(),
        })
    }
}
