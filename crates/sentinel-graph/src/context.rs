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
    pub target: String,
    pub target_symbols: Vec<SymbolInfo>,
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
        for edge in snapshot
            .edges
            .iter()
            .filter(|e| e.kind == "IMPORTS" && e.resolved && target_files.contains(e.file.as_str()))
        {
            if let Some(module) = snapshot
                .files
                .iter()
                .flat_map(|f| &f.symbols)
                .find(|s| s.id == edge.to)
            {
                for symbol in snapshot
                    .files
                    .iter()
                    .flat_map(|f| &f.symbols)
                    .filter(|s| s.location.file == module.location.file)
                {
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
        let mut candidates: Vec<(String, ContextItem)> = vec![];
        let push = |candidates: &mut Vec<(String, ContextItem)>,
                    key: String,
                    score: u16,
                    reason: &str,
                    evidence: ContextEvidence| {
            if let Some((_, item)) = candidates.iter_mut().find(|(existing, _)| existing == &key) {
                item.relevance_score = item.relevance_score.max(score);
                if !item.reason_selected.iter().any(|r| r == reason) {
                    item.reason_selected.push(reason.into());
                }
                return;
            }
            candidates.push((
                key,
                ContextItem {
                    relevance_score: score,
                    reason_selected: vec![reason.into()],
                    evidence,
                },
            ))
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
            if scores.contains_key(&edge.from) || target_ids.contains(edge.to.as_str()) {
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
        for finding in self.db.list_findings(true)? {
            let relative = finding
                .file
                .strip_prefix(&self.root)
                .ok()
                .map(|p| p.to_string_lossy().replace('\\', "/"));
            if relative.as_ref().is_some_and(|file| {
                snapshot.files.iter().any(|f| {
                    f.path == *file && f.symbols.iter().any(|s| scores.contains_key(&s.id))
                })
            }) {
                push(
                    &mut candidates,
                    format!("finding:{}", finding.id),
                    90,
                    "existing finding in target file; scan history may predate current source",
                    ContextEvidence::Finding(finding),
                );
            }
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
        if let Some(git) = git {
            for file in git.changed.into_iter().chain(git.deleted) {
                if target_files.contains(file.as_str())
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
        candidates.sort_by(|(ka, a), (kb, b)| {
            b.relevance_score
                .cmp(&a.relevance_score)
                .then_with(|| ka.cmp(kb))
        });
        let omitted_count = candidates.len().saturating_sub(max_items);
        Ok(SecurityContext {
            target: target.into(),
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
            complete: snapshot.stats.complete && trace.complete,
            coverage_notes: notes,
            duration_ms: start.elapsed().as_millis(),
        })
    }
}
