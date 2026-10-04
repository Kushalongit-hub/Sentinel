use std::path::Path;
use std::time::Instant;

use sentinel_ast::{walk, SymbolExtractor};
use sentinel_core::{
    Finding, ScanOutcome, ScannerOutcome, ScannerResult, ThresholdConfig,
};
use sentinel_db::SentinelDb;
use sentinel_report::render_terminal;

use crate::{normalize_finding, rules::RuleEngine, ScannerRegistry, SubprocessRunner};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: String,
    pub files: Vec<std::path::PathBuf>,
    pub threshold: ThresholdConfig,
    pub use_bundled_rules: bool,
    pub external_scanners: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            files: Vec::new(),
            threshold: ThresholdConfig::default(),
            use_bundled_rules: true,
            external_scanners: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanPipelineResult {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub symbols_indexed: usize,
    pub scanners_used: Vec<String>,
    pub scanner_results: Vec<ScannerResult>,
    pub outcome: ScanOutcome,
    pub coverage_notes: Vec<String>,
    pub duration_ms: u128,
}

pub fn run_scan(options: ScanOptions) -> ScanPipelineResult {
    let start = Instant::now();
    let target = Path::new(&options.target);
    let mut findings: Vec<Finding> = Vec::new();
    let mut scanners_used: Vec<String> = Vec::new();
    let mut scanner_results: Vec<ScannerResult> = Vec::new();
    let mut coverage_notes: Vec<String> = Vec::new();
    let mut symbols_indexed = 0usize;
    let mut outcome = ScanOutcome::Complete;

    let files: Vec<sentinel_ast::FileEntry> = if options.files.is_empty() {
        if !target.exists() {
            coverage_notes.push(format!("target does not exist: {}", options.target));
            return ScanPipelineResult {
                findings,
                files_scanned: 0,
                symbols_indexed: 0,
                scanners_used: Vec::new(),
                scanner_results: Vec::new(),
                outcome: ScanOutcome::Failed,
                coverage_notes,
                duration_ms: 0,
            };
        }
        match walk(&options.target) {
            Ok(f) => f,
            Err(e) => {
                coverage_notes.push(format!("file walk failed: {}", e));
                return ScanPipelineResult {
                    findings,
                    files_scanned: 0,
                    symbols_indexed: 0,
                    scanners_used: Vec::new(),
                    scanner_results: Vec::new(),
                    outcome: ScanOutcome::Failed,
                    coverage_notes,
                    duration_ms: start.elapsed().as_millis(),
                };
            }
        }
    } else {
        options.files.into_iter().filter(|p| p.exists()).map(|p| sentinel_ast::FileEntry {
            path: p.clone(),
            language: infer_language(&p),
        }).collect()
    };

    let extractor = SymbolExtractor::new();
    for entry in &files {
        match std::fs::read(&entry.path) {
            Ok(source) => {
                match extractor.extract(&entry.path, &source) {
                    Ok(symbols) => symbols_indexed += symbols.len(),
                    Err(_) => coverage_notes.push(format!("symbol extraction failed: {}", entry.path.display())),
                }
            }
            Err(e) => coverage_notes.push(format!("file read failed: {}: {}", entry.path.display(), e)),
        }
    }
    let files_scanned = files.len();

    if options.external_scanners {
        let registry = ScannerRegistry::new();
        for scanner in registry.available_scanners() {
            match SubprocessRunner::run(&scanner, &[], target) {
                Ok(raw) => {
                    match normalize_finding(&raw, &scanner) {
                        Ok(Some(finding)) => {
                            findings.push(finding);
                            scanners_used.push(scanner.clone());
                            scanner_results.push(ScannerResult {
                                name: scanner.clone(),
                                outcome: ScannerOutcome::Completed,
                                error: None,
                            });
                        }
                        Ok(None) => {
                            scanners_used.push(scanner.clone());
                            scanner_results.push(ScannerResult {
                                name: scanner.clone(),
                                outcome: ScannerOutcome::Completed,
                                error: None,
                            });
                        }
                        Err(e) => {
                            coverage_notes.push(format!("scanner parse failed: {}: {}", scanner, e));
                            scanner_results.push(ScannerResult {
                                name: scanner.clone(),
                                outcome: ScannerOutcome::Failed,
                                error: Some(e.to_string()),
                            });
                            outcome = ScanOutcome::Incomplete;
                        }
                    }
                }
                Err(e) => {
                    coverage_notes.push(format!("scanner execution failed: {}: {}", scanner, e));
                    scanner_results.push(ScannerResult {
                        name: scanner.clone(),
                        outcome: ScannerOutcome::Failed,
                        error: Some(e.to_string()),
                    });
                    outcome = ScanOutcome::Incomplete;
                }
            }
        }
    }

    if options.use_bundled_rules {
        let rule_engine = match RuleEngine::load_from_embedded_validated() {
            Ok(e) => e,
            Err(e) => {
                coverage_notes.push(format!("bundled rules load failed: {}", e));
                outcome = ScanOutcome::Incomplete;
                return ScanPipelineResult {
                    findings,
                    files_scanned,
                    symbols_indexed,
                    scanners_used,
                    scanner_results,
                    outcome,
                    coverage_notes,
                    duration_ms: start.elapsed().as_millis(),
                };
            }
        };

        let mut rule_findings = Vec::new();
        for entry in &files {
            if let Ok(source) = std::fs::read(&entry.path) {
                match String::from_utf8(source) {
                    Ok(text) => {
                        let lang = entry.language.as_deref().unwrap_or("");
                        let mut hits = rule_engine.scan(lang, &text, &entry.path);
                        rule_findings.append(&mut hits);
                    }
                    Err(_) => coverage_notes.push(format!("utf8 decode failed: {}", entry.path.display())),
                }
            }
        }

        if !rule_findings.is_empty() {
            scanners_used.push("bundled-rules".to_string());
            scanner_results.push(ScannerResult {
                name: "bundled-rules".to_string(),
                outcome: ScannerOutcome::Completed,
                error: None,
            });
        } else if rule_engine.is_empty() {
            coverage_notes.push("bundled rules loaded but are empty".to_string());
            scanner_results.push(ScannerResult {
                name: "bundled-rules".to_string(),
                outcome: ScannerOutcome::Completed,
                error: None,
            });
        }
        findings.extend(rule_findings);
    }

    ScanPipelineResult {
        findings,
        files_scanned,
        symbols_indexed,
        scanners_used,
        scanner_results,
        outcome,
        coverage_notes,
        duration_ms: start.elapsed().as_millis(),
    }
}

pub fn persist_and_report(result: ScanPipelineResult, target: &Path) -> anyhow::Result<ScanOutcome> {
    if result.outcome == ScanOutcome::Failed {
        for note in &result.coverage_notes {
            eprintln!("[error] {}", note);
        }
        return Ok(ScanOutcome::Failed);
    }

    if !result.coverage_notes.is_empty() {
        for note in &result.coverage_notes {
            eprintln!("[warn] {}", note);
        }
    }

    let db_path = target.join(".sentinel.db");
    let db = match SentinelDb::new(db_path.to_str().unwrap_or("sentinel.db")) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("[error] database write failed: {}", e);
            return Ok(ScanOutcome::Incomplete);
        }
    };

    for finding in &result.findings {
        if let Err(e) = db.insert_finding(finding) {
            eprintln!("[error] finding persist failed: {}", e);
        }
    }

    let at_threshold = result
        .findings
        .iter()
        .any(|f| f.severity >= ThresholdConfig::default().minimum_severity);

    let report = sentinel_core::ScanReport {
        findings: result.findings.clone(),
        files_scanned: result.files_scanned,
        symbols_indexed: result.symbols_indexed,
        scanners_used: result.scanners_used,
        duration_ms: result.duration_ms,
    };

    render_terminal(&report);

    if at_threshold {
        std::process::exit(1);
    }
    Ok(result.outcome)
}

fn infer_language(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_str()?.to_lowercase();
    match extension.as_str() {
        "js" | "jsx" => Some("javascript".to_string()),
        "ts" | "tsx" => Some("typescript".to_string()),
        "py" => Some("python".to_string()),
        "rs" => Some("rust".to_string()),
        _ => None,
    }
}
