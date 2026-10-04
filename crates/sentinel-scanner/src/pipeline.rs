use crate::{normalize_findings, RuleEngine, ScannerRegistry, SubprocessRunner};
use sentinel_ast::{walk, SymbolExtractor};
use sentinel_core::{
    Finding, ScanOutcome, ScanReport, ScannerOutcome, ScannerResult, ThresholdConfig,
};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub target: String,
    pub files: Vec<PathBuf>,
    pub explicit_files: bool,
    pub threshold: ThresholdConfig,
    pub use_bundled_rules: bool,
    pub external_scanners: bool,
    pub semgrep_config: Option<PathBuf>,
    pub scanner_timeout: Duration,
    pub max_file_bytes: u64,
}
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            target: String::new(),
            files: vec![],
            explicit_files: false,
            threshold: ThresholdConfig::default(),
            use_bundled_rules: true,
            external_scanners: false,
            semgrep_config: None,
            scanner_timeout: Duration::from_secs(60),
            max_file_bytes: 10 * 1024 * 1024,
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
    pub scan_id: String,
    pub files: Vec<PathBuf>,
    pub full_scan: bool,
    pub threshold: ThresholdConfig,
}
impl ScanPipelineResult {
    pub fn report(&self) -> ScanReport {
        ScanReport {
            findings: self.findings.clone(),
            files_scanned: self.files_scanned,
            symbols_indexed: self.symbols_indexed,
            scanners_used: self.scanners_used.clone(),
            duration_ms: self.duration_ms,
            outcome: self.outcome,
            coverage_notes: self.coverage_notes.clone(),
            scanner_results: self.scanner_results.clone(),
        }
    }
    pub fn exit_code(&self) -> i32 {
        if self.outcome != ScanOutcome::Complete {
            2
        } else if self
            .findings
            .iter()
            .any(|f| f.severity >= self.threshold.minimum_severity)
        {
            1
        } else {
            0
        }
    }
    fn incomplete(&mut self, message: impl Into<String>) {
        self.outcome = ScanOutcome::Incomplete;
        self.coverage_notes.push(message.into());
    }
}
pub fn run_scan(options: ScanOptions) -> ScanPipelineResult {
    let start = Instant::now();
    let target = Path::new(&options.target);
    let mut result = ScanPipelineResult {
        findings: vec![],
        files_scanned: 0,
        symbols_indexed: 0,
        scanners_used: vec![],
        scanner_results: vec![],
        outcome: ScanOutcome::Complete,
        coverage_notes: vec![],
        duration_ms: 0,
        scan_id: uuid::Uuid::new_v4().to_string(),
        files: vec![],
        full_scan: !options.explicit_files && options.files.is_empty(),
        threshold: options.threshold,
    };
    let selected = if options.explicit_files || !options.files.is_empty() {
        options.files.clone()
    } else {
        match walk(&options.target) {
            Ok(entries) => entries.into_iter().map(|e| e.path).collect(),
            Err(e) => {
                result.outcome = ScanOutcome::Failed;
                result.coverage_notes.push(e.to_string());
                return result;
            }
        }
    };
    if !target.exists() {
        result.outcome = ScanOutcome::Failed;
        result
            .coverage_notes
            .push(format!("target does not exist: {}", target.display()));
        return result;
    }
    let engine = if options.use_bundled_rules {
        match RuleEngine::load_from_embedded_validated() {
            Ok(e) => Some(e),
            Err(e) => {
                result.incomplete(format!("bundled rules failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    let extractor = SymbolExtractor::new();
    let mut inputs = vec![];
    for path in selected {
        let path = match path.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                result.incomplete(format!("cannot access {}: {e}", path.display()));
                continue;
            }
        };
        if !path.is_file() {
            result.incomplete(format!("not a regular file: {}", path.display()));
            continue;
        }
        if inputs.iter().any(|(p, _, _)| p == &path) {
            continue;
        }
        let language = sentinel_ast::detect_language(&path).unwrap_or_default();
        if language == "go" {
            result
                .coverage_notes
                .push(format!("unsupported language skipped: {}", path.display()));
            continue;
        }
        let bytes = match std::fs::File::open(&path).and_then(|file| {
            use std::io::Read;
            let mut bytes = vec![];
            file.take(options.max_file_bytes + 1)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        }) {
            Ok(bytes) => bytes,
            Err(e) => {
                result.incomplete(format!("file read failed: {}: {e}", path.display()));
                continue;
            }
        };
        if bytes.len() as u64 > options.max_file_bytes {
            result.incomplete(format!("file size limit exceeded: {}", path.display()));
            continue;
        }
        let source = match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => {
                if !language.is_empty() {
                    result.incomplete(format!("UTF-8 decode failed: {}", path.display()));
                } else {
                    result
                        .coverage_notes
                        .push(format!("binary file skipped: {}", path.display()));
                }
                continue;
            }
        };
        if !language.is_empty() {
            match extractor.extract(&path, source.as_bytes()) {
                Ok(symbols) => result.symbols_indexed += symbols.len(),
                Err(e) => {
                    result.incomplete(format!("symbol extraction failed: {}: {e}", path.display()));
                    continue;
                }
            }
        }
        if let Some(engine) = &engine {
            match engine.scan_checked(&language, &source, &path) {
                Ok(mut findings) => result.findings.append(&mut findings),
                Err(e) => {
                    result.incomplete(e.to_string());
                    continue;
                }
            }
        }
        result.files_scanned += 1;
        result.files.push(path.clone());
        inputs.push((path, language, source));
    }
    if engine.is_some() {
        result.scanners_used.push("bundled-rules".into());
        result.scanner_results.push(ScannerResult {
            name: "bundled-rules".into(),
            outcome: if result.outcome == ScanOutcome::Complete {
                ScannerOutcome::Completed
            } else {
                ScannerOutcome::Failed
            },
            error: if result.outcome == ScanOutcome::Complete {
                None
            } else {
                Some("incomplete source coverage".into())
            },
        });
    }
    if options.external_scanners && !inputs.is_empty() {
        let registry = ScannerRegistry::new();
        let mut available = 0;
        for name in ["semgrep", "bandit"] {
            let files: Vec<_> = inputs
                .iter()
                .filter(|(_, lang, _)| name != "bandit" || lang == "python")
                .map(|(p, _, _)| p.clone())
                .collect();
            if files.is_empty() {
                continue;
            }
            if !registry.is_available(name) {
                result.scanner_results.push(ScannerResult {
                    name: name.into(),
                    outcome: ScannerOutcome::Unavailable,
                    error: None,
                });
                continue;
            }
            available += 1;
            let external = SubprocessRunner::run(
                name,
                &files,
                options.semgrep_config.as_deref(),
                options.scanner_timeout,
            )
            .and_then(|output| {
                let mut scan = normalize_findings(&output.stdout, name)?;
                if let Some(error) = output.execution_error {
                    scan.coverage_notes.push(error);
                }
                Ok(scan)
            });
            match external {
                Ok(mut output) => {
                    for f in &mut output.findings {
                        if let Ok(path) = f.file.canonicalize() {
                            f.file = path;
                            f.stabilize_id();
                        } else {
                            output.coverage_notes.push(format!(
                                "{name} returned unresolvable path {}",
                                f.file.display()
                            ));
                        }
                    }
                    output.findings.retain(|f| files.contains(&f.file));
                    result.findings.extend(output.findings);
                    let outcome = if output.coverage_notes.is_empty() {
                        ScannerOutcome::Completed
                    } else {
                        ScannerOutcome::Failed
                    };
                    let error = (!output.coverage_notes.is_empty())
                        .then(|| output.coverage_notes.join("; "));
                    for note in output.coverage_notes {
                        result.incomplete(note);
                    }
                    if outcome == ScannerOutcome::Completed {
                        result.scanners_used.push(name.into());
                    }
                    result.scanner_results.push(ScannerResult {
                        name: name.into(),
                        outcome,
                        error,
                    });
                }
                Err(e) => {
                    result.incomplete(e.to_string());
                    result.scanner_results.push(ScannerResult {
                        name: name.into(),
                        outcome: ScannerOutcome::Failed,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        if available == 0 {
            result.incomplete("external scanners requested but no applicable scanner is available");
        }
    }
    result.duration_ms = start.elapsed().as_millis();
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> PathBuf {
        let root = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&root).unwrap();
        root
    }
    #[test]
    fn unreadable_source_is_incomplete() {
        let root = temp();
        let path = root.join("bad.js");
        std::fs::write(&path, [255]).unwrap();
        let r = run_scan(ScanOptions {
            target: root.to_string_lossy().into(),
            files: vec![path],
            ..Default::default()
        });
        assert_eq!(r.outcome, ScanOutcome::Incomplete);
        assert_eq!(r.files_scanned, 0);
        assert_eq!(r.exit_code(), 2);
    }
    #[test]
    fn missing_explicit_file_is_incomplete() {
        let root = temp();
        let r = run_scan(ScanOptions {
            target: root.to_string_lossy().into(),
            files: vec![root.join("missing.rs")],
            ..Default::default()
        });
        assert_eq!(r.exit_code(), 2);
    }
    #[test]
    fn clean_scan_records_bundled_completion() {
        let root = temp();
        std::fs::write(root.join("safe.js"), "const a = 1;").unwrap();
        let r = run_scan(ScanOptions {
            target: root.to_string_lossy().into(),
            ..Default::default()
        });
        assert_eq!(r.outcome, ScanOutcome::Complete);
        assert!(r.scanners_used.iter().any(|s| s == "bundled-rules"));
        assert_eq!(r.exit_code(), 0);
    }
}
