use anyhow::Result;
use sentinel_ast::{walk, SymbolExtractor};
use sentinel_core::ScanReport;
use sentinel_db::SentinelDb;
use sentinel_report::render_terminal;
use sentinel_scanner::{normalize_finding, rules::RuleEngine, ScannerRegistry, SubprocessRunner};
use std::path::Path;
use std::time::Instant;

pub fn audit(path: String) -> Result<()> {
    let start = Instant::now();
    let target = Path::new(&path);
    if !target.exists() {
        anyhow::bail!("path does not exist: {}", path);
    }

    let files = walk(&path)?;
    let extractor = SymbolExtractor::new();
    let registry = ScannerRegistry::new();
    let mut total_symbols = 0usize;
    let mut findings: Vec<sentinel_core::Finding> = Vec::new();
    let mut scanners_used: Vec<String> = Vec::new();

    for entry in &files {
        if let Ok(source) = std::fs::read(&entry.path) {
            if let Ok(symbols) = extractor.extract(&entry.path, &source) {
                total_symbols += symbols.len();
            }
        }
    }

    for scanner in registry.available_scanners() {
        match SubprocessRunner::run(&scanner, &[], target) {
            Ok(raw) => match normalize_finding(&raw, &scanner) {
                Ok(finding) => {
                    findings.push(finding);
                    scanners_used.push(scanner.clone());
                }
                Err(_) => {
                    scanners_used.push(scanner.clone());
                }
            },
            Err(_) => {
                scanners_used.push(scanner);
            }
        }
    }

    let engine = RuleEngine::load_from_dir(&(env!("CARGO_MANIFEST_DIR").to_owned() + "/../sentinel-scanner/rules"));
    let mut rule_findings = Vec::new();
    if let Ok(engine) = &engine {
        for entry in &files {
            if let Ok(source) = std::fs::read(&entry.path) {
                if let Ok(text) = String::from_utf8(source) {
                    let lang = entry.language.as_deref().unwrap_or("");
                    let mut hits = engine.scan(lang, &text, &entry.path);
                    rule_findings.append(&mut hits);
                }
            }
        }
        if !rule_findings.is_empty() {
            scanners_used.push("bundled-rules".to_string());
        }
    }
    findings.extend(rule_findings);

    let db_path = target.join(".sentinel.db");
    let db = SentinelDb::new(db_path.to_str().unwrap_or("sentinel.db"))?;
    for finding in &findings {
        let _ = db.insert_finding(finding);
    }

    let duration_ms = start.elapsed().as_millis();
    let report = ScanReport {
        findings: findings.clone(),
        files_scanned: files.len(),
        symbols_indexed: total_symbols,
        scanners_used: scanners_used.clone(),
        duration_ms,
    };

    render_terminal(&report);
    Ok(())
}
