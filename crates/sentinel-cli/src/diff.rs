use anyhow::Result;
use sentinel_core::ScanReport;
use sentinel_report::render_terminal;
use sentinel_scanner::{normalize_finding, ScannerRegistry, SubprocessRunner};
use std::path::Path;
use std::process::Command;

pub fn diff() -> Result<()> {
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMRTUXB"])
        .output()
        .map_err(|e| anyhow::anyhow!("git diff failed: {}", e))?;

    if !output.status.success() {
        anyhow::bail!("git diff failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let changed_files: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    if changed_files.is_empty() {
        println!("No changed files found.");
        return Ok(());
    }

    println!("Scanning {} changed files...", changed_files.len());

    let registry = ScannerRegistry::new();
    let mut findings: Vec<sentinel_core::Finding> = Vec::new();
    let mut scanners_used: Vec<String> = Vec::new();

    for scanner in registry.available_scanners() {
        let target = Path::new(".");
        if let Ok(raw) = SubprocessRunner::run(&scanner, &["--"], target) {
            if let Ok(finding) = normalize_finding(&raw, &scanner) {
                findings.push(finding);
                scanners_used.push(scanner.clone());
            } else {
                scanners_used.push(scanner.clone());
            }
        } else {
            scanners_used.push(scanner);
        }
    }

    let report = ScanReport {
        findings: findings.clone(),
        files_scanned: changed_files.len(),
        symbols_indexed: 0,
        scanners_used: scanners_used.clone(),
        duration_ms: 0,
    };

    render_terminal(&report);
    Ok(())
}
