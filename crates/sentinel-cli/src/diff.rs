use anyhow::Result;
use sentinel_scanner::pipeline::{run_scan, persist_and_report, ScanOptions};
use std::path::{Path, PathBuf};

pub fn diff() -> Result<i32> {
    let output = std::process::Command::new("git")
        .args(["diff", "-z", "--name-only", "--diff-filter=ACMRTUXB"])
        .output()
        .map_err(|e| anyhow::anyhow!("git diff failed: {}", e))?;

    if !output.status.success() {
        anyhow::bail!("git diff failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let changed_files: Vec<PathBuf> = stdout
        .split('\0')
        .filter(|l| !l.is_empty())
        .map(|l| PathBuf::from(l.to_string()))
        .collect();

    if changed_files.is_empty() {
        println!("No changed files found.");
        return Ok(0);
    }

    println!("Scanning {} changed files...", changed_files.len());

    let options = ScanOptions {
        target: ".".to_string(),
        files: changed_files,
        ..ScanOptions::default()
    };

    let result = run_scan(options);
    let target = Path::new(".");
    let outcome = persist_and_report(result, target)?;

    match outcome {
        sentinel_core::ScanOutcome::Complete => Ok(0),
        sentinel_core::ScanOutcome::Incomplete => Ok(2),
        sentinel_core::ScanOutcome::Failed => Ok(2),
    }
}
