use anyhow::Result;
use sentinel_scanner::pipeline::{persist_and_report, run_scan, ScanOptions};

pub fn audit(path: String) -> Result<i32> {
    let options = ScanOptions {
        target: path.clone(),
        ..ScanOptions::default()
    };

    let result = run_scan(options);
    let target = std::path::Path::new(&path);
    let outcome = persist_and_report(result, target)?;

    match outcome {
        sentinel_core::ScanOutcome::Complete => Ok(0),
        sentinel_core::ScanOutcome::Incomplete => Ok(2),
        sentinel_core::ScanOutcome::Failed => Ok(2),
    }
}
