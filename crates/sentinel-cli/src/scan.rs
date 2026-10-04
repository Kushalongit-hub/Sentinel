use crate::{OutputFormat, ScanArgs};
use anyhow::Result;
use sentinel_core::ScanOutcome;
use sentinel_db::{ScanRecord, SentinelDb};
use sentinel_scanner::{ScanOptions, ScanPipelineResult};
use std::path::{Path, PathBuf};
pub fn database_path(target: &Path, override_path: Option<&Path>) -> PathBuf {
    override_path.map(Path::to_path_buf).unwrap_or_else(|| {
        if target.is_file() {
            target
                .parent()
                .unwrap_or(Path::new("."))
                .join(".sentinel.db")
        } else {
            target.join(".sentinel.db")
        }
    })
}
pub fn options(target: String, args: &ScanArgs) -> ScanOptions {
    ScanOptions {
        target,
        threshold: sentinel_core::ThresholdConfig {
            minimum_severity: args.threshold,
        },
        external_scanners: args.external_scanners,
        semgrep_config: args.semgrep_config.clone(),
        scanner_timeout: std::time::Duration::from_secs(args.scanner_timeout),
        ..Default::default()
    }
}
pub fn finish(mut result: ScanPipelineResult, target: &Path, args: &ScanArgs) -> Result<i32> {
    if result.outcome != ScanOutcome::Failed {
        let db_path = database_path(target, args.db.as_deref());
        let persistence = (|| -> Result<()> {
            let db = SentinelDb::new(
                db_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("invalid database path"))?,
            )?;
            db.persist_scan(ScanRecord {
                id: &result.scan_id,
                target,
                report: &result.report(),
                files: &result.files,
                full_scan: result.full_scan,
            })?;
            Ok(())
        })();
        if let Err(e) = persistence {
            result.outcome = ScanOutcome::Incomplete;
            result
                .coverage_notes
                .push(format!("persistence failed: {e:#}"));
        }
    }
    let report = result.report();
    match args.format {
        OutputFormat::Terminal => sentinel_report::render_terminal(&report),
        OutputFormat::Json => println!("{}", sentinel_report::render_json(&report)),
        OutputFormat::Sarif => println!("{}", sentinel_report::render_sarif(&report)),
    }
    Ok(result.exit_code())
}
