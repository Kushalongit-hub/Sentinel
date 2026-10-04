use colored::*;
use sentinel_core::ScanReport;

pub fn render_terminal(report: &ScanReport) {
    let duration = format!("{}ms", report.duration_ms);
    println!("{}", "Scan Report".bold().cyan());
    println!("{}: {}", "Files scanned".bold(), report.files_scanned);
    println!("{}: {}", "Symbols indexed".bold(), report.symbols_indexed);
    println!("{}: {}", "Duration".bold(), duration);
    println!("{}: {:?}", "Scanners used".bold(), report.scanners_used);
    println!("Outcome: {:?}", report.outcome);
    for note in &report.coverage_notes {
        println!("  Coverage: {note}");
    }
    println!();

    if report.findings.is_empty() {
        if report.outcome == sentinel_core::ScanOutcome::Complete {
            println!("{}", "No findings detected.".green());
        } else {
            println!("No findings returned; analysis is incomplete.");
        }
    } else {
        let severity_label = |s: &sentinel_core::Severity| match s {
            sentinel_core::Severity::Critical => "Critical".red().bold(),
            sentinel_core::Severity::High => "High".red(),
            sentinel_core::Severity::Medium => "Medium".yellow(),
            sentinel_core::Severity::Low => "Low".blue(),
            sentinel_core::Severity::Info => "Info".dimmed(),
        };

        println!("{} {} findings:", "Findings:".bold(), report.findings.len());
        for finding in &report.findings {
            println!(
                "  [{}] {} - {}",
                severity_label(&finding.severity),
                finding.id,
                finding.title
            );
            println!(
                "    {}:{}: {}",
                finding.file.display(),
                finding.line,
                finding.description
            );
        }
    }
}

pub fn render_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).expect("report is serializable")
}

pub fn render_sarif(report: &ScanReport) -> String {
    let mut sarif = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinel",
                        "version": "0.1.0"
                    }
                },
                "results": [],
                "invocations": [{
                    "executionSuccessful": report.outcome == sentinel_core::ScanOutcome::Complete,
                    "toolExecutionNotifications": report.coverage_notes.iter().map(|note| serde_json::json!({"level": "warning", "message": {"text": note}})).collect::<Vec<_>>()
                }]
            }
        ]
    });

    if let Some(results) = sarif["runs"][0]["results"].as_array_mut() {
        for finding in &report.findings {
            let rule_level = match finding.severity {
                sentinel_core::Severity::Critical => "error",
                sentinel_core::Severity::High => "error",
                sentinel_core::Severity::Medium => "warning",
                sentinel_core::Severity::Low => "note",
                sentinel_core::Severity::Info => "note",
            };

            results.push(serde_json::json!({
                "ruleId": finding.title,
                "partialFingerprints": {"sentinel/v1": finding.fingerprint()},
                "level": rule_level,
                "message": {
                    "text": finding.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": path_uri(&finding.file)
                            },
                            "region": {
                                "startLine": finding.line.max(1)
                            }
                        }
                    }
                ]
            }));
        }
    }

    serde_json::to_string_pretty(&sarif).expect("SARIF is serializable")
}

fn path_uri(path: &std::path::Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    let value = value.strip_prefix("//?/").unwrap_or(&value);
    let encoded: String = value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    if path.is_absolute() || value.as_bytes().get(1) == Some(&b':') {
        if encoded.starts_with('/') {
            format!("file://{encoded}")
        } else {
            format!("file:///{encoded}")
        }
    } else {
        encoded
    }
}
