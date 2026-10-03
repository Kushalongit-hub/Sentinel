use colored::*;
use sentinel_core::ScanReport;

pub fn render_terminal(report: &ScanReport) {
    let duration = format!("{}ms", report.duration_ms);
    println!("{}", "Scan Report".bold().cyan());
    println!("{}: {}", "Files scanned".bold(), report.files_scanned);
    println!("{}: {}", "Symbols indexed".bold(), report.symbols_indexed);
    println!("{}: {}", "Duration".bold(), duration);
    println!("{}: {:?}", "Scanners used".bold(), report.scanners_used);
    println!();

    if report.findings.is_empty() {
        println!("{}", "No findings detected.".green());
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
    serde_json::to_string_pretty(report).unwrap_or_else(|_| String::new())
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
                "results": []
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
                "ruleId": finding.id,
                "level": rule_level,
                "message": {
                    "text": finding.description
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file.to_string_lossy()
                            },
                            "region": {
                                "startLine": finding.line
                            }
                        }
                    }
                ]
            }));
        }
    }

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| String::new())
}
