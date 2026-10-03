use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use thiserror::Error;
use which::which;

use sentinel_core::{models, Finding, Result as CoreResult};

#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Scanner not found on PATH: {0}")]
    NotFound(String),

    #[error("Scanner execution failed: {0}")]
    Execution(String),

    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, ScannerError>;

pub struct ScannerRegistry {
    available: HashMap<String, bool>,
}

impl ScannerRegistry {
    pub fn new() -> Self {
        let mut available = HashMap::new();
        for name in &["semgrep", "bandit", "trivy", "gitleaks"] {
            available.insert(name.to_string(), which(name).is_ok());
        }
        Self { available }
    }

    pub fn is_available(&self, name: &str) -> bool {
        self.available.get(name).copied().unwrap_or(false)
    }

    pub fn available_scanners(&self) -> Vec<String> {
        self.available
            .iter()
            .filter_map(|(name, available)| if *available { Some(name.clone()) } else { None })
            .collect()
    }
}

impl Default for ScannerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SubprocessRunner;

impl SubprocessRunner {
    pub fn run(scanner: &str, args: &[&str], target: &Path) -> Result<String> {
        let mut cmd = std::process::Command::new(scanner);
        cmd.args(args)
            .arg(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = cmd
            .output()
            .map_err(|e| ScannerError::Execution(e.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(ScannerError::Execution(format!("{}: {}", scanner, stderr)));
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

pub fn normalize_finding(raw: &str, scanner: &str) -> CoreResult<Finding> {
    match scanner {
        "semgrep" => parse_semgrep(raw),
        "bandit" => parse_bandit(raw),
        _ => Ok(Finding {
            id: format!("{}-stub", scanner),
            severity: models::Severity::Info,
            confidence: 0.0,
            category: scanner.to_string(),
            file: std::path::PathBuf::new(),
            line: 0,
            title: format!("{} finding", scanner),
            description: raw.lines().next().unwrap_or("").to_string(),
            execution_path: Vec::new(),
            affected_components: Vec::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
        }),
    }
}

fn parse_semgrep(raw: &str) -> CoreResult<Finding> {
    let json: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| sentinel_core::SentinelError::Parse(e.to_string()))?;
    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(|| sentinel_core::SentinelError::Parse("missing results".to_string()))?;
    if let Some(first) = results.first() {
        let path = first.get("path").and_then(|p| p.as_str()).unwrap_or("");
        let line = first
            .get("start")
            .and_then(|s| s.get("line"))
            .and_then(|l| l.as_u64())
            .unwrap_or(0) as usize;
        let rule_id = first
            .get("check_id")
            .and_then(|i| i.as_str())
            .unwrap_or("unknown");
        let message = first
            .get("extra")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let severity = match first
            .get("extra")
            .and_then(|e| e.get("severity"))
            .and_then(|s| s.as_str())
        {
            Some("ERROR") => models::Severity::High,
            Some("WARNING") => models::Severity::Medium,
            Some("INFO") => models::Severity::Info,
            _ => models::Severity::Info,
        };
        return Ok(Finding {
            id: format!("semgrep-{}", rule_id),
            severity,
            confidence: 0.9,
            category: "semgrep".to_string(),
            file: std::path::PathBuf::from(path),
            line,
            title: rule_id.to_string(),
            description: message.to_string(),
            execution_path: Vec::new(),
            affected_components: Vec::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
        });
    }
    Err(sentinel_core::SentinelError::Parse("no results".to_string()).into())
}

fn parse_bandit(raw: &str) -> CoreResult<Finding> {
    let json: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| sentinel_core::SentinelError::Parse(e.to_string()))?;
    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or_else(|| sentinel_core::SentinelError::Parse("missing results".to_string()))?;
    if let Some(first) = results.first() {
        let path = first.get("filename").and_then(|p| p.as_str()).unwrap_or("");
        let line = first
            .get("line_number")
            .and_then(|l| l.as_u64())
            .unwrap_or(0) as usize;
        let issue_id = first
            .get("issue_id")
            .and_then(|i| i.as_str())
            .unwrap_or("unknown");
        let message = first
            .get("issue_text")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        let severity = match first.get("issue_severity").and_then(|s| s.as_str()) {
            Some("HIGH") => models::Severity::High,
            Some("MEDIUM") => models::Severity::Medium,
            Some("LOW") => models::Severity::Low,
            _ => models::Severity::Info,
        };
        return Ok(Finding {
            id: format!("bandit-{}", issue_id),
            severity,
            confidence: 0.8,
            category: "bandit".to_string(),
            file: std::path::PathBuf::from(path),
            line,
            title: issue_id.to_string(),
            description: message.to_string(),
            execution_path: Vec::new(),
            affected_components: Vec::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
        });
    }
    Err(sentinel_core::SentinelError::Parse("no results".to_string()).into())
}

pub mod rules;
pub use rules::{RuleEngine, RuleError as RulesError};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_rule_engine_loads_and_matches() {
        let rules_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
        let engine = RuleEngine::load_from_dir(rules_dir.to_str().unwrap()).unwrap();
        let source = r#"
unsafe {
    let ptr = 0x1234 as *const i32;
}
"#;
        let findings = engine.scan("rust", source, &PathBuf::from("test.rs"));
        assert!(!findings.is_empty(), "expected findings for unsafe block, got none");
        assert!(findings.iter().any(|f| f.title == "rust-unsafe-usage"));
    }

    #[test]
    fn test_pattern_either_deserialization() {
        let yaml = r#"
rules:
  - id: test-rule
    message: test message
    pattern-either:
      - pattern: "foo()"
      - pattern: "bar()"
    languages: [rust]
    severity: INFO
"#;
        let rule_set: crate::rules::RuleSet = serde_yaml::from_str(yaml).unwrap();
        let rule = &rule_set.rules[0];
        assert!(rule.pattern_either.is_some(), "pattern_either should be Some");
    }
}
