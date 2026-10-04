use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" | "warning" => Ok(Self::Medium),
            "high" | "error" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(format!("unknown severity: {value}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub confidence: f64,
    pub category: String,
    pub file: PathBuf,
    pub line: usize,
    pub title: String,
    pub description: String,
    pub execution_path: Vec<String>,
    pub affected_components: Vec<String>,
    pub evidence: Vec<String>,
    pub recommendation: String,
}

impl Finding {
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let path = self.file.to_string_lossy().replace('\\', "/");
        let key = serde_json::to_vec(&(
            &path,
            self.line,
            &self.category,
            &self.title,
            &self.evidence,
        ))
        .expect("finding identity is serializable");
        format!("{:x}", Sha256::digest(key))
    }
    pub fn stabilize_id(&mut self) {
        self.id = self.fingerprint();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub symbols_indexed: usize,
    pub scanners_used: Vec<String>,
    pub duration_ms: u128,
    pub outcome: ScanOutcome,
    pub coverage_notes: Vec<String>,
    pub scanner_results: Vec<ScannerResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanOutcome {
    Complete,
    Incomplete,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScannerOutcome {
    Completed,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerResult {
    pub name: String,
    pub outcome: ScannerOutcome,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub minimum_severity: Severity,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            minimum_severity: Severity::Info,
        }
    }
}
