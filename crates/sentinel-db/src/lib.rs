#![allow(clippy::single_component_path_imports)]
use serde_json;
use thiserror::Error;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use sentinel_core::Finding;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, DbError>;

pub struct SentinelDb {
    conn: rusqlite::Connection,
}

impl SentinelDb {
    pub fn new(path: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn new_in_memory() -> Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                category TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                execution_path TEXT NOT NULL,
                affected_components TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                resolved_at TEXT
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                coverage_notes TEXT NOT NULL,
                files_scanned INTEGER NOT NULL,
                symbols_indexed INTEGER NOT NULL,
                scanners_used TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                pattern TEXT NOT NULL,
                severity TEXT NOT NULL
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS memory (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            [],
        )?;
        let _ = self.conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''", []);
        let _ = self.conn.execute("ALTER TABLE findings ADD COLUMN scan_id TEXT NOT NULL DEFAULT ''", []);
        let _ = self.conn.execute("ALTER TABLE findings ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP", []);
        let _ = self.conn.execute("ALTER TABLE findings ADD COLUMN resolved_at TEXT", []);
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)", [])?;
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)", [])?;
        Ok(())
    }

    pub fn insert_finding(&self, finding: &Finding, scan_id: &str) -> Result<()> {
        let fingerprint = compute_fingerprint(finding);
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, severity, confidence, category, file, line, title, description, execution_path, affected_components, evidence, recommendation, fingerprint, scan_id, created_at, resolved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, COALESCE((SELECT resolved_at FROM findings WHERE id = ?1), NULL))",
            rusqlite::params![
                finding.id,
                finding.severity.to_string(),
                finding.confidence,
                finding.category,
                finding.file.to_string_lossy(),
                finding.line as i64,
                finding.title,
                finding.description,
                serde_json::to_string(&finding.execution_path).map_err(|e| DbError::Serialization(e.to_string()))?,
                serde_json::to_string(&finding.affected_components).map_err(|e| DbError::Serialization(e.to_string()))?,
                serde_json::to_string(&finding.evidence).map_err(|e| DbError::Serialization(e.to_string()))?,
                finding.recommendation,
                fingerprint,
                scan_id,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn get_finding(&self, id: &str) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, severity, confidence, category, file, line, title, description, execution_path, affected_components, evidence, recommendation FROM findings WHERE id = ?1"
        )?;
        let mut rows = stmt.query(rusqlite::params![id])?;
        if let Some(row) = rows.next()? {
            let execution_path: String = row.get(8)?;
            let affected_components: String = row.get(9)?;
            let evidence: String = row.get(10)?;
            Ok(Some(Finding {
                id: row.get(0)?,
                severity: parse_severity(&row.get::<_, String>(1)?),
                confidence: row.get(2)?,
                category: row.get(3)?,
                file: std::path::PathBuf::from(row.get::<_, String>(4)?),
                line: row.get::<_, i64>(5)? as usize,
                title: row.get(6)?,
                description: row.get(7)?,
                execution_path: serde_json::from_str(&execution_path).unwrap_or_default(),
                affected_components: serde_json::from_str(&affected_components).unwrap_or_default(),
                evidence: serde_json::from_str(&evidence).unwrap_or_default(),
                recommendation: row.get(11)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn resolve_finding(&self, id: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE findings SET resolved_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        Ok(())
    }

    pub fn record_scan(&self, scan_id: &str, target: &str, outcome: &str, coverage_notes: &[String], files_scanned: usize, symbols_indexed: usize, scanners_used: &[String], duration_ms: u128) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO scans (id, target, outcome, coverage_notes, files_scanned, symbols_indexed, scanners_used, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                scan_id,
                target,
                outcome,
                serde_json::to_string(coverage_notes).map_err(|e| DbError::Serialization(e.to_string()))?,
                files_scanned as i64,
                symbols_indexed as i64,
                serde_json::to_string(scanners_used).map_err(|e| DbError::Serialization(e.to_string()))?,
                duration_ms as i64,
            ],
        )?;
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT id, name FROM rules")?;
        let mut result = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row_result) = rows.next()? {
            let row = row_result;
            result.push((row.get(0)?, row.get(1)?));
        }
        Ok(result)
    }

    pub fn set_memory(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO memory (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    pub fn get_memory(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM memory WHERE key = ?1")?;
        let mut rows = stmt.query(rusqlite::params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }
}

fn compute_fingerprint(finding: &Finding) -> String {
    let mut hasher = DefaultHasher::new();
    let key = format!("{}:{}:{}:{}", finding.file.display(), finding.line, finding.title, finding.description);
    key.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

fn parse_severity(s: &str) -> sentinel_core::Severity {
    match s.to_lowercase().as_str() {
        "critical" => sentinel_core::Severity::Critical,
        "high" => sentinel_core::Severity::High,
        "medium" => sentinel_core::Severity::Medium,
        "low" => sentinel_core::Severity::Low,
        _ => sentinel_core::Severity::Info,
    }
}
