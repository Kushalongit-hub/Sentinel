use serde_json;
use thiserror::Error;

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
                recommendation TEXT NOT NULL
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
                id TEXT PRIMARY KEY,
                key TEXT NOT NULL,
                value TEXT NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    pub fn insert_finding(&self, finding: &Finding) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, severity, confidence, category, file, line, title, description, execution_path, affected_components, evidence, recommendation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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

    pub fn upsert_rule(&self, id: &str, name: &str, pattern: &str, severity: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO rules (id, name, pattern, severity) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, name, pattern, severity],
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

fn parse_severity(s: &str) -> sentinel_core::Severity {
    match s.to_lowercase().as_str() {
        "critical" => sentinel_core::Severity::Critical,
        "high" => sentinel_core::Severity::High,
        "medium" => sentinel_core::Severity::Medium,
        "low" => sentinel_core::Severity::Low,
        _ => sentinel_core::Severity::Info,
    }
}
