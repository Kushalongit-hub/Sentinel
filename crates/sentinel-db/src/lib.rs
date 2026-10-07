use sentinel_core::{Finding, ScanOutcome, ScanReport};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Database error: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, DbError>;
pub struct SentinelDb {
    conn: rusqlite::Connection,
}
pub struct ScanRecord<'a> {
    pub id: &'a str,
    pub target: &'a Path,
    pub report: &'a ScanReport,
    pub files: &'a [PathBuf],
    pub full_scan: bool,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS findings (
 id TEXT PRIMARY KEY, severity TEXT NOT NULL, confidence REAL NOT NULL,
 category TEXT NOT NULL, file TEXT NOT NULL, line INTEGER NOT NULL,
 title TEXT NOT NULL, description TEXT NOT NULL, execution_path TEXT NOT NULL,
 affected_components TEXT NOT NULL, evidence TEXT NOT NULL, recommendation TEXT NOT NULL,
 fingerprint TEXT NOT NULL UNIQUE, scan_id TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS scans (
 id TEXT PRIMARY KEY, target TEXT NOT NULL, outcome TEXT NOT NULL,
 coverage_notes TEXT NOT NULL, files_scanned INTEGER NOT NULL,
 symbols_indexed INTEGER NOT NULL, scanners_used TEXT NOT NULL,
 duration_ms INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS scan_findings (
 scan_id TEXT NOT NULL, fingerprint TEXT NOT NULL, snapshot TEXT NOT NULL,
 PRIMARY KEY(scan_id, fingerprint));
CREATE TABLE IF NOT EXISTS memory (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);";

impl SentinelDb {
    pub fn new(path: &str) -> Result<Self> {
        Self::from_connection(rusqlite::Connection::open(path)?)
    }
    pub fn open_existing(path: &Path) -> Result<Self> {
        let conn = rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(Self { conn })
    }
    pub fn new_in_memory() -> Result<Self> {
        Self::from_connection(rusqlite::Connection::open_in_memory()?)
    }
    fn from_connection(conn: rusqlite::Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }
    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 6 {
            return Err(DbError::Migration(format!(
                "database version {version} is newer than supported version 6"
            )));
        }
        if version == 6 {
            return Ok(());
        }
        if version == 5 {
            return self.migrate_jobs();
        }
        if version == 4 {
            return self.migrate_audit();
        }
        if version == 3 {
            return self.migrate_baseline();
        }
        if version == 2 {
            return self.migrate_graph();
        }
        let tx = self.conn.unchecked_transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='findings')",
            [],
            |r| r.get(0),
        )?;
        let mut old = Vec::new();
        if exists {
            let columns = {
                let mut stmt = tx.prepare("PRAGMA table_info(findings)")?;
                let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
                rows.collect::<std::result::Result<std::collections::BTreeSet<_>, _>>()?
            };
            let scan = if columns.contains("scan_id") {
                "COALESCE(scan_id,'legacy')"
            } else {
                "'legacy'"
            };
            let created = if columns.contains("created_at") {
                "created_at"
            } else {
                "NULL"
            };
            let resolved = if columns.contains("resolved_at") {
                "resolved_at"
            } else {
                "NULL"
            };
            let mut stmt = tx.prepare(&format!("SELECT id,severity,confidence,category,file,line,title,description,execution_path,affected_components,evidence,recommendation,{scan},{created},{resolved} FROM findings ORDER BY rowid"))?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                old.push((
                    read_finding(row)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ));
            }
            tx.execute_batch("DROP INDEX IF EXISTS idx_findings_scan; DROP INDEX IF EXISTS idx_findings_fingerprint; ALTER TABLE findings RENAME TO legacy_findings;")?;
        }
        let memory_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memory')",
            [],
            |r| r.get(0),
        )?;
        if memory_exists {
            tx.execute_batch("ALTER TABLE memory RENAME TO legacy_memory;")?;
        }
        tx.execute_batch(SCHEMA)?;
        for (mut finding, scan, created, resolved) in old {
            if finding.file.is_relative() {
                if let Some(base) = self.conn.path().and_then(|path| Path::new(path).parent()) {
                    if let Ok(path) = base.join(&finding.file).canonicalize().or_else(|_| {
                        base.parent()
                            .unwrap_or(base)
                            .join(&finding.file)
                            .canonicalize()
                    }) {
                        finding.file = path;
                    }
                }
            }
            write_finding(&tx, &finding, &scan)?;
            tx.execute("UPDATE findings SET created_at=COALESCE(?1,created_at),resolved_at=?2 WHERE fingerprint=?3", rusqlite::params![created,resolved,finding.fingerprint()])?;
        }
        if exists {
            tx.execute_batch("DROP TABLE legacy_findings;")?;
        }
        if memory_exists {
            tx.execute_batch("INSERT INTO memory(key,value) SELECT key,value FROM legacy_memory m WHERE rowid=(SELECT MAX(rowid) FROM legacy_memory WHERE key=m.key); DROP TABLE legacy_memory;")?;
        }
        tx.execute_batch("PRAGMA user_version = 2;")?;
        tx.commit()?;
        self.migrate_graph()
    }
    fn migrate_graph(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,root TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS files(project_id TEXT NOT NULL,path TEXT NOT NULL,language TEXT NOT NULL,content_hash TEXT NOT NULL,payload TEXT NOT NULL,indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(project_id,path));
CREATE TABLE IF NOT EXISTS symbols(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,file TEXT NOT NULL,name TEXT NOT NULL,qualified_name TEXT NOT NULL,kind TEXT NOT NULL,start_line INTEGER NOT NULL,end_line INTEGER NOT NULL,language TEXT NOT NULL,content_hash TEXT NOT NULL,payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_symbols_project_name ON symbols(project_id,name);
CREATE TABLE IF NOT EXISTS symbol_edges(project_id TEXT NOT NULL,owner_file TEXT NOT NULL,from_id TEXT NOT NULL,to_id TEXT NOT NULL,kind TEXT NOT NULL,line INTEGER NOT NULL,name TEXT NOT NULL,resolved INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(project_id,from_id,to_id,kind,line,name));
CREATE INDEX IF NOT EXISTS idx_edges_to ON symbol_edges(project_id,to_id);
CREATE TABLE IF NOT EXISTS security_annotations(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,file TEXT NOT NULL,owner TEXT NOT NULL,kind TEXT NOT NULL,category TEXT NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS index_metadata(project_id TEXT PRIMARY KEY,payload TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
PRAGMA user_version=3;")?;
        tx.commit()?;
        self.migrate_baseline()
    }
    fn migrate_baseline(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS security_baselines(project_id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS baseline_findings(project_id TEXT NOT NULL,fingerprint TEXT NOT NULL,rule TEXT NOT NULL,location TEXT NOT NULL,status TEXT NOT NULL,first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(project_id,fingerprint));
PRAGMA user_version=4; COMMIT;")?;
        self.migrate_audit()
    }
    fn migrate_audit(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS audit_revisions (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, run_id TEXT NOT NULL,
 source_snapshot TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL,
 imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(project_id,revision_id));
CREATE INDEX IF NOT EXISTS idx_audit_runs ON audit_revisions(project_id,run_id);
CREATE TABLE IF NOT EXISTS audit_latest (
 project_id TEXT PRIMARY KEY, revision_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_coverage (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, coverage_id TEXT NOT NULL,
 status TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(project_id,revision_id,coverage_id));
CREATE TABLE IF NOT EXISTS audit_attempts (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, coverage_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(project_id,revision_id,coverage_id,ordinal));
CREATE TABLE IF NOT EXISTS audit_candidates (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 assessment TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(project_id,revision_id,fingerprint));
CREATE TABLE IF NOT EXISTS audit_reviews (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
 payload TEXT NOT NULL, PRIMARY KEY(project_id,revision_id,fingerprint));
PRAGMA user_version=5;")?;
        tx.commit()?;
        self.migrate_jobs()
    }
    fn migrate_jobs(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS security_jobs(project_id TEXT NOT NULL,job_id TEXT NOT NULL,payload TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(project_id,job_id)); PRAGMA user_version=6;")?;
        tx.commit()?;
        Ok(())
    }
    /// Access the shared SQLite store for composable transactional repository services.
    /// Schema changes must remain in this crate's versioned migrations.
    pub fn connection(&self) -> &rusqlite::Connection {
        &self.conn
    }
    /// Return current or historical finding rows without creating a database.
    pub fn list_findings(&self, active_only: bool) -> Result<Vec<Finding>> {
        let suffix = if active_only {
            " WHERE resolved_at IS NULL"
        } else {
            ""
        };
        let mut stmt=self.conn.prepare(&format!("SELECT id,severity,confidence,category,file,line,title,description,execution_path,affected_components,evidence,recommendation FROM findings{suffix}"))?;
        let mut rows = stmt.query([])?;
        let mut results = vec![];
        while let Some(row) = rows.next()? {
            results.push(read_finding(row)?);
        }
        Ok(results)
    }
    pub fn insert_finding(&self, finding: &Finding, scan_id: &str) -> Result<()> {
        write_finding(&self.conn, finding, scan_id)
    }
    pub fn get_finding(&self, id: &str) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare("SELECT id,severity,confidence,category,file,line,title,description,execution_path,affected_components,evidence,recommendation FROM findings WHERE id=?1 OR fingerprint=?1")?;
        let mut rows = stmt.query([id])?;
        rows.next()?.map(read_finding).transpose()
    }
    pub fn resolve_finding(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE findings SET resolved_at=CURRENT_TIMESTAMP WHERE id=?1 OR fingerprint=?1",
            [id],
        )?;
        Ok(())
    }
    pub fn persist_scan(&self, record: ScanRecord<'_>) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let report = record.report;
        tx.execute("INSERT INTO scans(id,target,outcome,coverage_notes,files_scanned,symbols_indexed,scanners_used,duration_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![record.id, record.target.to_string_lossy(), format!("{:?}",report.outcome), serde_json::to_string(&report.coverage_notes)?, report.files_scanned as i64, report.symbols_indexed as i64, serde_json::to_string(&report.scanner_results)?, report.duration_ms as i64])?;
        for finding in &report.findings {
            write_finding(&tx, finding, record.id)?;
            tx.execute(
                "INSERT INTO scan_findings(scan_id,fingerprint,snapshot) VALUES (?1,?2,?3)",
                rusqlite::params![
                    record.id,
                    finding.fingerprint(),
                    serde_json::to_string(finding)?
                ],
            )?;
        }
        // Only complete coverage can resolve old findings. Partial scans leave history active.
        if report.outcome == ScanOutcome::Complete {
            let candidates = {
                let mut stmt = tx.prepare(
                    "SELECT id,file FROM findings WHERE resolved_at IS NULL AND scan_id != ?1",
                )?;
                let rows = stmt.query_map([record.id], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        PathBuf::from(r.get::<_, String>(1)?),
                    ))
                })?;
                rows.collect::<std::result::Result<Vec<_>, _>>()?
            };
            for (id, path) in candidates {
                let deleted_in_target = record.full_scan
                    && (path.starts_with(record.target) || path == record.target)
                    && path.try_exists().is_ok_and(|exists| !exists);
                if deleted_in_target || record.files.contains(&path) {
                    tx.execute(
                        "UPDATE findings SET resolved_at=CURRENT_TIMESTAMP WHERE id=?1",
                        [id],
                    )?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub fn set_memory(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT INTO memory(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [key,value])?;
        Ok(())
    }
    pub fn get_memory(&self, key: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn
            .query_row("SELECT value FROM memory WHERE key=?1", [key], |r| r.get(0))
            .optional()?)
    }
}
fn write_finding(conn: &rusqlite::Connection, f: &Finding, scan: &str) -> Result<()> {
    conn.execute("INSERT INTO findings(id,severity,confidence,category,file,line,title,description,execution_path,affected_components,evidence,recommendation,fingerprint,scan_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,confidence=excluded.confidence,description=excluded.description,execution_path=excluded.execution_path,affected_components=excluded.affected_components,evidence=excluded.evidence,recommendation=excluded.recommendation,scan_id=excluded.scan_id,resolved_at=NULL", rusqlite::params![f.id,f.severity.to_string(),f.confidence,f.category,f.file.to_string_lossy(),f.line as i64,f.title,f.description,serde_json::to_string(&f.execution_path)?,serde_json::to_string(&f.affected_components)?,serde_json::to_string(&f.evidence)?,f.recommendation,f.fingerprint(),scan])?;
    Ok(())
}
fn read_finding(r: &rusqlite::Row<'_>) -> Result<Finding> {
    Ok(Finding {
        id: r.get(0)?,
        severity: r
            .get::<_, String>(1)?
            .parse()
            .map_err(|e: String| rusqlite::Error::InvalidParameterName(e))?,
        confidence: r.get(2)?,
        category: r.get(3)?,
        file: PathBuf::from(r.get::<_, String>(4)?),
        line: r.get::<_, i64>(5)?.max(1) as usize,
        title: r.get(6)?,
        description: r.get(7)?,
        execution_path: serde_json::from_str(&r.get::<_, String>(8)?)?,
        affected_components: serde_json::from_str(&r.get::<_, String>(9)?)?,
        evidence: serde_json::from_str(&r.get::<_, String>(10)?)?,
        recommendation: r.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_scan_preserves_unanalyzed_files_and_resolves_deleted_files() {
        let db = SentinelDb::new_in_memory().unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        let existing = root.join("src/lib.rs").canonicalize().unwrap();
        let missing = root.join("sentinel-missing-fixture.rs");
        assert!(!missing.exists());
        for (id, file) in [("existing", existing), ("deleted", missing)] {
            db.insert_finding(
                &Finding {
                    id: id.into(),
                    severity: sentinel_core::Severity::High,
                    confidence: 0.7,
                    category: "rule".into(),
                    file,
                    line: 1,
                    title: "rule".into(),
                    description: "message".into(),
                    execution_path: vec![],
                    affected_components: vec![],
                    evidence: vec![],
                    recommendation: String::new(),
                },
                "previous",
            )
            .unwrap();
        }
        let report = ScanReport {
            findings: vec![],
            files_scanned: 0,
            symbols_indexed: 0,
            scanners_used: vec![],
            duration_ms: 0,
            outcome: ScanOutcome::Complete,
            coverage_notes: vec![],
            scanner_results: vec![],
        };
        db.persist_scan(ScanRecord {
            id: "current",
            target: &root,
            report: &report,
            files: &[],
            full_scan: true,
        })
        .unwrap();
        let active: String = db
            .conn
            .query_row(
                "SELECT id FROM findings WHERE resolved_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, "existing");
    }
    #[test]
    fn migrates_populated_legacy_database_and_memory() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE findings(id TEXT PRIMARY KEY,severity TEXT,confidence REAL,category TEXT,file TEXT,line INTEGER,title TEXT,description TEXT,execution_path TEXT,affected_components TEXT,evidence TEXT,recommendation TEXT); INSERT INTO findings VALUES('old','Info',0.7,'rule','test.rs',1,'test','test','[]','[]','[]',''); CREATE TABLE memory(id TEXT PRIMARY KEY,key TEXT,value TEXT); INSERT INTO memory(key,value) VALUES('k','old'),('k','new');").unwrap();
        let db = SentinelDb::from_connection(conn).unwrap();
        let f = db.get_finding("old").unwrap().unwrap();
        db.insert_finding(&f, "new").unwrap();
        assert_eq!(db.get_memory("k").unwrap().as_deref(), Some("new"));
        db.set_memory("k", "latest").unwrap();
        assert_eq!(db.get_memory("k").unwrap().as_deref(), Some("latest"));
    }
    #[test]
    fn migration_preserves_existing_lifecycle_metadata() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE findings(id TEXT PRIMARY KEY,severity TEXT,confidence REAL,category TEXT,file TEXT,line INTEGER,title TEXT,description TEXT,execution_path TEXT,affected_components TEXT,evidence TEXT,recommendation TEXT,scan_id TEXT,created_at TEXT,resolved_at TEXT); INSERT INTO findings VALUES('old','Info',0.7,'rule','test.rs',1,'test','test','[]','[]','[]','','original','2025-01-01','2025-01-02');").unwrap();
        let db = SentinelDb::from_connection(conn).unwrap();
        let metadata: (String, String, String) = db
            .conn
            .query_row(
                "SELECT scan_id,created_at,resolved_at FROM findings WHERE id='old'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            metadata,
            ("original".into(), "2025-01-01".into(), "2025-01-02".into())
        );
    }
    #[test]
    fn deduplicates_and_reactivates_occurrences() {
        let db = SentinelDb::new_in_memory().unwrap();
        let f = Finding {
            id: "one".into(),
            severity: sentinel_core::Severity::High,
            confidence: 0.7,
            category: "rule".into(),
            file: "test.rs".into(),
            line: 1,
            title: "rule".into(),
            description: "message".into(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        db.insert_finding(&f, "first").unwrap();
        db.resolve_finding("one").unwrap();
        let mut again = f.clone();
        again.id = "two".into();
        db.insert_finding(&again, "second").unwrap();
        let count: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM findings WHERE resolved_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn version_three_upgrade_preserves_graph_and_rejects_future_versions() {
        let db = SentinelDb::new_in_memory().unwrap();
        db.conn.execute_batch("INSERT INTO projects(id,root) VALUES ('p','root'); PRAGMA user_version=3; DROP TABLE security_baselines; DROP TABLE baseline_findings;").unwrap();
        db.migrate().unwrap();
        let root: String = db
            .conn
            .query_row("SELECT root FROM projects WHERE id='p'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(root, "root");
        let version: i64 = db
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 6);
        db.conn.execute_batch("PRAGMA user_version=7;").unwrap();
        assert!(db.migrate().is_err());
    }
}
