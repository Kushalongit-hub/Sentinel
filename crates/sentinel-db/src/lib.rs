use sentinel_core::{Finding, ScanOutcome, ScanReport};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Finding exceeds the 1 MiB text payload limit")]
    FindingTooLarge,
    #[error("Index metadata exceeds the 1 MiB encoded payload limit")]
    IndexMetadataTooLarge,

    #[error("Scan persistence exceeds its metadata or snapshot byte budget")]
    ScanPersistenceTooLarge,
    #[error("Scan counters must fit nonnegative SQLite integers")]
    InvalidScanNumbers,

    #[error("Finding confidence must be finite and between 0 and 1; line must be a positive supported integer")]
    InvalidFindingNumbers,

    #[error("Finding query requires at most 2000 files and a row limit between 1 and 200")]
    InvalidFindingQueryBudget,
    #[error("Scoped finding query exceeds its row limit; narrow the target")]
    FindingQueryLimit,

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

const MAX_INDEX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_FINDING_TEXT_BYTES: usize = 1024 * 1024;
const RESOLUTION_BATCH_ROWS: usize = 64;
const MAX_SCAN_ID_BYTES: usize = 128;
const MAX_SCAN_METADATA_BYTES: usize = 1024 * 1024;
const MAX_SCAN_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SCAN_SNAPSHOTS_BYTES: usize = 16 * 1024 * 1024;

fn finding_text_column(column: &str) -> String {
    format!("CASE WHEN length(CAST({column} AS BLOB))=0 THEN '' ELSE CAST(substr(CAST({column} AS BLOB),1,{}) AS TEXT) END", MAX_FINDING_TEXT_BYTES + 1)
}

/// Cap SQLite-to-Rust text transfers before allocating strings or decoding JSON.
fn finding_columns() -> String {
    [
        "id",
        "severity",
        "confidence",
        "category",
        "file",
        "line",
        "title",
        "description",
        "execution_path",
        "affected_components",
        "evidence",
        "recommendation",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, column)| {
        if matches!(index, 2 | 5) {
            format!("CASE WHEN typeof({column}) IN ('integer','real') THEN {column} ELSE NULL END")
        } else {
            finding_text_column(column)
        }
    })
    .collect::<Vec<_>>()
    .join(",")
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
        // Additive indexes keep schema-v7 payloads compatible with older readers.
        db.conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_symbols_project_file ON symbols(project_id,file);
CREATE INDEX IF NOT EXISTS idx_annotations_project_file ON security_annotations(project_id,file);
CREATE INDEX IF NOT EXISTS idx_findings_file_active ON findings(replace(file,char(92),'/'),resolved_at,id);",
        )?;
        Ok(db)
    }
    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 7 {
            return Err(DbError::Migration(format!(
                "database version {version} is newer than supported version 7"
            )));
        }
        if version == 7 {
            return Ok(());
        }
        if version == 6 {
            return self.migrate_artifacts();
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
            let mut stmt = tx.prepare(&format!(
                "SELECT {},{scan},{created},{resolved} FROM findings ORDER BY rowid",
                finding_columns()
            ))?;
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
        self.migrate_artifacts()
    }
    fn migrate_artifacts(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_artifacts (
 project_id TEXT NOT NULL, revision_id TEXT NOT NULL, name TEXT NOT NULL,
 payload TEXT NOT NULL, PRIMARY KEY(project_id,revision_id,name));
PRAGMA user_version=7;",
        )?;
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
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM findings{suffix}",
            finding_columns()
        ))?;
        let mut rows = stmt.query([])?;
        let mut results = vec![];
        while let Some(row) = rows.next()? {
            results.push(read_finding(row)?);
        }
        Ok(results)
    }
    /// Return bounded active history for exact normalized file paths, or fail without truncation.
    pub fn list_active_findings_for_files(
        &self,
        files: &[PathBuf],
        limit: usize,
    ) -> Result<Vec<Finding>> {
        if !(1..=200).contains(&limit) || files.len() > 2000 {
            return Err(DbError::InvalidFindingQueryBudget);
        }
        if files.is_empty() {
            return Ok(vec![]);
        }
        let paths = files
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>();
        let placeholders = vec!["?"; paths.len()].join(",");
        let mut statement = self.conn.prepare(&format!(
            "SELECT {} FROM findings WHERE resolved_at IS NULL AND replace(file,char(92),'/') IN ({placeholders}) ORDER BY id LIMIT {}",
            finding_columns(), limit + 1))?;
        let mut rows = statement.query(rusqlite::params_from_iter(&paths))?;
        let mut findings = vec![];
        while let Some(row) = rows.next()? {
            if findings.len() == limit {
                return Err(DbError::FindingQueryLimit);
            }
            findings.push(read_finding(row)?);
        }
        Ok(findings)
    }

    pub fn insert_finding(&self, finding: &Finding, scan_id: &str) -> Result<()> {
        write_finding(&self.conn, finding, scan_id)
    }
    pub fn get_finding(&self, id: &str) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM findings WHERE id=?1 OR fingerprint=?1",
            finding_columns()
        ))?;
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
        if record.id.len() > MAX_SCAN_ID_BYTES {
            return Err(DbError::ScanPersistenceTooLarge);
        }
        let report = record.report;
        let files_scanned =
            i64::try_from(report.files_scanned).map_err(|_| DbError::InvalidScanNumbers)?;
        let symbols_indexed =
            i64::try_from(report.symbols_indexed).map_err(|_| DbError::InvalidScanNumbers)?;
        let duration_ms =
            i64::try_from(report.duration_ms).map_err(|_| DbError::InvalidScanNumbers)?;
        let target = record.target.to_string_lossy();
        let outcome = format!("{:?}", report.outcome);
        let mut metadata_budget = MAX_SCAN_METADATA_BYTES;
        for value in [record.id, target.as_ref(), outcome.as_str()] {
            metadata_budget = metadata_budget
                .checked_sub(value.len())
                .ok_or(DbError::ScanPersistenceTooLarge)?;
        }
        let coverage_notes = bounded_json(
            &report.coverage_notes,
            &mut metadata_budget,
            DbError::ScanPersistenceTooLarge,
        )?;
        let scanner_results = bounded_json(
            &report.scanner_results,
            &mut metadata_budget,
            DbError::ScanPersistenceTooLarge,
        )?;
        let mut snapshot_budget = MAX_SCAN_SNAPSHOTS_BYTES;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("INSERT INTO scans(id,target,outcome,coverage_notes,files_scanned,symbols_indexed,scanners_used,duration_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", rusqlite::params![record.id,target,outcome,coverage_notes,files_scanned,symbols_indexed,scanner_results,duration_ms])?;
        for finding in &report.findings {
            write_finding(&tx, finding, record.id)?;
            let mut per_snapshot_budget = snapshot_budget.min(MAX_SCAN_SNAPSHOT_BYTES);
            let snapshot = bounded_json(
                finding,
                &mut per_snapshot_budget,
                DbError::ScanPersistenceTooLarge,
            )?;
            snapshot_budget -= snapshot.len();
            tx.execute(
                "INSERT INTO scan_findings(scan_id,fingerprint,snapshot) VALUES (?1,?2,?3)",
                rusqlite::params![record.id, finding.fingerprint(), snapshot],
            )?;
        }
        // Only complete coverage can resolve old findings. Partial scans leave history active.
        if report.outcome == ScanOutcome::Complete {
            let mut after_rowid: Option<i64> = None;
            loop {
                // Finish each read before updates; rowid is stable as resolved_at changes.
                let candidates = {
                    let cursor = if after_rowid.is_some() {
                        "rowid > ?2"
                    } else {
                        "?2 IS NULL"
                    };
                    let mut statement = tx.prepare(&format!(
                        "SELECT rowid,{},{} FROM findings WHERE resolved_at IS NULL AND scan_id != ?1 AND {cursor} ORDER BY rowid LIMIT {}",
                        finding_text_column("id"), finding_text_column("file"), RESOLUTION_BATCH_ROWS))?;
                    let mut rows = statement.query(rusqlite::params![record.id, after_rowid])?;
                    let mut candidates = vec![];
                    while let Some(row) = rows.next()? {
                        validate_finding_text(row, &[1, 2])?;
                        candidates.push((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            PathBuf::from(row.get::<_, String>(2)?),
                        ));
                    }
                    candidates
                };
                let Some(last) = candidates.last() else {
                    break;
                };
                after_rowid = Some(last.0);
                for (_, id, path) in candidates {
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
        }
        tx.commit()?;
        Ok(())
    }
    /// Save bounded index statistics in the caller's transaction, if one exists.
    pub fn set_index_metadata<T: serde::Serialize + ?Sized>(
        &self,
        project: &str,
        value: &T,
    ) -> Result<()> {
        let mut remaining = MAX_INDEX_METADATA_BYTES;
        let payload = bounded_json(value, &mut remaining, DbError::IndexMetadataTooLarge)?;
        self.conn.execute("INSERT INTO index_metadata(project_id,payload) VALUES(?1,?2) ON CONFLICT(project_id) DO UPDATE SET payload=excluded.payload,updated_at=CURRENT_TIMESTAMP", rusqlite::params![project, payload])?;
        Ok(())
    }
    /// Bound SQLite transfer before decoding a selected project's persisted statistics.
    pub fn get_index_metadata<T: serde::de::DeserializeOwned>(
        &self,
        project: &str,
    ) -> Result<Option<T>> {
        use rusqlite::OptionalExtension;
        let payload: Option<Vec<u8>> = self.conn.query_row(
            &format!("SELECT substr(CAST(payload AS BLOB),1,{}) FROM index_metadata WHERE project_id=?1", MAX_INDEX_METADATA_BYTES + 1),
            [project], |row| row.get(0)).optional()?;
        payload
            .map(|bytes| {
                if bytes.len() > MAX_INDEX_METADATA_BYTES {
                    return Err(DbError::IndexMetadataTooLarge);
                }
                Ok(serde_json::from_slice(&bytes)?)
            })
            .transpose()
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
/// Serialize into a bounded standard-library slice writer, including JSON escaping.
fn bounded_json<T: serde::Serialize + ?Sized>(
    values: &T,
    remaining: &mut usize,
    overflow: DbError,
) -> Result<String> {
    let mut bytes = vec![0; *remaining];
    let mut destination = bytes.as_mut_slice();
    serde_json::to_writer(&mut destination, values).map_err(|error| {
        if error.is_io() {
            overflow
        } else {
            DbError::Serialization(error)
        }
    })?;
    let written = *remaining - destination.len();
    bytes.truncate(written);
    *remaining -= written;
    Ok(String::from_utf8(bytes).expect("serde_json emits UTF-8"))
}

fn finding_line(confidence: f64, line: i64) -> Result<usize> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) || line <= 0 {
        return Err(DbError::InvalidFindingNumbers);
    }
    usize::try_from(line).map_err(|_| DbError::InvalidFindingNumbers)
}

fn write_finding(conn: &rusqlite::Connection, f: &Finding, scan: &str) -> Result<()> {
    let line = i64::try_from(f.line).map_err(|_| DbError::InvalidFindingNumbers)?;
    finding_line(f.confidence, line)?;
    let severity = f.severity.to_string();
    let file = f.file.to_string_lossy();
    let mut remaining = MAX_FINDING_TEXT_BYTES;
    for value in [
        f.id.as_str(),
        severity.as_str(),
        f.category.as_str(),
        file.as_ref(),
        f.title.as_str(),
        f.description.as_str(),
        f.recommendation.as_str(),
    ] {
        remaining = remaining
            .checked_sub(value.len())
            .ok_or(DbError::FindingTooLarge)?;
    }
    let execution_path = bounded_json(&f.execution_path, &mut remaining, DbError::FindingTooLarge)?;
    let affected_components = bounded_json(
        &f.affected_components,
        &mut remaining,
        DbError::FindingTooLarge,
    )?;
    let evidence = bounded_json(&f.evidence, &mut remaining, DbError::FindingTooLarge)?;
    conn.execute("INSERT INTO findings(id,severity,confidence,category,file,line,title,description,execution_path,affected_components,evidence,recommendation,fingerprint,scan_id) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) ON CONFLICT(fingerprint) DO UPDATE SET severity=excluded.severity,confidence=excluded.confidence,description=excluded.description,execution_path=excluded.execution_path,affected_components=excluded.affected_components,evidence=excluded.evidence,recommendation=excluded.recommendation,scan_id=excluded.scan_id,resolved_at=NULL", rusqlite::params![f.id,severity,f.confidence,f.category,file,line,f.title,f.description,execution_path,affected_components,evidence,f.recommendation,f.fingerprint(),scan])?;
    Ok(())
}
fn validate_finding_text(r: &rusqlite::Row<'_>, columns: &[usize]) -> Result<()> {
    let mut text_bytes = 0;
    for &index in columns {
        let value = r.get_ref(index)?;
        let bytes = value.as_bytes().map_err(|_| {
            rusqlite::Error::InvalidColumnType(index, "finding text".into(), value.data_type())
        })?;
        text_bytes += bytes.len();
        if text_bytes > MAX_FINDING_TEXT_BYTES {
            return Err(DbError::FindingTooLarge);
        }
    }
    Ok(())
}

fn read_finding(r: &rusqlite::Row<'_>) -> Result<Finding> {
    let confidence: f64 = r.get(2)?;
    let line = finding_line(confidence, r.get(5)?)?;
    validate_finding_text(r, &[0, 1, 3, 4, 6, 7, 8, 9, 10, 11])?;
    Ok(Finding {
        id: r.get(0)?,
        severity: r
            .get::<_, String>(1)?
            .parse()
            .map_err(|e: String| rusqlite::Error::InvalidParameterName(e))?,
        confidence,
        category: r.get(3)?,
        file: PathBuf::from(r.get::<_, String>(4)?),
        line,
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
    fn index_metadata_bounds_isolate_projects_and_preserve_caller_transactions() {
        let db = SentinelDb::new_in_memory().unwrap();
        assert!(db
            .get_index_metadata::<String>("missing")
            .unwrap()
            .is_none());
        let exact = "x".repeat(MAX_INDEX_METADATA_BYTES - 2);
        db.set_index_metadata("p", &exact).unwrap();
        db.set_index_metadata("other", &"unchanged").unwrap();
        assert_eq!(
            db.get_index_metadata::<String>("p").unwrap().unwrap(),
            exact
        );
        let oversized = format!("{exact}é");
        assert!(matches!(
            db.set_index_metadata("p", &oversized),
            Err(DbError::IndexMetadataTooLarge)
        ));
        assert_eq!(
            db.get_index_metadata::<String>("p").unwrap().unwrap(),
            exact
        );
        let failure = (|| -> Result<()> {
            let tx = db.conn.unchecked_transaction()?;
            db.set_memory("uncommitted", "value")?;
            db.set_index_metadata("p", &oversized)?;
            tx.commit()?;
            Ok(())
        })();
        assert!(matches!(failure, Err(DbError::IndexMetadataTooLarge)));
        assert!(db.conn.is_autocommit());
        assert!(db.get_memory("uncommitted").unwrap().is_none());
        let escaped = "\0".repeat(MAX_INDEX_METADATA_BYTES / 6 + 1);
        assert!(matches!(
            db.set_index_metadata("p", &escaped),
            Err(DbError::IndexMetadataTooLarge)
        ));
        let corrupt = format!(
            "sensitive-invalid-json{}",
            "é".repeat(MAX_INDEX_METADATA_BYTES)
        );
        db.conn
            .execute(
                "UPDATE index_metadata SET payload=?1 WHERE project_id='p'",
                [&corrupt],
            )
            .unwrap();
        let error = db.get_index_metadata::<String>("p").unwrap_err();
        assert!(matches!(error, DbError::IndexMetadataTooLarge));
        assert!(!error.to_string().contains("sensitive-invalid-json"));
        assert_eq!(
            db.get_index_metadata::<String>("other").unwrap().as_deref(),
            Some("unchanged")
        );
        let retained: usize = db
            .conn
            .query_row(
                "SELECT length(CAST(payload AS BLOB)) FROM index_metadata WHERE project_id='p'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, corrupt.len());
        for invalid in ["", "{", "null"] {
            db.conn
                .execute(
                    "UPDATE index_metadata SET payload=?1 WHERE project_id='p'",
                    [invalid],
                )
                .unwrap();
            assert!(db.get_index_metadata::<String>("p").is_err());
        }
        let tx = db.conn.unchecked_transaction().unwrap();
        db.set_index_metadata("p", &"repaired").unwrap();
        assert!(!db.conn.is_autocommit());
        assert_eq!(
            db.get_index_metadata::<String>("p").unwrap().as_deref(),
            Some("repaired")
        );
        tx.rollback().unwrap();
        assert!(db.get_index_metadata::<String>("p").is_err());
    }

    #[test]
    fn lifecycle_resolution_batches_preserve_scope_and_roll_back_late_corruption() {
        let db = SentinelDb::new_in_memory().unwrap();
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        let selected = root.join("src/lib.rs").canonicalize().unwrap();
        let unselected = root.join("Cargo.toml").canonicalize().unwrap();
        let deleted = root.join("sentinel-missing-batch-fixture.py");
        let outside = root
            .parent()
            .unwrap()
            .join("sentinel-outside-batch-fixture.py");
        assert!(!deleted.exists() && !outside.exists());
        let finding = |id: String, file: PathBuf, line: usize| Finding {
            id,
            severity: sentinel_core::Severity::High,
            confidence: 0.5,
            category: "rule".into(),
            file,
            line,
            title: "title".into(),
            description: String::new(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        for index in 0..160 {
            let file = [&selected, &unselected, &deleted, &outside][index % 4].clone();
            db.insert_finding(
                &finding(format!("old-{}", 160 - index), file, index + 1),
                "old",
            )
            .unwrap();
        }
        // The first page must include negative and zero rowids, with no sentinel collision.
        db.conn.execute_batch("UPDATE findings SET rowid=-rowid WHERE rowid<=4; UPDATE findings SET rowid=-9223372036854775808 WHERE rowid=-1; UPDATE findings SET rowid=0 WHERE rowid=5;").unwrap();
        let mut report = ScanReport {
            findings: vec![finding("current".into(), selected.clone(), 1000)],
            files_scanned: 1,
            symbols_indexed: 0,
            scanners_used: vec![],
            duration_ms: 0,
            outcome: ScanOutcome::Complete,
            coverage_notes: vec![],
            scanner_results: vec![],
        };
        let files = [selected.clone()];
        db.persist_scan(ScanRecord {
            id: "batch",
            target: &root,
            report: &report,
            files: &files,
            full_scan: true,
        })
        .unwrap();
        let active = db.list_findings(true).unwrap();
        assert_eq!(active.len(), 81);
        assert!(active.iter().any(|f| f.id == "current"));
        assert!(active
            .iter()
            .all(|f| f.id == "current" || f.file == unselected || f.file == outside));
        let resolved: usize = db
            .conn
            .query_row(
                "SELECT count(*) FROM findings WHERE resolved_at IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(resolved, 80);
        for index in 0..72 {
            db.insert_finding(
                &finding(format!("late-{index}"), selected.clone(), index + 2000),
                "old",
            )
            .unwrap();
        }
        db.insert_finding(&finding("corrupt".into(), selected, 3000), "old")
            .unwrap();
        let oversized = "sensitive".repeat(MAX_FINDING_TEXT_BYTES / 9 + 1);
        db.conn
            .execute(
                "UPDATE findings SET file=?1 WHERE id='corrupt'",
                [&oversized],
            )
            .unwrap();
        report.findings.clear();
        let error = db
            .persist_scan(ScanRecord {
                id: "failed",
                target: &root,
                report: &report,
                files: &files,
                full_scan: true,
            })
            .unwrap_err();
        assert!(matches!(error, DbError::FindingTooLarge));
        assert!(!error.to_string().contains("sensitive"));
        assert!(db.conn.is_autocommit());
        let state: (usize, usize) = db
            .conn
            .query_row(
                "SELECT sum(resolved_at IS NULL),sum(resolved_at IS NOT NULL) FROM findings",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, (154, 80));
        let scans: usize = db
            .conn
            .query_row("SELECT count(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        let snapshots: usize = db
            .conn
            .query_row("SELECT count(*) FROM scan_findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!((scans, snapshots), (1, 1));
    }

    #[test]
    fn scan_metadata_and_snapshot_budgets_preserve_atomic_history() {
        let db = SentinelDb::new_in_memory().unwrap();
        let files = [PathBuf::from("test.py")];
        let save = |id: &str, report: &ScanReport| {
            db.persist_scan(ScanRecord {
                id,
                target: Path::new("test.py"),
                report,
                files: &files,
                full_scan: false,
            })
        };
        let empty = ScanReport {
            findings: vec![],
            files_scanned: 0,
            symbols_indexed: 0,
            scanners_used: vec![],
            duration_ms: 0,
            outcome: ScanOutcome::Incomplete,
            coverage_notes: vec![],
            scanner_results: vec![],
        };
        let mut exact = empty.clone();
        let base = "exact".len() + "test.py".len() + "Incomplete".len() + 6;
        exact.coverage_notes = vec!["x".repeat(MAX_SCAN_METADATA_BYTES - base)];
        save("exact", &exact).unwrap();
        exact.coverage_notes[0].push('é');
        assert!(matches!(
            save("exact", &exact),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        save(&"i".repeat(MAX_SCAN_ID_BYTES), &empty).unwrap();
        assert!(matches!(
            save(&"i".repeat(MAX_SCAN_ID_BYTES + 1), &empty),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        let large = "sensitive".repeat(MAX_SCAN_METADATA_BYTES / 9 + 1);
        let error = save(&large, &empty).unwrap_err();
        assert!(matches!(error, DbError::ScanPersistenceTooLarge));
        assert!(!error.to_string().contains("sensitive"));
        assert!(matches!(
            db.persist_scan(ScanRecord {
                id: "target-overflow",
                target: Path::new(&large),
                report: &empty,
                files: &[],
                full_scan: false
            }),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        let mut escaped = empty.clone();
        escaped.coverage_notes = vec!["\0".repeat(MAX_SCAN_METADATA_BYTES / 6)];
        assert!(matches!(
            save("escaped", &escaped),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        let mut scanner = empty.clone();
        scanner.scanner_results = vec![sentinel_core::ScannerResult {
            name: "scanner".into(),
            outcome: sentinel_core::ScannerOutcome::Failed,
            error: Some(large),
        }];
        assert!(matches!(
            save("scanner", &scanner),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        let mut counters = empty.clone();
        counters.duration_ms = u128::MAX;
        assert!(matches!(
            save("duration", &counters),
            Err(DbError::InvalidScanNumbers)
        ));
        if usize::BITS > 63 {
            for symbol_count in [false, true] {
                counters = empty.clone();
                if symbol_count {
                    counters.symbols_indexed = usize::MAX;
                } else {
                    counters.files_scanned = usize::MAX;
                }
                assert!(matches!(
                    save("counter", &counters),
                    Err(DbError::InvalidScanNumbers)
                ));
            }
        }
        counters = empty.clone();
        counters.duration_ms = i64::MAX as u128;
        save("numbers", &counters).unwrap();
        let duration: i64 = db
            .conn
            .query_row(
                "SELECT duration_ms FROM scans WHERE id='numbers'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(duration, i64::MAX);
        let old = Finding {
            id: "old".into(),
            severity: sentinel_core::Severity::High,
            confidence: 0.5,
            category: "rule".into(),
            file: "test.py".into(),
            line: 99,
            title: "title".into(),
            description: String::new(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        db.insert_finding(&old, "retained").unwrap();
        let mut report = empty;
        report.outcome = ScanOutcome::Complete;
        report.findings = (0..3)
            .map(|index| {
                let mut finding = old.clone();
                finding.id = format!("snapshot-{index}");
                finding.line = index + 1;
                finding.description = "\0".repeat(MAX_FINDING_TEXT_BYTES - 1024);
                finding
            })
            .collect();
        assert!(matches!(
            save("snapshots", &report),
            Err(DbError::ScanPersistenceTooLarge)
        ));
        assert!(db.conn.is_autocommit());
        assert_eq!(
            db.list_findings(true)
                .unwrap()
                .iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>(),
            ["old"]
        );
        let scans: usize = db
            .conn
            .query_row("SELECT count(*) FROM scans", [], |row| row.get(0))
            .unwrap();
        let snapshots: usize = db
            .conn
            .query_row("SELECT count(*) FROM scan_findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!((scans, snapshots), (3, 0));
    }

    #[test]
    fn finding_numeric_contracts_reject_invalid_writes_and_corrupt_history() {
        let db = SentinelDb::new_in_memory().unwrap();
        let mut f = Finding {
            id: "numeric".into(),
            severity: sentinel_core::Severity::High,
            confidence: 0.5,
            category: "rule".into(),
            file: "test.py".into(),
            line: 1,
            title: "title".into(),
            description: String::new(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        db.insert_finding(&f, "seed").unwrap();
        db.resolve_finding(&f.id).unwrap();
        for confidence in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -0.01, 1.01] {
            f.confidence = confidence;
            assert!(
                matches!(
                    db.insert_finding(&f, "invalid"),
                    Err(DbError::InvalidFindingNumbers)
                ),
                "{confidence}"
            );
            assert!(db.list_findings(true).unwrap().is_empty());
            assert_eq!(db.get_finding(&f.id).unwrap().unwrap().confidence, 0.5);
        }
        f.confidence = 0.5;
        f.line = 0;
        assert!(db.insert_finding(&f, "zero-line").is_err());
        if usize::BITS > 63 {
            f.line = usize::MAX;
            assert!(db.insert_finding(&f, "overflow-line").is_err());
        }
        f.line = 1;
        for confidence in [0.0, 1.0] {
            f.confidence = confidence;
            db.insert_finding(&f, "boundary").unwrap();
            assert_eq!(
                db.get_finding(&f.id).unwrap().unwrap().confidence,
                confidence
            );
        }
        if let Ok(max_line) = usize::try_from(i64::MAX) {
            let mut largest = f.clone();
            largest.id = "max-line".into();
            largest.line = max_line;
            db.insert_finding(&largest, "max-line").unwrap();
            assert_eq!(db.get_finding(&largest.id).unwrap().unwrap().line, max_line);
        }
        let mut first = f.clone();
        first.id = "first".into();
        first.line = 2;
        let mut invalid = f.clone();
        invalid.id = "invalid".into();
        invalid.line = 3;
        invalid.confidence = f64::INFINITY;
        let report = ScanReport {
            findings: vec![first, invalid],
            files_scanned: 1,
            symbols_indexed: 0,
            scanners_used: vec![],
            duration_ms: 0,
            outcome: ScanOutcome::Complete,
            coverage_notes: vec![],
            scanner_results: vec![],
        };
        assert!(matches!(
            db.persist_scan(ScanRecord {
                id: "invalid-numeric",
                target: Path::new("test.py"),
                report: &report,
                files: &[PathBuf::from("test.py")],
                full_scan: true
            }),
            Err(DbError::InvalidFindingNumbers)
        ));
        assert!(db.get_finding("first").unwrap().is_none());
        assert_eq!(db.get_finding(&f.id).unwrap().unwrap().confidence, 1.0);
        for table in ["scans", "scan_findings"] {
            let count: usize = db
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
        for confidence in [f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.01] {
            db.conn
                .execute("UPDATE findings SET confidence=?1", [confidence])
                .unwrap();
            assert!(db.get_finding(&f.id).is_err());
            assert!(db.list_findings(true).is_err());
            assert!(db
                .list_active_findings_for_files(&[f.file.clone()], 1)
                .is_err());
        }
        db.conn
            .execute("UPDATE findings SET confidence=0.5", [])
            .unwrap();
        for line in [0i64, -1, i64::MIN] {
            db.conn
                .execute("UPDATE findings SET line=?1", [line])
                .unwrap();
            assert!(db.get_finding(&f.id).is_err());
            assert!(db.list_findings(false).is_err());
        }
        db.conn
            .execute_batch("UPDATE findings SET line=0; PRAGMA user_version=0;")
            .unwrap();
        assert!(db.migrate().is_err());
        assert!(db.conn.is_autocommit());
        let line: i64 = db
            .conn
            .query_row("SELECT line FROM findings", [], |row| row.get(0))
            .unwrap();
        assert_eq!(line, 0);
        let version: i64 = db
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
    }

    #[test]
    fn finding_write_admission_matches_reads_and_rolls_back_failed_scans() {
        let db = SentinelDb::new_in_memory().unwrap();
        let f = Finding {
            id: "record".into(),
            severity: sentinel_core::Severity::High,
            confidence: 0.7,
            category: "rule".into(),
            file: "test.py".into(),
            line: 1,
            title: "title".into(),
            description: String::new(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        db.insert_finding(&f, "seed").unwrap();
        let base = f.id.len()
            + f.severity.to_string().len()
            + f.category.len()
            + f.file.to_string_lossy().len()
            + f.title.len()
            + f.recommendation.len()
            + 6;
        let mut exact = f.clone();
        exact.description = "x".repeat(MAX_FINDING_TEXT_BYTES - base);
        db.insert_finding(&exact, "exact").unwrap();
        assert_eq!(
            db.get_finding("record").unwrap().unwrap().description.len(),
            exact.description.len()
        );
        exact.description.push('é');
        assert!(matches!(
            db.insert_finding(&exact, "overflow"),
            Err(DbError::FindingTooLarge)
        ));
        assert_eq!(
            db.get_finding("record").unwrap().unwrap().description.len(),
            MAX_FINDING_TEXT_BYTES - base
        );
        db.insert_finding(&f, "seed").unwrap();
        for field in [
            "id",
            "category",
            "file",
            "title",
            "description",
            "recommendation",
            "execution_path",
            "affected_components",
            "evidence",
        ] {
            let mut bad = f.clone();
            let large = "sensitive".repeat(MAX_FINDING_TEXT_BYTES / 9 + 1);
            match field {
                "id" => bad.id = large,
                "category" => bad.category = large,
                "file" => bad.file = large.into(),
                "title" => bad.title = large,
                "description" => bad.description = large,
                "recommendation" => bad.recommendation = large,
                "execution_path" => bad.execution_path = vec![large],
                "affected_components" => bad.affected_components = vec![large],
                "evidence" => bad.evidence = vec![large],
                _ => unreachable!(),
            }
            let error = db.insert_finding(&bad, "rejected").unwrap_err();
            assert!(matches!(error, DbError::FindingTooLarge), "{field}");
            assert!(!error.to_string().contains("sensitive"));
        }
        let mut escaped = f.clone();
        escaped.evidence = vec!["\0".repeat(MAX_FINDING_TEXT_BYTES / 6)];
        assert!(matches!(
            db.insert_finding(&escaped, "escaped"),
            Err(DbError::FindingTooLarge)
        ));
        let mut combined = f.clone();
        combined.execution_path = vec!["x".repeat(MAX_FINDING_TEXT_BYTES / 2)];
        combined.affected_components = combined.execution_path.clone();
        assert!(matches!(
            db.insert_finding(&combined, "combined"),
            Err(DbError::FindingTooLarge)
        ));
        db.resolve_finding("record").unwrap();
        let mut bad_upsert = f.clone();
        bad_upsert.description = "x".repeat(MAX_FINDING_TEXT_BYTES);
        assert!(matches!(
            db.insert_finding(&bad_upsert, "bad-upsert"),
            Err(DbError::FindingTooLarge)
        ));
        assert!(db.list_findings(true).unwrap().is_empty());
        db.insert_finding(&f, "seed").unwrap();
        let mut first = f.clone();
        first.id = "first".into();
        first.line = 2;
        let mut second = bad_upsert;
        second.id = "second".into();
        second.line = 3;
        let report = ScanReport {
            findings: vec![first, second],
            files_scanned: 1,
            symbols_indexed: 0,
            scanners_used: vec![],
            duration_ms: 0,
            outcome: ScanOutcome::Complete,
            coverage_notes: vec![],
            scanner_results: vec![],
        };
        assert!(matches!(
            db.persist_scan(ScanRecord {
                id: "failed",
                target: Path::new("test.py"),
                report: &report,
                files: &[PathBuf::from("test.py")],
                full_scan: true
            }),
            Err(DbError::FindingTooLarge)
        ));
        assert!(db.conn.is_autocommit());
        assert_eq!(db.list_findings(true).unwrap().len(), 1);
        assert!(db.get_finding("first").unwrap().is_none());
        for table in ["scans", "scan_findings"] {
            let count: usize = db
                .conn
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
        let scan: String = db
            .conn
            .query_row(
                "SELECT scan_id FROM findings WHERE id='record'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scan, "seed");
    }

    #[test]
    fn scoped_active_history_filters_before_decoding_and_rejects_overflow() {
        let db = SentinelDb::new_in_memory().unwrap();
        for (id, file, line) in [
            ("b", "root/target.py", 1),
            ("a", "root\\target.py", 2),
            ("outside", "root/other.py", 3),
            ("resolved", "root/target.py", 4),
        ] {
            db.insert_finding(
                &Finding {
                    id: id.into(),
                    severity: sentinel_core::Severity::High,
                    confidence: 0.7,
                    category: "rule".into(),
                    file: file.into(),
                    line,
                    title: "title".into(),
                    description: String::new(),
                    execution_path: vec![],
                    affected_components: vec![],
                    evidence: vec![],
                    recommendation: String::new(),
                },
                "scan",
            )
            .unwrap();
        }
        db.resolve_finding("resolved").unwrap();
        let oversized = "x".repeat(MAX_FINDING_TEXT_BYTES + 1);
        db.conn
            .execute(
                "UPDATE findings SET evidence=?1 WHERE id='outside'",
                [&oversized],
            )
            .unwrap();
        let target = [PathBuf::from("root/target.py")];
        let findings = db.list_active_findings_for_files(&target, 2).unwrap();
        assert_eq!(
            findings.iter().map(|f| f.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(
            db.list_active_findings_for_files(&[PathBuf::from("root\\target.py")], 2)
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            db.list_active_findings_for_files(&target, 1),
            Err(DbError::FindingQueryLimit)
        ));
        assert!(matches!(
            db.list_active_findings_for_files(&[PathBuf::from("root/other.py")], 2),
            Err(DbError::FindingTooLarge)
        ));
        assert_eq!(
            db.list_active_findings_for_files(&vec![target[0].clone(); 2000], 2)
                .unwrap()
                .len(),
            2
        );
        assert!(db
            .list_active_findings_for_files(&[], 1)
            .unwrap()
            .is_empty());
        assert!(db
            .list_active_findings_for_files(&[PathBuf::from("x'); DROP TABLE findings; --")], 1)
            .unwrap()
            .is_empty());
        for limit in [0, 201, usize::MAX] {
            assert!(matches!(
                db.list_active_findings_for_files(&target, limit),
                Err(DbError::InvalidFindingQueryBudget)
            ));
        }
        assert!(matches!(
            db.list_active_findings_for_files(&vec![PathBuf::from("target.py"); 2001], 1),
            Err(DbError::InvalidFindingQueryBudget)
        ));
        // The lookahead signals overflow without decoding an inadmissible extra payload.
        db.conn
            .execute(
                "UPDATE findings SET evidence='invalid-json' WHERE id='b'",
                [],
            )
            .unwrap();
        assert!(matches!(
            db.list_active_findings_for_files(&target, 1),
            Err(DbError::FindingQueryLimit)
        ));
        assert!(db.list_active_findings_for_files(&target, 2).is_err());
        let active: usize = db
            .conn
            .query_row(
                "SELECT count(*) FROM findings WHERE resolved_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 3);
        assert!(db.conn.is_autocommit());
        let index: usize = db
            .conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='idx_findings_file_active'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(index, 1);
    }

    #[test]
    fn finding_reads_bound_every_text_field_and_aggregate_before_json_decoding() {
        let db = SentinelDb::new_in_memory().unwrap();
        let f = Finding {
            id: "record".into(),
            severity: sentinel_core::Severity::High,
            confidence: 0.7,
            category: "rule".into(),
            file: "test.py".into(),
            line: 1,
            title: "title".into(),
            description: String::new(),
            execution_path: vec![],
            affected_components: vec![],
            evidence: vec![],
            recommendation: String::new(),
        };
        db.insert_finding(&f, "scan").unwrap();
        let key = f.fingerprint();
        let columns = [
            "id",
            "severity",
            "category",
            "file",
            "title",
            "description",
            "execution_path",
            "affected_components",
            "evidence",
            "recommendation",
        ];
        let base: usize = columns
            .iter()
            .map(|column| {
                db.conn
                    .query_row(&format!("SELECT {column} FROM findings"), [], |r| {
                        r.get::<_, String>(0)
                    })
                    .unwrap()
                    .len()
            })
            .sum();
        let exact = "x".repeat(MAX_FINDING_TEXT_BYTES - base);
        db.conn
            .execute("UPDATE findings SET description=?1", [&exact])
            .unwrap();
        assert_eq!(db.get_finding(&key).unwrap().unwrap().description, exact);
        assert_eq!(db.list_findings(true).unwrap().len(), 1);
        // A multibyte character crosses the aggregate byte boundary, not a character count.
        db.conn
            .execute("UPDATE findings SET description=?1", [format!("{exact}é")])
            .unwrap();
        assert!(matches!(
            db.get_finding(&key),
            Err(DbError::FindingTooLarge)
        ));
        db.conn
            .execute("UPDATE findings SET description=''", [])
            .unwrap();
        let oversized = format!(
            "sensitive-invalid-json{}",
            "é".repeat(MAX_FINDING_TEXT_BYTES)
        );
        for column in columns {
            let original: String = db
                .conn
                .query_row(&format!("SELECT {column} FROM findings"), [], |r| r.get(0))
                .unwrap();
            db.conn
                .execute(&format!("UPDATE findings SET {column}=?1"), [&oversized])
                .unwrap();
            assert!(
                matches!(db.get_finding(&key), Err(DbError::FindingTooLarge)),
                "{column}"
            );
            assert!(
                matches!(db.list_findings(true), Err(DbError::FindingTooLarge)),
                "{column}"
            );
            let error = db.list_findings(false).unwrap_err().to_string();
            assert!(!error.contains("sensitive-invalid-json"));
            db.conn
                .execute(&format!("UPDATE findings SET {column}=?1"), [&original])
                .unwrap();
        }
        for column in ["confidence", "line"] {
            db.conn
                .execute(&format!("UPDATE findings SET {column}=?1"), [&oversized])
                .unwrap();
            assert!(db.get_finding(&key).is_err());
            let error = db.list_findings(true).unwrap_err().to_string();
            assert!(!error.contains("sensitive-invalid-json"));
            db.conn
                .execute("UPDATE findings SET confidence=0.7,line=1", [])
                .unwrap();
        }
        // Each cell fits independently; their sum still cannot exceed the row budget.
        let half = "x".repeat(MAX_FINDING_TEXT_BYTES / 2);
        db.conn
            .execute("UPDATE findings SET title=?1,description=?1", [&half])
            .unwrap();
        assert!(matches!(
            db.list_findings(true),
            Err(DbError::FindingTooLarge)
        ));
        // Migration rejects unreadable legacy records before changing any retained history.
        db.conn.execute_batch("PRAGMA user_version=0;").unwrap();
        assert!(matches!(db.migrate(), Err(DbError::FindingTooLarge)));
        assert!(db.conn.is_autocommit());
        let retained: usize = db
            .conn
            .query_row("SELECT length(description) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(retained, half.len());
        let version: i64 = db
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 0);
    }

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
        assert_eq!(version, 7);
        db.conn.execute_batch("PRAGMA user_version=8;").unwrap();
        assert!(db.migrate().is_err());
    }
}
