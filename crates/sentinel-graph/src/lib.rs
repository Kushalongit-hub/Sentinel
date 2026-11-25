//! Persistent, local repository security graph and typed query service.
use anyhow::{Context, Result};
use sentinel_core::security::*;
use sentinel_db::SentinelDb;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};
pub mod analysis;
pub mod audit_workflow;
pub mod context;
pub mod diff;
pub mod jobs;
pub mod verification;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexTimings {
    pub source_refresh_ms: u128,
    #[serde(default)]
    pub source_read_ms: Option<u128>,
    #[serde(default)]
    pub source_extract_ms: Option<u128>,
    pub relationship_analysis_ms: u128,
    pub persistence_ms: u128,
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexStats {
    pub project_id: String,
    pub repository: String,
    pub files_indexed: usize,
    pub symbols: usize,
    pub call_edges: usize,
    pub sources: usize,
    pub sinks: usize,
    pub sanitizers: usize,
    pub security_guards: usize,
    pub changed_files: usize,
    pub unchanged_files: usize,
    pub removed_files: usize,
    pub duration_ms: u128,
    #[serde(default)]
    pub timings: Option<IndexTimings>,
    pub complete: bool,
    pub coverage_notes: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub id: String,
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub location: Location,
    pub language: String,
    pub content_hash: String,
}
impl From<&SymbolRecord> for SymbolInfo {
    fn from(s: &SymbolRecord) -> Self {
        Self {
            id: s.id.clone(),
            name: s.name.clone(),
            qualified_name: s.qualified_name.clone(),
            kind: s.kind.clone(),
            location: s.location.clone(),
            language: s.language.clone(),
            content_hash: s.content_hash.clone(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationships {
    #[serde(default)]
    pub backend: Option<AnalysisBackendIdentity>,
    #[serde(default)]
    pub source_snapshot: Option<String>,
    /// Completeness reported by graph refresh; output limits are separate.
    #[serde(default)]
    pub index_complete: bool,
    #[serde(default)]
    pub coverage_notes: Vec<String>,
    pub target: Vec<SymbolInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub edges: Vec<SecurityEdge>,
    pub omitted_count: usize,
    pub duration_ms: u128,
}
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub files: Vec<IndexedFile>,
    pub edges: Vec<SecurityEdge>,
    pub stats: IndexStats,
}
/// Repository-bound service backed by the existing Sentinel SQLite database.
pub struct Engine {
    pub root: PathBuf,
    pub project_id: String,
    pub db: SentinelDb,
}
impl Engine {
    /// Open and migrate the local project database; never execute project code.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            anyhow::bail!("repository must be a directory");
        }
        let project_id = identity(root.to_string_lossy().replace('\\', "/"));
        let path = root.join(".sentinel.db");
        if path.exists() && !path.canonicalize()?.starts_with(&root) {
            anyhow::bail!("project database resolves outside the repository");
        }
        for name in [
            ".sentinel.db-journal",
            ".sentinel.db-wal",
            ".sentinel.db-shm",
        ] {
            let sidecar = root.join(name);
            if let Ok(meta) = std::fs::symlink_metadata(&sidecar) {
                if meta.file_type().is_symlink() || !sidecar.canonicalize()?.starts_with(&root) {
                    anyhow::bail!("database sidecar is a symlink or outside repository");
                }
            }
        }
        let db = SentinelDb::new(path.to_str().context("invalid database path")?)?;
        Ok(Self {
            root,
            project_id,
            db,
        })
    }
    /// Resolve an existing request path and reject traversal or symlink escapes.
    pub fn checked_path(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        checked_project_path(&self.root, path.as_ref())
    }
    /// Refresh changed files only. Relationship resolution uses the persisted IR for unchanged files.
    pub fn index(&self) -> Result<IndexStats> {
        self.index_with_rebuild(false)
    }
    /// Explicitly replace this project's derived graph cache, preserving retained history.
    pub fn rebuild_index(&self) -> Result<IndexStats> {
        self.index_with_rebuild(true)
    }
    fn index_with_rebuild(&self, rebuild: bool) -> Result<IndexStats> {
        let started = Instant::now();
        // Reserve the writer before reading reusable IR; concurrent refreshes must not
        // apply deltas computed against a superseded database view.
        let tx = rusqlite::Transaction::new_unchecked(
            self.db.connection(),
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if rebuild {
            for table in [
                "symbol_edges",
                "security_annotations",
                "symbols",
                "files",
                "index_metadata",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE project_id=?1"),
                    [&self.project_id],
                )?;
            }
        }
        let previous = self.load_files()?;
        let previous: BTreeMap<_, _> = previous.into_iter().map(|f| (f.path.clone(), f)).collect();
        let mut entries = sentinel_ast::walk(self.root.to_str().context("invalid root path")?)?;
        entries.retain(|e| e.language.is_some());
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let mut stats = IndexStats {
            project_id: self.project_id.clone(),
            repository: self.root.to_string_lossy().into(),
            complete: true,
            ..Default::default()
        };
        if entries.len() > 2000 {
            stats.complete = false;
            stats
                .coverage_notes
                .push("file limit reached (2000)".into());
            entries.truncate(2000);
        }
        let mut current = vec![];
        let mut total = 0;
        let mut read_duration = std::time::Duration::ZERO;
        let mut extract_duration = std::time::Duration::ZERO;
        let mut pending = entries.into_iter().peekable();
        'refresh: while pending.peek().is_some() {
            // Near the admitted byte limit, retain the original single-file overshoot ceiling.
            let batch_limit = if total <= 12 * 1024 * 1024 { 4 } else { 1 };
            let batch = pending.by_ref().take(batch_limit).collect::<Vec<_>>();
            let read_started = Instant::now();
            let reads = read_source_batch(&self.root, &batch)?;
            read_duration += read_started.elapsed();
            for (entry, read) in batch.into_iter().zip(reads) {
                let path = entry
                    .path
                    .strip_prefix(&self.root)?
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = match read {
                    Ok(s) => s,
                    Err(e) => {
                        stats.complete = false;
                        stats.coverage_notes.push(format!("{path}: {e}"));
                        continue;
                    }
                };
                total += source.len();
                if total > 16 * 1024 * 1024 {
                    stats.complete = false;
                    stats
                        .coverage_notes
                        .push("source read budget reached (16 MiB)".into());
                    break 'refresh;
                }
                let hash = identity(&source);
                if let Some(old) = previous.get(&path).filter(|f| {
                    f.content_hash == hash && f.semantics_revision == ANALYSIS_SEMANTICS_REVISION
                }) {
                    current.push(old.clone());
                    stats.unchanged_files += 1;
                    continue;
                }
                let extract_started = Instant::now();
                let extracted =
                    sentinel_ast::security::extract_security_file(&self.project_id, &path, &source);
                extract_duration += extract_started.elapsed();
                match extracted {
                    Ok(file) => {
                        current.push(file);
                        stats.changed_files += 1;
                    }
                    Err(e) => {
                        stats.complete = false;
                        stats.coverage_notes.push(format!("{path}: {e}"));
                    }
                }
            }
        }
        let current_paths = current
            .iter()
            .map(|f| f.path.clone())
            .collect::<BTreeSet<_>>();
        stats.removed_files = previous
            .keys()
            .filter(|p| !current_paths.contains(*p))
            .count();
        for file in &current {
            if !file.notes.is_empty() {
                stats.complete = false;
                stats.coverage_notes.extend(file.notes.clone());
            }
        }
        stats.files_indexed = current.len();
        stats.symbols = current.iter().map(|f| f.symbols.len()).sum();
        let source_refresh_ms = started.elapsed().as_millis();
        let relationship_started = Instant::now();
        let mut edges = resolve_edges(&self.project_id, &current);
        let trace = sentinel_taint::interprocedural::trace_project(
            &current,
            &edges,
            TraceLimits::default(),
        );
        if !trace.complete {
            stats.complete = false;
            stats.coverage_notes.extend(trace.coverage_notes.clone());
        }
        let mut annotations = BTreeMap::new();
        for annotation in current
            .iter()
            .flat_map(|file| &file.annotations)
            .filter(|annotation| matches!(annotation.kind.as_str(), "source" | "sink"))
        {
            // Preserve the first match when multiple annotations share a source line.
            annotations
                .entry((
                    annotation.kind.as_str(),
                    annotation.owner.as_str(),
                    annotation.location.start_line,
                ))
                .or_insert(&annotation.id);
        }
        for path in &trace.paths {
            let annotation = |kind: &str, step: &FlowStep| {
                annotations
                    .get(&(kind, step.symbol_id.as_str(), step.location.start_line))
                    .map(|id| (*id).clone())
                    .unwrap_or_else(|| step.symbol_id.clone())
            };
            edges.push(SecurityEdge {
                from: annotation("source", &path.source),
                to: annotation("sink", &path.sink),
                kind: "FLOWS_TO".into(),
                file: path.sink.location.file.clone(),
                line: path.sink.location.start_line,
                name: path.id.clone(),
                resolved: path.confidence != "low",
            });
        }
        stats.call_edges = edges
            .iter()
            .filter(|e| e.kind == "CALLS" && e.resolved)
            .count();
        for a in current.iter().flat_map(|f| &f.annotations) {
            match a.kind.as_str() {
                "source" => stats.sources += 1,
                "sink" => stats.sinks += 1,
                "sanitizer" => stats.sanitizers += 1,
                "security_guard" => stats.security_guards += 1,
                _ => {}
            }
        }
        let relationship_analysis_ms = relationship_started.elapsed().as_millis();
        let persistence_started = Instant::now();
        tx.execute("INSERT INTO projects(id,root) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET root=excluded.root",rusqlite::params![self.project_id,self.root.to_string_lossy()])?;
        for path in previous.keys().filter(|p| !current_paths.contains(*p)) {
            delete_file(&tx, &self.project_id, path)?;
        }
        for file in &current {
            if previous.get(&file.path).is_some_and(|f| {
                f.content_hash == file.content_hash
                    && f.semantics_revision == file.semantics_revision
            }) {
                continue;
            }
            if previous.contains_key(&file.path) {
                delete_file(&tx, &self.project_id, &file.path)?;
            }
            tx.execute("INSERT INTO files(project_id,path,language,content_hash,payload) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![self.project_id,file.path,file.language,file.content_hash,serde_json::to_string(file)?])?;
            for symbol in &file.symbols {
                tx.execute("INSERT INTO symbols(id,project_id,file,name,qualified_name,kind,start_line,end_line,language,content_hash,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",rusqlite::params![symbol.id,self.project_id,file.path,symbol.name,symbol.qualified_name,symbol.kind,symbol.location.start_line as i64,symbol.location.end_line as i64,symbol.language,symbol.content_hash,serde_json::to_string(symbol)?])?;
            }
            for a in &file.annotations {
                tx.execute("INSERT INTO security_annotations(id,project_id,file,owner,kind,category,payload) VALUES(?1,?2,?3,?4,?5,?6,?7)",rusqlite::params![a.id,self.project_id,file.path,a.owner,a.kind,a.category,serde_json::to_string(a)?])?;
            }
        }
        tx.execute(
            "DELETE FROM symbol_edges WHERE project_id=?1",
            [&self.project_id],
        )?;
        {
            let mut insert = tx.prepare("INSERT OR IGNORE INTO symbol_edges(project_id,owner_file,from_id,to_id,kind,line,name,resolved,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)")?;
            for edge in &edges {
                insert.execute(rusqlite::params![
                    self.project_id,
                    edge.file,
                    edge.from,
                    edge.to,
                    edge.kind,
                    edge.line as i64,
                    edge.name,
                    edge.resolved,
                    serde_json::to_string(edge)?
                ])?;
            }
        }
        stats.timings = Some(IndexTimings {
            source_refresh_ms,
            source_read_ms: Some(read_duration.as_millis()),
            source_extract_ms: Some(extract_duration.as_millis()),
            relationship_analysis_ms,
            persistence_ms: persistence_started.elapsed().as_millis(),
        });
        // Persisted duration includes graph writes, but excludes the metadata write and commit.
        stats.duration_ms = started.elapsed().as_millis();
        self.db.set_index_metadata(&self.project_id, &stats)?;
        tx.commit()?;
        Ok(stats)
    }
    /// Last completed index statistics, without reparsing files.
    pub fn status(&self) -> Result<Option<IndexStats>> {
        let stats: Option<IndexStats> = self.db.get_index_metadata(&self.project_id)?;
        if let Some(stats) = &stats {
            if stats.project_id != self.project_id
                || stats.repository != self.root.to_string_lossy()
            {
                anyhow::bail!(
                    "persisted index statistics do not match this repository; refresh the index"
                );
            }
        }
        Ok(stats)
    }
    fn load_files(&self) -> Result<Vec<IndexedFile>> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT path,language,content_hash,payload FROM files WHERE project_id=?1 ORDER BY path")?;
        let rows = stmt.query_map([&self.project_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (path, language, content_hash, payload) = row?;
            let file: IndexedFile = serde_json::from_str(&payload)?;
            if file.path != path || file.language != language || file.content_hash != content_hash {
                anyhow::bail!("cached file identity mismatch between row and payload");
            }
            Ok(file)
        })
        .collect()
    }
    /// Load a persisted snapshot. Query methods refresh it before use.
    pub fn snapshot(&self) -> Result<Snapshot> {
        // Join an existing caller transaction, or pin one read view for all tables.
        let tx = self
            .db
            .connection()
            .is_autocommit()
            .then(|| self.db.connection().unchecked_transaction())
            .transpose()?;
        let files = self.load_files()?;
        let edges = {
            let mut stmt = self.db.connection().prepare(
                "SELECT from_id,to_id,kind,owner_file,line,name,resolved,payload FROM symbol_edges WHERE project_id=?1 ORDER BY from_id,kind,line,to_id",
            )?;
            let rows = stmt.query_map([&self.project_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })?;
            rows.map(|row| {
                let (from, to, kind, file, line, name, resolved, payload) = row?;
                let edge: SecurityEdge = serde_json::from_str(&payload)?;
                if edge.from != from
                    || edge.to != to
                    || edge.kind != kind
                    || edge.file != file
                    || usize::try_from(line).ok() != Some(edge.line)
                    || edge.name != name
                    || resolved != i64::from(edge.resolved)
                {
                    anyhow::bail!("cached edge identity mismatch between row and payload");
                }
                Ok(edge)
            })
            .collect::<Result<Vec<_>>>()?
        };
        let snapshot = Snapshot {
            files,
            edges,
            stats: self.status()?.unwrap_or_default(),
        };
        if let Some(tx) = tx {
            tx.commit()?;
        }
        Ok(snapshot)
    }
    /// Search symbol IDs, qualified names, names, or source file locations.
    pub(crate) fn normalized_target(&self, target: &str) -> Result<String> {
        if target.len() > 512 {
            anyhow::bail!("target exceeds 512 bytes");
        }
        let (file, line) = target
            .rsplit_once(':')
            .filter(|(_, n)| n.parse::<usize>().is_ok())
            .map(|(f, n)| (f, Some(n)))
            .unwrap_or((target, None));
        let file = if Path::new(file).is_absolute() {
            Path::new(file)
                .canonicalize()?
                .strip_prefix(&self.root)
                .context("target is outside repository")?
                .to_string_lossy()
                .replace('\\', "/")
        } else {
            file.trim_start_matches("./").replace('\\', "/")
        };
        Ok(if let Some(line) = line {
            format!("{file}:{line}")
        } else {
            file
        })
    }
    pub fn find_symbols(&self, query: &str, max_items: usize) -> Result<Relationships> {
        validate_limit(max_items)?;
        self.index()?;
        let start = Instant::now();
        let snapshot = self.snapshot()?;
        let query = self.normalized_target(query)?;
        let symbols = select_symbols(&snapshot, &query);
        let omitted_count = symbols.len().saturating_sub(max_items);
        Ok(Relationships {
            backend: Some(AnalysisBackendIdentity {
                name: "sentinel-native".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                semantics_revision: ANALYSIS_SEMANTICS_REVISION,
            }),
            source_snapshot: Some(identity(
                snapshot
                    .files
                    .iter()
                    .map(|file| (file.path.clone(), file.content_hash.clone()))
                    .collect::<BTreeMap<_, _>>(),
            )),
            index_complete: snapshot.stats.complete,
            coverage_notes: snapshot.stats.coverage_notes.clone(),
            target: vec![],
            symbols: symbols
                .into_iter()
                .take(max_items)
                .map(SymbolInfo::from)
                .collect(),
            edges: vec![],
            omitted_count,
            duration_ms: start.elapsed().as_millis(),
        })
    }
    /// Return incoming or outgoing resolved calls, preserving uncertainty in edge records.
    pub fn relationships(
        &self,
        target: &str,
        callers: bool,
        max_items: usize,
    ) -> Result<Relationships> {
        validate_limit(max_items)?;
        self.index()?;
        let start = Instant::now();
        let snapshot = self.snapshot()?;
        let target = self.normalized_target(target)?;
        let selected = select_symbols(&snapshot, &target);
        let ids = selected
            .iter()
            .map(|s| s.id.as_str())
            .collect::<BTreeSet<_>>();
        let all = snapshot
            .edges
            .iter()
            .filter(|e| {
                e.kind == "CALLS"
                    && if callers {
                        ids.contains(e.to.as_str())
                    } else {
                        ids.contains(e.from.as_str())
                    }
            })
            .collect::<Vec<_>>();
        let edges = all
            .iter()
            .take(max_items)
            .map(|e| (*e).clone())
            .collect::<Vec<_>>();
        let neighbors = edges
            .iter()
            .map(|e| {
                if callers {
                    e.from.as_str()
                } else {
                    e.to.as_str()
                }
            })
            .collect::<BTreeSet<_>>();
        let symbols = snapshot
            .files
            .iter()
            .flat_map(|f| &f.symbols)
            .filter(|s| neighbors.contains(s.id.as_str()))
            .map(SymbolInfo::from)
            .collect();
        let omitted_targets = selected.len().saturating_sub(max_items);
        Ok(Relationships {
            backend: Some(AnalysisBackendIdentity {
                name: "sentinel-native".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                semantics_revision: ANALYSIS_SEMANTICS_REVISION,
            }),
            source_snapshot: Some(identity(
                snapshot
                    .files
                    .iter()
                    .map(|file| (file.path.clone(), file.content_hash.clone()))
                    .collect::<BTreeMap<_, _>>(),
            )),
            index_complete: snapshot.stats.complete,
            coverage_notes: snapshot.stats.coverage_notes.clone(),
            target: selected
                .into_iter()
                .take(max_items)
                .map(SymbolInfo::from)
                .collect(),
            symbols,
            edges,
            omitted_count: all.len().saturating_sub(max_items) + omitted_targets,
            duration_ms: start.elapsed().as_millis(),
        })
    }
}
fn delete_file(tx: &rusqlite::Transaction<'_>, project: &str, path: &str) -> Result<()> {
    for table in ["files", "symbols", "security_annotations"] {
        let column = if table == "files" { "path" } else { "file" };
        tx.execute(
            &format!("DELETE FROM {table} WHERE project_id=?1 AND {column}=?2"),
            rusqlite::params![project, path],
        )?;
    }
    Ok(())
}
pub(crate) fn validate_limit(limit: usize) -> Result<()> {
    if !(1..=200).contains(&limit) {
        anyhow::bail!("max_items must be 1 to 200");
    }
    Ok(())
}
pub(crate) fn select_symbols<'a>(snapshot: &'a Snapshot, target: &str) -> Vec<&'a SymbolRecord> {
    let target = target.replace('\\', "/");
    let (file, line) = target
        .rsplit_once(':')
        .and_then(|(file, line)| line.parse::<usize>().ok().map(|line| (file, line)))
        .unwrap_or((target.as_str(), 0));
    let all = snapshot
        .files
        .iter()
        .flat_map(|f| &f.symbols)
        .collect::<Vec<_>>();
    let exact = all
        .iter()
        .copied()
        .filter(|s| {
            s.id == target
                || s.name == target
                || s.qualified_name == target
                || (s.location.file == file
                    && (line == 0
                        || (s.location.start_line <= line && s.location.end_line >= line)))
        })
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return exact;
    }
    all.into_iter()
        .filter(|s| s.name.to_lowercase().contains(&target.to_lowercase()))
        .collect()
}
fn module_matches(owner: &str, module: &str, target: &str) -> bool {
    let module = module.trim_matches(['\'', '"']).replace("::", "/");
    let module = if module.starts_with("./") || module.starts_with("../") {
        let mut parts = Path::new(owner)
            .parent()
            .unwrap_or(Path::new(""))
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for part in module.split('/') {
            match part {
                "." | "" => {}
                ".." => {
                    parts.pop();
                }
                value => parts.push(value.into()),
            }
        }
        parts.join("/")
    } else if module.starts_with('.') {
        let dots = module.chars().take_while(|c| *c == '.').count();
        let mut parent = Path::new(owner)
            .parent()
            .unwrap_or(Path::new(""))
            .to_path_buf();
        for _ in 1..dots {
            parent.pop();
        }
        parent
            .join(module[dots..].trim_start_matches('/').replace('.', "/"))
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        module.trim_start_matches("crate/").replace('.', "/")
    };
    let module = module.trim_start_matches("./");
    [
        "",
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".rs",
        "/index.js",
        "/index.ts",
        "/__init__.py",
        "/mod.rs",
    ]
    .iter()
    .any(|suffix| {
        target == format!("{module}{suffix}") || target == format!("src/{module}{suffix}")
    })
}
/// Resolve only unambiguous lexical or imported calls; dynamic receivers remain unresolved.
pub fn resolve_edges(project: &str, files: &[IndexedFile]) -> Vec<SecurityEdge> {
    let mut edges = vec![];
    let mut symbols_by_name: BTreeMap<&str, Vec<&SymbolRecord>> = BTreeMap::new();
    let mut symbols_by_id = BTreeMap::new();
    for symbol in files.iter().flat_map(|file| &file.symbols) {
        symbols_by_name
            .entry(&symbol.name)
            .or_default()
            .push(symbol);
        // Match the previous linear lookup's first-result behavior.
        symbols_by_id.entry(symbol.id.as_str()).or_insert(symbol);
    }
    for file in files {
        let file_id = identity((project, &file.path, "file"));
        let class_scopes = file
            .symbols
            .iter()
            .filter(|symbol| file.language == "python" && symbol.kind == "class")
            .map(|symbol| symbol.qualified_name.as_str())
            .collect::<BTreeSet<_>>();
        let import_targets = file
            .imports
            .iter()
            .map(|import| {
                let mut targets = files
                    .iter()
                    .filter(|target| module_matches(&file.path, &import.module, &target.path));
                let first = targets.next();
                if targets.next().is_none() {
                    first
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for symbol in &file.symbols {
            edges.push(SecurityEdge {
                from: file_id.clone(),
                to: symbol.id.clone(),
                kind: "DEFINES".into(),
                file: file.path.clone(),
                line: symbol.location.start_line,
                name: symbol.name.clone(),
                resolved: true,
            });
        }
        for (import, target) in file.imports.iter().zip(&import_targets) {
            edges.push(SecurityEdge {
                from: file_id.clone(),
                to: target
                    .map(|f| identity((project, &f.path, "file")))
                    .unwrap_or_else(|| format!("unresolved-module:{}", import.module)),
                kind: "IMPORTS".into(),
                file: file.path.clone(),
                line: import.line,
                name: import.module.clone(),
                resolved: target.is_some(),
            });
        }
        for call in &file.calls {
            let mut candidates = vec![];
            let normalized = call.name.replace("::", ".");
            let parts = normalized.split('.').collect::<Vec<_>>();
            let short = parts.last().copied().unwrap_or("");
            let owner_scope = symbols_by_id
                .get(call.owner.as_str())
                .map(|s| s.qualified_name.as_str())
                .unwrap_or("");
            let visible_scope = |scope: &str| {
                scope.is_empty()
                    || scope == owner_scope
                    || (!class_scopes.contains(scope)
                        && owner_scope
                            .strip_prefix(scope)
                            .is_some_and(|rest| rest.starts_with('.')))
            };
            let mut call_imports = file
                .imports
                .iter()
                .zip(&import_targets)
                .filter(|(import, _)| {
                    parts.first().copied() == Some(import.local.as_str())
                        && (file.language != "python" || visible_scope(&import.scope))
                })
                .collect::<Vec<_>>();
            if file.language == "python" {
                let nearest = call_imports
                    .iter()
                    .map(|(import, _)| import.scope.len())
                    .max();
                call_imports.retain(|(import, _)| Some(import.scope.len()) == nearest);
            }
            for (import, target) in &call_imports {
                if file.language == "python" {
                    let expected_parts = if import.imported == "*" { 2 } else { 1 };
                    if parts.len() != expected_parts {
                        // Do not turn an attribute chain into a call to its import binding.
                        continue;
                    }
                }
                let wanted = if import.imported == "*" {
                    short
                } else {
                    import.imported.as_str()
                };
                if target.is_none() {
                    continue;
                }
                candidates.extend(
                    symbols_by_name
                        .get(wanted)
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|s| {
                            module_matches(&file.path, &import.module, &s.location.file)
                                    // Python module imports expose module-level definitions,
                                    // never unrelated class/nested methods with the same name.
                                    && (file.language != "python"
                                        || s.qualified_name == wanted)
                        }),
                );
            }
            if candidates.is_empty() {
                if parts.len() == 1 {
                    let mut scope = owner_scope;
                    loop {
                        let wanted = if scope.is_empty() {
                            short.to_string()
                        } else {
                            format!("{scope}.{short}")
                        };
                        // Python class namespaces are not enclosing function closures.
                        // Keep the class's own body lookup, but skip it from methods.
                        let skip_class = scope != owner_scope && class_scopes.contains(scope);
                        let local = file
                            .symbols
                            .iter()
                            .filter(|s| {
                                !skip_class && s.qualified_name == wanted && s.kind != "module"
                            })
                            .collect::<Vec<_>>();
                        if !local.is_empty() {
                            candidates.extend(local);
                            break;
                        }
                        if scope.is_empty() {
                            break;
                        }
                        scope = scope
                            .rsplit_once('.')
                            .map(|(parent, _)| parent)
                            .unwrap_or("");
                    }
                } else if parts.len() == 2
                    && matches!(parts.first().copied(), Some("self" | "this"))
                {
                    if let Some(owner) = symbols_by_id.get(call.owner.as_str()) {
                        let scope = owner
                            .qualified_name
                            .rsplit_once('.')
                            .map(|(s, _)| s)
                            .unwrap_or("");
                        candidates.extend(
                            file.symbols
                                .iter()
                                .filter(|s| s.qualified_name == format!("{scope}.{short}")),
                        );
                    }
                }
            }
            if parts.len() == 1
                && !call_imports.is_empty()
                && file.symbols.iter().any(|s| {
                    if s.name != short || s.kind == "module" {
                        return false;
                    }
                    if file.language != "python" {
                        return true;
                    }
                    let scope = s
                        .qualified_name
                        .rsplit_once('.')
                        .map(|(p, _)| p)
                        .unwrap_or("");
                    // Only visible lexical definitions can conflict with an import.
                    visible_scope(scope)
                })
            {
                candidates.clear();
            }
            // Repeated bindings to the same symbol do not create another possible target.
            candidates.sort_by(|left, right| left.id.cmp(&right.id));
            candidates.dedup_by(|left, right| left.id == right.id);
            let resolved = candidates.len() == 1;
            let to = if resolved {
                candidates[0].id.clone()
            } else {
                format!("unresolved:{}", call.name)
            };
            edges.push(SecurityEdge {
                from: call.owner.clone(),
                to,
                kind: "CALLS".into(),
                file: file.path.clone(),
                line: call.line,
                name: call.name.clone(),
                resolved,
            });
        }
        for a in &file.annotations {
            let kind = match a.kind.as_str() {
                "source" => "READS_FROM",
                "sink" => "WRITES_TO",
                "sanitizer" => "SANITIZED_BY",
                "security_guard" => "GUARDED_BY",
                "endpoint" => "DEFINES",
                _ => continue,
            };
            edges.push(SecurityEdge {
                from: a.owner.clone(),
                to: a.id.clone(),
                kind: kind.into(),
                file: file.path.clone(),
                line: a.location.start_line,
                name: a.name.clone(),
                resolved: a.kind != "security_guard",
            });
        }
    }
    edges.sort_by(|a, b| (&a.from, &a.kind, a.line, &a.to).cmp(&(&b.from, &b.kind, b.line, &b.to)));
    edges
}

/// Bound bytes during the read; metadata alone cannot cap a growing file.
pub(crate) fn read_source(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        anyhow::bail!("source exceeds 1 MiB");
    }
    Ok(String::from_utf8(bytes)?)
}

fn checked_project_path(root: &Path, path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let path = path.canonicalize()?;
    if !path.starts_with(root) {
        anyhow::bail!("path is outside the configured repository");
    }
    Ok(path)
}

/// At most four byte-capped source buffers; results stay in lexical admission order.
fn read_source_batch(
    root: &Path,
    entries: &[sentinel_ast::FileEntry],
) -> Result<Vec<Result<String>>> {
    if entries.len() > 4 {
        anyhow::bail!("source batch exceeds four-file limit");
    }
    let read = |entry: &sentinel_ast::FileEntry| {
        checked_project_path(root, &entry.path).and_then(|path| read_source(&path))
    };
    if entries.len() <= 1 {
        return Ok(entries.iter().map(read).collect());
    }
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for entry in entries {
            workers.push(
                std::thread::Builder::new()
                    .name("sentinel-source-read".into())
                    .spawn_scoped(scope, || read(entry))?,
            );
        }
        // Join all workers even if one panics, so scoped teardown never leaves an unjoined panic.
        let joined = workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>();
        joined
            .into_iter()
            .map(|result| result.map_err(|_| anyhow::anyhow!("source read worker panicked")))
            .collect()
    })
}
