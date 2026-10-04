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
pub mod context;
pub mod diff;
pub mod verification;

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
        let path = path.as_ref();
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let path = path.canonicalize()?;
        if !path.starts_with(&self.root) {
            anyhow::bail!("path is outside the configured repository");
        }
        Ok(path)
    }
    /// Refresh changed files only. Relationship resolution uses the persisted IR for unchanged files.
    pub fn index(&self) -> Result<IndexStats> {
        let started = Instant::now();
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
        for entry in entries {
            let path = entry
                .path
                .strip_prefix(&self.root)?
                .to_string_lossy()
                .replace('\\', "/");
            let read = (|| -> Result<String> {
                let file = self.checked_path(&entry.path)?;
                let mut bytes = vec![];
                std::fs::File::open(file)?
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 1024 * 1024 {
                    anyhow::bail!("source exceeds 1 MiB");
                }
                Ok(String::from_utf8(bytes)?)
            })();
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
                break;
            }
            let hash = identity(&source);
            if let Some(old) = previous.get(&path).filter(|f| f.content_hash == hash) {
                current.push(old.clone());
                stats.unchanged_files += 1;
                continue;
            }
            match sentinel_ast::security::extract_security_file(&self.project_id, &path, &source) {
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
        for path in &trace.paths {
            let annotation = |kind: &str, step: &FlowStep| {
                current
                    .iter()
                    .flat_map(|f| &f.annotations)
                    .find(|a| {
                        a.kind == kind
                            && a.owner == step.symbol_id
                            && a.location.start_line == step.location.start_line
                    })
                    .map(|a| a.id.clone())
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
        stats.duration_ms = started.elapsed().as_millis();
        let tx = self.db.connection().unchecked_transaction()?;
        tx.execute("INSERT INTO projects(id,root) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET root=excluded.root",rusqlite::params![self.project_id,self.root.to_string_lossy()])?;
        for path in previous.keys().filter(|p| !current_paths.contains(*p)) {
            delete_file(&tx, &self.project_id, path)?;
        }
        for file in &current {
            if previous
                .get(&file.path)
                .is_some_and(|f| f.content_hash == file.content_hash)
            {
                continue;
            }
            delete_file(&tx, &self.project_id, &file.path)?;
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
        for edge in &edges {
            tx.execute("INSERT OR IGNORE INTO symbol_edges(project_id,owner_file,from_id,to_id,kind,line,name,resolved,payload) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",rusqlite::params![self.project_id,edge.file,edge.from,edge.to,edge.kind,edge.line as i64,edge.name,edge.resolved,serde_json::to_string(edge)?])?;
        }
        tx.execute("INSERT INTO index_metadata(project_id,payload) VALUES(?1,?2) ON CONFLICT(project_id) DO UPDATE SET payload=excluded.payload,updated_at=CURRENT_TIMESTAMP",rusqlite::params![self.project_id,serde_json::to_string(&stats)?])?;
        tx.commit()?;
        Ok(stats)
    }
    /// Last completed index statistics, without reparsing files.
    pub fn status(&self) -> Result<Option<IndexStats>> {
        use rusqlite::OptionalExtension;
        let data: Option<String> = self
            .db
            .connection()
            .query_row(
                "SELECT payload FROM index_metadata WHERE project_id=?1",
                [&self.project_id],
                |r| r.get(0),
            )
            .optional()?;
        data.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    fn load_files(&self) -> Result<Vec<IndexedFile>> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT payload FROM files WHERE project_id=?1 ORDER BY path")?;
        let rows = stmt.query_map([&self.project_id], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }
    /// Load a persisted snapshot. Query methods refresh it before use.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let files = self.load_files()?;
        let mut stmt = self.db.connection().prepare(
            "SELECT payload FROM symbol_edges WHERE project_id=?1 ORDER BY from_id,kind,line,to_id",
        )?;
        let rows = stmt.query_map([&self.project_id], |r| r.get::<_, String>(0))?;
        let edges = rows
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(Snapshot {
            files,
            edges,
            stats: self.status()?.unwrap_or_default(),
        })
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
    let symbols = files.iter().flat_map(|f| &f.symbols).collect::<Vec<_>>();
    for file in files {
        let file_id = identity((project, &file.path, "file"));
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
        for import in &file.imports {
            let target = files
                .iter()
                .find(|f| module_matches(&file.path, &import.module, &f.path));
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
            for import in &file.imports {
                if parts.first().copied() == Some(import.local.as_str()) {
                    let wanted = if import.imported == "*" {
                        short
                    } else {
                        import.imported.as_str()
                    };
                    candidates.extend(symbols.iter().copied().filter(|s| {
                        s.name == wanted
                            && module_matches(&file.path, &import.module, &s.location.file)
                    }));
                }
            }
            if candidates.is_empty() {
                if parts.len() == 1 {
                    candidates.extend(
                        file.symbols
                            .iter()
                            .filter(|s| s.name == short && s.kind != "module"),
                    );
                } else if matches!(parts.first().copied(), Some("self" | "this")) {
                    if let Some(owner) = symbols.iter().find(|s| s.id == call.owner) {
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
