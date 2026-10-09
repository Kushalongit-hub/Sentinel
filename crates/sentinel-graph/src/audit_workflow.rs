use crate::Engine;
use anyhow::{bail, Context, Result};
use rusqlite::{params, OptionalExtension};
use sentinel_core::security::identity;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
include!(concat!(env!("OUT_DIR"), "/audit_assets.rs"));
const LIMIT: usize = 2 * 1024 * 1024;
const KEY: &str = "audit-workflow.latest.v1";
pub const REVISION: &str = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub run_id: String,
    pub repo: String,
    pub target: PathBuf,
    pub source_ref: String,
    pub source_snapshot: String,
    pub source_manifest: BTreeMap<String, String>,
    pub include_paths: Vec<String>,
    pub snapshot_notes: Vec<String>,
    pub profile: String,
    pub scope_paths: Vec<String>,
    pub budget: Option<usize>,
    pub execution_policy: String,
    pub upstream_revision: String,
    pub run_status: String,
    pub selected_companion_files: Vec<String>,
    pub prior_run_paths: Vec<String>,
    pub shared_file_owners: BTreeMap<String, String>,
    pub incomplete_reason: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRun {
    pub metadata: Metadata,
    pub coverage: Value,
    pub findings: Value,
    pub verification: Value,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditStatus {
    pub available: bool,
    pub run_id: Option<String>,
    pub source_snapshot: Option<String>,
    pub stale: bool,
    pub run_status: Option<String>,
    pub coverage_counts: BTreeMap<String, usize>,
    pub finding_counts: BTreeMap<String, usize>,
    pub partial_coverage: bool,
    pub notes: Vec<String>,
    pub report: Option<AuditRun>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditHistory {
    pub revisions: Vec<AuditRevision>,
    pub has_more: bool,
    pub source_freshness_checked: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditRevision {
    pub revision_id: String,
    pub run_id: String,
    pub source_snapshot: String,
    pub run_status: String,
    pub imported_at: String,
    pub is_latest: bool,
}
/// Descriptor for normalized JSON retained in an immutable imported revision.
/// Hash/size refer to canonical serialization, not the original on-disk bytes.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditArtifact {
    pub schema_version: u32,
    pub revision_id: String,
    pub name: String,
    pub media_type: String,
    pub encoding: String,
    pub content_hash: String,
    pub size_bytes: usize,
    pub source_snapshot: String,
    pub provenance: String,
    pub execution_observed: bool,
}
fn artifact_descriptors(run: &AuditRun, revision: &str) -> Result<Vec<AuditArtifact>> {
    [
        ("run-metadata.json", serde_json::to_value(&run.metadata)?),
        ("coverage-ledger.json", run.coverage.clone()),
        ("findings.json", run.findings.clone()),
        ("verification.json", run.verification.clone()),
    ]
    .into_iter()
    .map(|(name, value)| {
        Ok(AuditArtifact {
            schema_version: 1,
            revision_id: revision.into(),
            name: name.into(),
            media_type: "application/json".into(),
            encoding: "sentinel-serde-json-v1".into(),
            content_hash: identity(&value),
            size_bytes: serde_json::to_vec(&value)?.len(),
            source_snapshot: run.metadata.source_snapshot.clone(),
            provenance: "validated-import-attestation".into(),
            execution_observed: false,
        })
    })
    .collect()
}
fn asset(name: &str) -> &'static str {
    ASSETS
        .iter()
        .find(|(n, _)| *n == name)
        .expect("embedded audit asset")
        .1
}
pub fn workflow() -> Value {
    json!({"upstream_revision":REVISION,"skill":asset("SKILL.md"),"validation_runtime":"Node.js; SENTINEL_AUDIT_NODE optionally selects an executable", "target_execution":false,"schema_validation_is_exploit_proof":false})
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}
fn new_directory(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context("output parent must already exist")?;
    let name = path
        .file_name()
        .context("output must name a new directory")?;
    let result = parent.join(name);
    fs::create_dir(&result).context("output directory must be new")?;
    Ok(result)
}
pub fn export_skill(output: &Path) -> Result<PathBuf> {
    let output = new_directory(output)?;
    export_assets(&output)?;
    Ok(output)
}
fn export_assets(output: &Path) -> Result<()> {
    for (name, contents) in ASSETS {
        let path = output.join(name);
        fs::create_dir_all(path.parent().unwrap())?;
        write_new(&path, contents.as_bytes())?;
    }
    Ok(())
}
fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 {
        bail!("input must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("input exceeded its byte limit");
    }
    Ok(bytes)
}
impl Engine {
    fn audit_snapshot(
        &self,
        include: &[String],
    ) -> Result<(BTreeMap<String, String>, Vec<String>)> {
        if include.len() > 100 {
            bail!("at most 100 explicitly included files");
        }
        let mut paths: BTreeSet<_> =
            sentinel_ast::walk(self.root.to_str().context("invalid root")?)?
                .into_iter()
                .map(|f| f.path)
                .collect();
        for file in include {
            paths.insert(self.checked_path(file)?);
        }
        if paths.len() > 2000 {
            bail!("audit snapshot exceeds 2000 files; narrow the repository");
        }
        let mut manifest = BTreeMap::new();
        let mut notes = vec!["Snapshot uses Sentinel's selected text files: ignored/hidden files, lockfiles, generated directories and binary assets are excluded unless explicitly included. Maximum 2000 files, 1 MiB/file, 16 MiB total. A snapshot is not audit coverage.".into()];
        let mut total = 0;
        for path in paths {
            let checked = self.checked_path(&path)?;
            let name = checked
                .strip_prefix(&self.root)?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = bounded_file(&checked, 1024 * 1024)?;
            total += bytes.len();
            if total > 16 * 1024 * 1024 {
                bail!("audit snapshot exceeds 16 MiB");
            }
            match String::from_utf8(bytes) {
                Ok(text) => {
                    manifest.insert(name, identity(text));
                }
                Err(_) => notes.push(format!("Non-UTF8 file omitted: {name}")),
            }
        }
        Ok((manifest, notes))
    }
    pub fn init_audit_run(&self, output: &Path, include: Vec<String>) -> Result<Metadata> {
        // Resolve and reject an in-target output before creating anything.
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if parent.canonicalize()?.starts_with(&self.root) {
            bail!("audit runs must be outside the target repository");
        }
        let stats = self.index()?;
        let (manifest, notes) = self.audit_snapshot(&include)?;
        let snapshot = identity(&manifest);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let metadata = Metadata {
            run_id: format!("run-{stamp}"),
            repo: self.project_id.clone(),
            target: self.root.clone(),
            source_ref: sentinel_scanner::git::commit(&self.root, "HEAD")
                .map(|commit| {
                    let dirty = sentinel_scanner::git::read(
                        &self.root,
                        &["status", "--porcelain", "--untracked-files=normal"],
                        65536,
                    )
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(true);
                    format!("{commit}; dirty={dirty}; selected-source:{snapshot}")
                })
                .unwrap_or_else(|_| format!("no-git; selected-source:{snapshot}")),
            source_snapshot: snapshot,
            source_manifest: manifest,
            include_paths: include,
            snapshot_notes: notes,
            profile: "standard".into(),
            scope_paths: vec!["selected-text-files".into()],
            budget: None,
            execution_policy: "sandboxed-source-and-local-only".into(),
            upstream_revision: REVISION.into(),
            run_status: "in_progress".into(),
            selected_companion_files: Vec::new(),
            prior_run_paths: Vec::new(),
            shared_file_owners: [
                "run-metadata.json",
                "architecture.md",
                "coverage-ledger.json",
                "findings.json",
                "verification.json",
            ]
            .into_iter()
            .map(|name| (name.into(), "parent".into()))
            .collect(),
            incomplete_reason: None,
        };
        let mut coverage = Vec::new();
        for file in self.load_files()? {
            let refs = json!({"surface":format!("{}#file",file.path),"boundary":format!("{}#trust-boundary-to-review",file.path),"subsystem":"repository","attack_class":"ATTACK-CLASSES.md#obvious-things"});
            let encode = |s: &str| {
                s.as_bytes()
                    .iter()
                    .map(|b| {
                        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                            (*b as char).to_string()
                        } else {
                            format!("%{b:02X}")
                        }
                    })
                    .collect::<String>()
            };
            let id = format!(
                "{}::{}::{}::{}",
                encode(refs["surface"].as_str().unwrap()),
                encode(refs["boundary"].as_str().unwrap()),
                encode("repository"),
                encode("ATTACK-CLASSES.md#obvious-things")
            );
            coverage.push(json!({"coverage_id":id,"canonical_refs":refs,"surface":file.path,"boundary":"Unreviewed; replace during reconnaissance","subsystem":"Repository","attack_class":"Initial source review","starting_paths":[file.path],"ordinary_attack_class_block":"ATTACK-CLASSES.md#obvious-things","selected_companion_blocks":[],"excluded_blocks":[],"prior_status":"new","attempts":[],"wave":1,"status":"planned","agent_id":null,"reviewed_paths":[],"local_checks":[],"result_fingerprints":[],"unresolved":[]}));
        }
        coverage.sort_by(|a, b| a["coverage_id"].as_str().cmp(&b["coverage_id"].as_str()));
        let output = new_directory(output)?;
        let skill = output.join("skill");
        fs::create_dir(&skill)?;
        export_assets(&skill)?;
        for (name, value) in [
            ("run-metadata.json", serde_json::to_value(&metadata)?),
            ("coverage-ledger.json", json!(coverage)),
            ("findings.json", json!([])),
            ("verification.json", json!([])),
            ("index-evidence.json", serde_json::to_value(stats)?),
        ] {
            write_new(&output.join(name), &serde_json::to_vec_pretty(&value)?)?;
        }
        write_new(&output.join("architecture.md"), b"# Reconnaissance pending\n\nUse index-evidence.json and Sentinel MCP to map entry points, trust boundaries, assets, and omitted surfaces. Planned ledger units do not imply coverage.\n")?;
        Ok(metadata)
    }
    /// Recover legacy compatibility records without promoting them into audit tables.
    /// Export is not validation; the normal validate/import path remains mandatory.
    pub fn export_legacy_audit_run(&self, output: &Path) -> Result<PathBuf> {
        let value = self
            .db
            .get_memory(KEY)?
            .context("no legacy audit record available")?;
        if value.len() > LIMIT {
            bail!("legacy audit record exceeds 2 MiB");
        }
        let run: AuditRun = serde_json::from_str(&value)?;
        if run.metadata.target != self.root || run.metadata.repo != self.project_id {
            bail!("legacy audit belongs to another repository");
        }
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if parent.canonicalize()?.starts_with(&self.root) {
            bail!("legacy export must be outside the target repository");
        }
        let records = [
            ("run-metadata.json", serde_json::to_value(&run.metadata)?),
            ("coverage-ledger.json", run.coverage),
            ("findings.json", run.findings),
            ("verification.json", run.verification),
        ]
        .into_iter()
        .map(|(name, value)| Ok((name, serde_json::to_vec_pretty(&value)?)))
        .collect::<Result<Vec<_>>>()?;
        if records.iter().any(|(_, bytes)| bytes.len() > LIMIT) {
            bail!("legacy export record exceeds 2 MiB");
        }
        let directory = new_directory(output)?;
        for (name, bytes) in records {
            write_new(&directory.join(name), &bytes)?;
        }
        Ok(directory)
    }
    pub fn validate_audit_run(&self, directory: &Path) -> Result<AuditRun> {
        let directory = directory.canonicalize()?;
        if directory.starts_with(&self.root) {
            bail!("audit run must be outside the target");
        }
        let read = |name: &str| -> Result<Value> {
            let path = directory.join(name);
            if !path.canonicalize()?.starts_with(&directory) {
                bail!("audit input escapes run directory");
            }
            Ok(serde_json::from_slice(&bounded_file(&path, LIMIT)?)?)
        };
        let run = AuditRun {
            metadata: serde_json::from_value(read("run-metadata.json")?)?,
            coverage: read("coverage-ledger.json")?,
            findings: read("findings.json")?,
            verification: read("verification.json")?,
        };
        if serde_json::to_vec(&run)?.len() > LIMIT {
            bail!("combined audit record exceeds 2 MiB");
        }
        self.check_audit_run(&run)?;
        validate_upstream(&run)?;
        Ok(run)
    }
    fn check_audit_run(&self, run: &AuditRun) -> Result<()> {
        let m = &run.metadata;
        if m.target != self.root
            || m.repo != self.project_id
            || m.upstream_revision != REVISION
            || m.execution_policy != "sandboxed-source-and-local-only"
        {
            bail!("audit provenance or repository does not match");
        }
        if !safe_id(&m.run_id)
            || !["in_progress", "complete", "incomplete"].contains(&m.run_status.as_str())
            || !["quick", "standard", "deep"].contains(&m.profile.as_str())
        {
            bail!("invalid audit metadata state");
        }
        let (current, _) = self.audit_snapshot(&m.include_paths)?;
        if current != m.source_manifest || identity(&current) != m.source_snapshot {
            bail!(
                "audit source snapshot is stale; start a new run and revalidate changed evidence"
            );
        }
        let units = run
            .coverage
            .as_array()
            .context("coverage must be an array")?;
        let findings = run
            .findings
            .as_array()
            .context("findings must be an array")?;
        let reviews = run
            .verification
            .as_array()
            .context("verification must be an array")?;
        let fingerprints: BTreeSet<_> = findings
            .iter()
            .filter_map(|f| f["fingerprint"].as_str())
            .collect();
        let mut linked = BTreeSet::new();
        let mut line_counts = BTreeMap::new();
        for unit in units {
            if m.run_status == "complete"
                && ["planned", "assigned", "in_progress"]
                    .contains(&unit["status"].as_str().unwrap_or(""))
            {
                bail!("complete run contains unfinished coverage units");
            }
            for key in ["starting_paths", "reviewed_paths"] {
                for path in unit[key]
                    .as_array()
                    .context("coverage paths must be arrays")?
                {
                    self.audit_location(
                        path.as_str().context("invalid source path")?,
                        None,
                        m,
                        &mut line_counts,
                    )?;
                }
            }
            for fp in unit["result_fingerprints"]
                .as_array()
                .context("coverage fingerprints must be an array")?
            {
                let fp = fp.as_str().context("invalid fingerprint")?;
                if !fingerprints.contains(fp) {
                    bail!("a ledger candidate is not accounted for in findings");
                }
                linked.insert(fp);
            }
            for check in unit["local_checks"]
                .as_array()
                .context("local_checks must be an array")?
            {
                for path in check["reviewed_paths"]
                    .as_array()
                    .context("check paths must be an array")?
                {
                    self.audit_location(
                        path.as_str().context("invalid path")?,
                        None,
                        m,
                        &mut line_counts,
                    )?;
                }
            }
        }
        let mut review_ids = BTreeSet::new();
        for review in reviews {
            let fp = review["fingerprint"]
                .as_str()
                .context("review missing fingerprint")?;
            if !review_ids.insert(fp) || !fingerprints.contains(fp) {
                bail!("duplicate or unknown review fingerprint");
            }
        }
        for finding in findings {
            let fp = finding["fingerprint"]
                .as_str()
                .context("missing fingerprint")?;
            if !linked.contains(fp) {
                bail!("a finding is not linked to a coverage unit");
            }
            for key in ["trace", "evidence"] {
                for loc in finding[key]
                    .as_array()
                    .context("finding source evidence must be an array")?
                {
                    self.audit_location(
                        loc["file"].as_str().context("missing evidence file")?,
                        loc["line"].as_u64(),
                        m,
                        &mut line_counts,
                    )?;
                    if loc["line"].as_u64().is_none() {
                        bail!("missing source line");
                    }
                }
            }
            if finding["verdict"] == "confirmed" {
                let review = reviews
                    .iter()
                    .find(|r| r["fingerprint"] == fp)
                    .context("confirmed finding requires independent verification attestation")?;
                let hunter = review["discoverer"]
                    .as_str()
                    .context("missing discoverer")?;
                let verifier = review["verifier"].as_str().context("missing verifier")?;
                if !safe_id(hunter)
                    || !safe_id(verifier)
                    || hunter == verifier
                    || review["source_snapshot"] != m.source_snapshot
                    || review["method"] != "sandboxed-local"
                    || review["observed_result"] != finding["execution"]["observed_result"]
                {
                    bail!("invalid independent review or observed result");
                }
                let owners: Vec<_> = units
                    .iter()
                    .filter(|u| {
                        u["result_fingerprints"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|v| v == fp))
                    })
                    .filter_map(|u| u["agent_id"].as_str())
                    .collect();
                if !owners.contains(&hunter) || owners.contains(&verifier) {
                    bail!("review identities do not preserve discovery independence");
                }
                for key in [
                    "network_disabled",
                    "environment_allowlisted",
                    "read_only_target",
                    "scratch_only_writes",
                    "resource_limited",
                ] {
                    if review["sandbox"][key] != true {
                        bail!("confirmed reproduction lacks sandbox control {key}");
                    }
                }
                if review["sandbox"]["limits"]
                    .as_str()
                    .is_none_or(|s| s.trim().is_empty())
                {
                    bail!("sandbox limits must be recorded");
                }
            }
        }
        Ok(())
    }
    fn audit_location(
        &self,
        file: &str,
        line: Option<u64>,
        metadata: &Metadata,
        line_counts: &mut BTreeMap<String, usize>,
    ) -> Result<()> {
        if !metadata.source_manifest.contains_key(file) {
            bail!("evidence path is outside the recorded snapshot");
        }
        if let Some(line) = line {
            if !line_counts.contains_key(file) {
                let text =
                    String::from_utf8(bounded_file(&self.checked_path(file)?, 1024 * 1024)?)?;
                if identity(&text) != metadata.source_manifest[file] {
                    bail!("source changed during evidence validation");
                }
                line_counts.insert(file.into(), text.lines().count());
            }
            if line == 0 || line > line_counts[file] as u64 {
                bail!("evidence line is outside source");
            }
        }
        Ok(())
    }
    pub fn import_audit_run(&self, directory: &Path) -> Result<AuditStatus> {
        let run = self.validate_audit_run(directory)?;
        let encoded = serde_json::to_string(&run)?;
        let revision = identity(&run);
        let tx = self.db.connection().unchecked_transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM audit_revisions WHERE project_id=?1 AND revision_id=?2)",
            params![self.project_id, revision],
            |row| row.get(0),
        )?;
        if !exists {
            tx.execute("INSERT INTO audit_revisions(project_id,revision_id,run_id,source_snapshot,status,payload) VALUES (?1,?2,?3,?4,?5,?6)",
                params![self.project_id,revision,run.metadata.run_id,run.metadata.source_snapshot,run.metadata.run_status,encoded])?;
            for unit in run.coverage.as_array().context("invalid coverage")? {
                let id = unit["coverage_id"]
                    .as_str()
                    .context("missing coverage id")?;
                tx.execute("INSERT INTO audit_coverage(project_id,revision_id,coverage_id,status,payload) VALUES (?1,?2,?3,?4,?5)",
                    params![self.project_id,revision,id,unit["status"].as_str(),serde_json::to_string(unit)?])?;
                for (ordinal, attempt) in unit["attempts"]
                    .as_array()
                    .context("invalid attempts")?
                    .iter()
                    .enumerate()
                {
                    tx.execute("INSERT INTO audit_attempts(project_id,revision_id,coverage_id,ordinal,payload) VALUES (?1,?2,?3,?4,?5)",
                        params![self.project_id,revision,id,ordinal as i64,serde_json::to_string(attempt)?])?;
                }
            }
            for finding in run.findings.as_array().context("invalid findings")? {
                tx.execute("INSERT INTO audit_candidates(project_id,revision_id,fingerprint,assessment,payload) VALUES (?1,?2,?3,?4,?5)",
                    params![self.project_id,revision,finding["fingerprint"].as_str(),finding["verdict"].as_str(),serde_json::to_string(finding)?])?;
            }
            for review in run
                .verification
                .as_array()
                .context("invalid verification")?
            {
                tx.execute("INSERT INTO audit_reviews(project_id,revision_id,fingerprint,payload) VALUES (?1,?2,?3,?4)",
                    params![self.project_id,revision,review["fingerprint"].as_str(),serde_json::to_string(review)?])?;
            }
        }
        for artifact in artifact_descriptors(&run, &revision)? {
            tx.execute("INSERT OR IGNORE INTO audit_artifacts(project_id,revision_id,name,payload) VALUES (?1,?2,?3,?4)", params![self.project_id,revision,artifact.name,serde_json::to_string(&artifact)?])?;
        }
        tx.execute("INSERT INTO audit_latest(project_id,revision_id) VALUES (?1,?2) ON CONFLICT(project_id) DO UPDATE SET revision_id=excluded.revision_id",
            params![self.project_id,revision])?;
        // Preserve old readers, but update both compatibility keys in the same transaction.
        for key in [
            format!("audit-workflow.run.{}", run.metadata.run_id),
            KEY.into(),
        ] {
            tx.execute("INSERT INTO memory(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,encoded])?;
        }
        tx.commit()?;
        self.audit_status()
    }
    /// Metadata only, scoped to a retained revision in this repository.
    /// Legacy revisions are described from their retained payload without inventing
    /// original file bytes or observed execution. No artifact paths are opened.
    pub fn audit_artifacts(&self, revision: &str) -> Result<Vec<AuditArtifact>> {
        if revision.len() != 64 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("revision must be a 64-character hexadecimal identity");
        }
        let payload: String = self
            .db
            .connection()
            .query_row(
                "SELECT payload FROM audit_revisions WHERE project_id=?1 AND revision_id=?2",
                params![self.project_id, revision],
                |r| r.get(0),
            )
            .optional()?
            .context("audit revision not found in this repository")?;
        let mut stmt = self.db.connection().prepare("SELECT payload FROM audit_artifacts WHERE project_id=?1 AND revision_id=?2 ORDER BY name LIMIT 4")?;
        let stored = stmt
            .query_map(params![self.project_id, revision], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if stored.is_empty() {
            return artifact_descriptors(&serde_json::from_str(&payload)?, revision);
        }
        let actual: Vec<AuditArtifact> = stored
            .into_iter()
            .map(|s| serde_json::from_str(&s))
            .collect::<std::result::Result<_, _>>()?;
        let mut expected = artifact_descriptors(&serde_json::from_str(&payload)?, revision)?;
        expected.sort_by(|a, b| a.name.cmp(&b.name));
        if actual != expected {
            bail!("artifact descriptors disagree with retained audit revision");
        }
        Ok(actual)
    }
    /// Bounded revision metadata only; historical source freshness is not inferred.
    pub fn audit_history(&self, limit: usize) -> Result<AuditHistory> {
        if !(1..=100).contains(&limit) {
            bail!("audit history limit must be 1..100");
        }
        let mut statement = self.db.connection().prepare(
            "SELECT r.revision_id,r.run_id,r.source_snapshot,r.status,r.imported_at,
             EXISTS(SELECT 1 FROM audit_latest l WHERE l.project_id=r.project_id AND l.revision_id=r.revision_id)
             FROM audit_revisions r WHERE r.project_id=?1 ORDER BY r.rowid DESC LIMIT ?2")?;
        let mut revisions = statement
            .query_map(params![self.project_id, (limit + 1) as i64], |row| {
                Ok(AuditRevision {
                    revision_id: row.get(0)?,
                    run_id: row.get(1)?,
                    source_snapshot: row.get(2)?,
                    run_status: row.get(3)?,
                    imported_at: row.get(4)?,
                    is_latest: row.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let has_more = revisions.len() > limit;
        revisions.truncate(limit);
        Ok(AuditHistory {
            revisions,
            has_more,
            source_freshness_checked: false,
        })
    }
    pub fn audit_status(&self) -> Result<AuditStatus> {
        let mut status=AuditStatus {available:false,run_id:None,source_snapshot:None,stale:false,run_status:None,coverage_counts:BTreeMap::new(),finding_counts:BTreeMap::new(),partial_coverage:true,notes:vec!["Imported audit verdicts and reviewer identities are attestations, not independently authenticated proof. They do not alter deterministic findings or patch gates.".into()],report:None};
        let current: Option<String> = self.db.connection().query_row(
            "SELECT r.payload FROM audit_latest l JOIN audit_revisions r ON r.project_id=l.project_id AND r.revision_id=l.revision_id WHERE l.project_id=?1",
            [&self.project_id], |row| row.get(0)).optional()?;
        if let Some(value) = current.or(self.db.get_memory(KEY)?) {
            if value.len() > LIMIT {
                bail!("stored audit exceeds size limit");
            }
            let run: AuditRun = serde_json::from_str(&value)?;
            status.available = true;
            status.run_id = Some(run.metadata.run_id.clone());
            status.source_snapshot = Some(run.metadata.source_snapshot.clone());
            status.run_status = Some(run.metadata.run_status.clone());
            status.stale = self
                .audit_snapshot(&run.metadata.include_paths)
                .map(|(m, _)| m != run.metadata.source_manifest)
                .unwrap_or(true);
            for unit in run.coverage.as_array().context("invalid stored coverage")? {
                *status
                    .coverage_counts
                    .entry(unit["status"].as_str().unwrap_or("unknown").into())
                    .or_default() += 1;
            }
            for finding in run.findings.as_array().context("invalid stored findings")? {
                *status
                    .finding_counts
                    .entry(finding["verdict"].as_str().unwrap_or("unknown").into())
                    .or_default() += 1;
            }
            status.partial_coverage = status.stale
                || run.metadata.run_status != "complete"
                || status.coverage_counts.is_empty()
                || status
                    .coverage_counts
                    .iter()
                    .any(|(s, n)| *n > 0 && s != "covered");
            status.notes.extend(run.metadata.snapshot_notes.clone());
            if status.stale {
                status.notes.push("SOURCE CHANGED: imported evidence is stale; historical confirmations must be revalidated.".into());
            }
            status.report = Some(run);
        }
        Ok(status)
    }
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
        && ![
            "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
            "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
        ]
        .contains(&id)
}
fn validate_upstream(run: &AuditRun) -> Result<()> {
    // Compile only the pinned embedded validator modules. The run supplies JSON data, never code.
    let payload = json!({"coverage_code":asset("upstream/security-audit/validate-coverage-ledger.cjs"),"findings_code":asset("upstream/security-audit/validate-findings.cjs"),"schema":serde_json::from_str::<Value>(asset("upstream/security-audit/report-schema.json"))?,"coverage":run.coverage,"findings":run.findings});
    let wrapper = r#"const fs=require('node:fs');const data=JSON.parse(fs.readFileSync(0,'utf8'));function load(code){const module={exports:{}};new Function('module','exports','require',code.replace(/^#![^\n]*\n/,''))(module,module.exports,require);return module.exports;}const errors=[...load(data.coverage_code).validateDocument(data.coverage),...load(data.findings_code).validateDocument(data.findings,data.schema)];process.stdout.write(JSON.stringify({valid:errors.length===0,errors:errors.slice(0,20).map(e=>String(e).slice(0,500))}));"#;
    let node = std::env::var_os("SENTINEL_AUDIT_NODE").unwrap_or_else(|| "node".into());
    let mut command = Command::new(node);
    command
        .args(["--max-old-space-size=128", "--eval", wrapper])
        .current_dir(std::env::temp_dir())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in ["SystemRoot", "WINDIR", "PATH"] {
        if let Some(v) = std::env::var_os(key) {
            command.env(key, v);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .context("audit validation requires Node.js on PATH or SENTINEL_AUDIT_NODE")?;
    let mut stdin = child.stdin.take().unwrap();
    let bytes = serde_json::to_vec(&payload)?;
    let writer = std::thread::spawn(move || stdin.write_all(&bytes));
    let stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(16385).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let exit = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("audit validator exceeded 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    writer
        .join()
        .map_err(|_| anyhow::anyhow!("validator input worker failed"))??;
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("validator output worker failed"))??;
    if !exit.success() || output.len() > 16384 {
        bail!("audit validator failed or exceeded output bounds");
    }
    let result: Value = serde_json::from_slice(&output)?;
    if result["valid"] != true {
        bail!(
            "upstream audit schema validation failed: {}",
            result["errors"]
        );
    }
    Ok(())
}
pub fn render_report(status: &AuditStatus) -> Result<String> {
    let mut text = format!(
        "# Sentinel security audit\n\nSource stale: **{}**. Partial coverage: **{}**.\n\n",
        status.stale, status.partial_coverage
    );
    for note in &status.notes {
        text.push_str(&format!("- {}\n", markdown(note)));
    }
    let run = status.report.as_ref().context("no imported audit report")?;
    text.push_str(&format!(
        "\nRun: `{}`\n\n## Coverage\n\n| Surface | Status |\n|---|---|\n",
        run.metadata.run_id
    ));
    for unit in run.coverage.as_array().unwrap() {
        text.push_str(&format!(
            "| {} | {} |\n",
            markdown(unit["surface"].as_str().unwrap_or("")),
            markdown(unit["status"].as_str().unwrap_or(""))
        ));
    }
    text.push_str("\n## Findings\n\n");
    for finding in run.findings.as_array().unwrap() {
        text.push_str(&format!(
            "### {}\n\nRecorded verdict: **{}**\n\n{}\n\n",
            markdown(finding["title"].as_str().unwrap_or("")),
            finding["verdict"].as_str().unwrap_or(""),
            markdown(finding["description"].as_str().unwrap_or(""))
        ));
        let data = serde_json::to_string_pretty(finding)?
            .replace('`', "\\u0060")
            .replace('<', "\\u003c");
        text.push_str(&format!("```json\n{data}\n```\n\n"));
    }
    Ok(text)
}
fn markdown(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace('[', "\\[")
        .replace(']', "\\]")
}
pub fn export_report(status: &AuditStatus, output: &Path) -> Result<()> {
    write_new(output, render_report(status)?.as_bytes())
}
