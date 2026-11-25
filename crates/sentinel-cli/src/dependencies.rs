use anyhow::{bail, Result};
use serde_json::Value;
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 50_000;
const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

struct NpmInventory {
    schema_version: u32,
    ecosystem: &'static str,
    lockfile: &'static str,
    lockfile_version: Option<u64>,
    complete: bool,
    package_count: usize,
    packages: Vec<NpmPackage>,
    coverage_notes: Vec<String>,
}

struct NpmPackage {
    name: String,
    version: String,
    development: bool,
    optional: bool,
}

impl NpmInventory {
    fn incomplete(note: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            ecosystem: "npm",
            lockfile: "package-lock.json",
            lockfile_version: None,
            complete: false,
            package_count: 0,
            packages: vec![],
            coverage_notes: vec![note.into(),
                "inventory only: no advisory database was consulted and no package was assessed as vulnerable or safe".into()],
        }
    }

    fn to_json(&self) -> Value {
        serde_json::json!({
            "schema_version": self.schema_version,
            "ecosystem": self.ecosystem,
            "lockfile": self.lockfile,
            "lockfile_version": self.lockfile_version,
            "complete": self.complete,
            "package_count": self.package_count,
            "packages": self.packages.iter().map(|package| serde_json::json!({
                "name": package.name,
                "version": package.version,
                "development": package.development,
                "optional": package.optional,
            })).collect::<Vec<_>>(),
            "coverage_notes": self.coverage_notes,
        })
    }
}

pub fn inventory_npm(root: PathBuf) -> Result<i32> {
    let report = read_npm_inventory(&root)?;
    let status = if report.complete { 0 } else { 2 };
    println!("{}", serde_json::to_string_pretty(&report.to_json())?);
    Ok(status)
}

fn read_npm_inventory(root: &Path) -> Result<NpmInventory> {
    let root = root.canonicalize()?;
    if !root.is_dir() {
        bail!("dependency inventory requires a project directory");
    }
    let lock_path = root.join("package-lock.json");
    let canonical_lock = lock_path.canonicalize()?;
    if !canonical_lock.starts_with(&root) {
        bail!("package-lock.json resolves outside the project directory");
    }
    let mut file = File::open(canonical_lock)?;
    if file.metadata()?.len() > MAX_LOCK_BYTES {
        return Ok(NpmInventory::incomplete(format!(
            "package-lock.json exceeds the {MAX_LOCK_BYTES}-byte read limit"
        )));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_LOCK_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LOCK_BYTES {
        return Ok(NpmInventory::incomplete(format!(
            "package-lock.json exceeded the {MAX_LOCK_BYTES}-byte read limit while reading"
        )));
    }
    let lock: Value = serde_json::from_slice(&bytes)?;
    let lockfile_version = lock.get("lockfileVersion").and_then(Value::as_u64);
    if !matches!(lockfile_version, Some(2 | 3)) {
        let mut report = NpmInventory::incomplete(
            "only npm package-lock v2 and v3 are supported; no dependency versions were inferred",
        );
        report.lockfile_version = lockfile_version;
        return Ok(report);
    }
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return Ok(NpmInventory::incomplete(
            "supported lockfile version has no packages object",
        ));
    };
    let entries = packages
        .iter()
        .filter(|(path, _)| !path.is_empty() && package_key_name(path).is_some());
    let total = entries.clone().count();
    let mut report = NpmInventory {
        schema_version: 1,
        ecosystem: "npm",
        lockfile: "package-lock.json",
        lockfile_version,
        complete: total <= MAX_PACKAGES,
        package_count: 0,
        packages: Vec::with_capacity(total.min(MAX_PACKAGES)),
        coverage_notes: vec![
            "inventory only: no advisory database was consulted and no package was assessed as vulnerable or safe".into(),
        ],
    };
    if total > MAX_PACKAGES {
        report.coverage_notes.push(format!(
            "inventory limited to the first {MAX_PACKAGES} package records"
        ));
    }
    let mut omitted = 0usize;
    let mut output_budget = 0usize;
    let mut output_limited = false;
    for (key, entry) in entries.take(MAX_PACKAGES) {
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| valid_field(name, 512))
            .map(str::to_owned)
            .or_else(|| package_key_name(key));
        let version = entry
            .get("version")
            .and_then(Value::as_str)
            .filter(|version| valid_field(version, 256));
        let (Some(name), Some(version)) = (name, version) else {
            omitted += 1;
            continue;
        };
        let estimated_bytes = name
            .len()
            .saturating_add(version.len())
            .saturating_mul(6)
            .saturating_add(160);
        if output_budget.saturating_add(estimated_bytes) > MAX_OUTPUT_BYTES {
            output_limited = true;
            break;
        }
        output_budget += estimated_bytes;
        report.packages.push(NpmPackage {
            name,
            version: version.to_owned(),
            development: entry.get("dev").and_then(Value::as_bool).unwrap_or(false),
            optional: entry
                .get("optional")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    if omitted > 0 {
        report.complete = false;
        report.coverage_notes.push(format!(
            "{omitted} package record(s) lacked a valid name or version and were omitted"
        ));
    }
    if output_limited {
        report.complete = false;
        report.coverage_notes.push(format!(
            "inventory stopped at the {MAX_OUTPUT_BYTES}-byte estimated output budget"
        ));
    }
    report.package_count = report.packages.len();
    Ok(report)
}

fn package_key_name(key: &str) -> Option<String> {
    let tail = key
        .rsplit_once("/node_modules/")
        .map(|(_, tail)| tail)
        .or_else(|| key.strip_prefix("node_modules/"))?;
    let mut components = tail.split('/');
    let first = components.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", components.next()?)
    } else {
        first.to_owned()
    };
    valid_field(&name, 512).then_some(name)
}

fn valid_field(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Project(PathBuf);

    impl Project {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "sentinel-deps-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn write_lock(&self, content: &str) {
            std::fs::write(self.0.join("package-lock.json"), content).unwrap();
        }
    }

    impl Drop for Project {
        fn drop(&mut self) {
            if self.0.starts_with(std::env::temp_dir())
                && self
                    .0
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("sentinel-deps-")
            {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn npm_lock_inventory_is_deterministic_bounded_and_advisory_neutral() {
        let project = Project::new();
        project.write_lock(
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"},"node_modules/@scope/lib":{"version":"2.3.4","optional":true},"node_modules/app/node_modules/dep":{"version":"1.2.0","dev":true}}}"#,
        );
        let first = read_npm_inventory(&project.0).unwrap();
        let second = read_npm_inventory(&project.0).unwrap();
        assert!(first.complete);
        assert_eq!(first.package_count, 2);
        assert_eq!(first.to_json(), second.to_json());
        let serialized = second.to_json().to_string();
        assert!(serialized.contains("@scope/lib"));
        assert!(serialized.contains("2.3.4"));
        assert!(serialized.contains("inventory only"));
        assert!(!project.0.join(".sentinel.db").exists());
    }

    #[test]
    fn unsupported_lock_versions_and_invalid_package_rows_are_incomplete() {
        let project = Project::new();
        project.write_lock(r#"{"lockfileVersion":1,"dependencies":{}}"#);
        let unsupported = read_npm_inventory(&project.0).unwrap();
        assert!(!unsupported.complete);
        assert_eq!(unsupported.lockfile_version, Some(1));
        assert_eq!(unsupported.package_count, 0);

        project.write_lock(
            r#"{"lockfileVersion":2,"packages":{"node_modules/no-version":{"name":"no-version"}}}"#,
        );
        let incomplete = read_npm_inventory(&project.0).unwrap();
        assert!(!incomplete.complete);
        assert_eq!(incomplete.package_count, 0);
        assert!(incomplete
            .coverage_notes
            .iter()
            .any(|note| note.contains("omitted")));
    }

    #[test]
    fn npm_inventory_stops_at_input_and_serialized_output_budgets() {
        let project = Project::new();
        std::fs::write(
            project.0.join("package-lock.json"),
            vec![b' '; MAX_LOCK_BYTES as usize + 1],
        )
        .unwrap();
        let oversized = read_npm_inventory(&project.0).unwrap();
        assert!(!oversized.complete);
        assert!(oversized.coverage_notes[0].contains("read limit"));

        let mut packages = serde_json::Map::new();
        for index in 0..3_000 {
            packages.insert(
                format!("node_modules/package-{index:04}"),
                serde_json::json!({"version":"1.0.0", "name":"x".repeat(200)}),
            );
        }
        project
            .write_lock(&serde_json::json!({"lockfileVersion":3,"packages":packages}).to_string());
        let bounded = read_npm_inventory(&project.0).unwrap();
        assert!(!bounded.complete);
        assert!(bounded.package_count < 3_000);
        assert!(bounded
            .coverage_notes
            .iter()
            .any(|note| note.contains("estimated output budget")));
        assert!(
            serde_json::to_string_pretty(&bounded.to_json())
                .unwrap()
                .len()
                <= MAX_OUTPUT_BYTES
        );
    }
}
