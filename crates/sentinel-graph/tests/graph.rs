use sentinel_core::security::TraceLimits;
use sentinel_graph::Engine;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sentinel-graph-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, path: &str, source: &str) {
        std::fs::write(self.0.join(path), source).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.starts_with(std::env::temp_dir())
            && self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sentinel-graph-test-")
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
#[test]
fn repeated_import_targets_are_deduplicated_without_hiding_distinct_symbols() {
    let f = Fixture::new();
    let helper = "def helper(value):\n    return value\n";
    f.write("other.py", helper);
    let e = Engine::open(&f.0).unwrap();
    for (imports, call, service, resolved) in [
        (
            "from service import helper as run\nfrom service import helper as run",
            "run",
            helper.to_string(),
            true,
        ),
        (
            "import service as lib\nimport service as lib",
            "lib.helper",
            helper.to_string(),
            true,
        ),
        (
            "from service import helper as run\nfrom other import helper as run",
            "run",
            helper.to_string(),
            false,
        ),
        (
            "from service import helper as run\nfrom service import helper as run",
            "run",
            format!("{helper}{helper}"),
            false,
        ),
    ] {
        f.write("service.py", &service);
        f.write(
            "routes.py",
            &format!("{imports}\ndef handler(value):\n    return {call}(value)\n"),
        );
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let symbols = snapshot
            .files
            .iter()
            .flat_map(|file| &file.symbols)
            .collect::<Vec<_>>();
        let owner = symbols
            .iter()
            .find(|s| s.location.file == "routes.py" && s.qualified_name == "handler")
            .unwrap();
        let edge = snapshot
            .edges
            .iter()
            .find(|edge| edge.kind == "CALLS" && edge.from == owner.id && edge.name == call)
            .unwrap();
        assert_eq!(edge.resolved, resolved, "{imports}");
        if resolved {
            let target = symbols.iter().find(|s| s.id == edge.to).unwrap();
            assert_eq!(target.location.file, "service.py");
            assert_eq!(target.qualified_name, "helper");
        }
    }
}

#[test]
fn python_import_statements_respect_function_class_and_nearest_binding_scopes() {
    let f = Fixture::new();
    f.write("service.py", "def helper(value):\n    return value\n");
    f.write("other.py", "def helper(value):\n    return 0\n");
    let e = Engine::open(&f.0).unwrap();
    for (source, target, call_name, expected_file) in [
        ("def loader():\n    from service import helper\n    return helper(0)\ndef handler(value):\n    return helper(value)\n", "handler", "helper", None),
        ("class Worker:\n    from service import helper\n    def run(self, value):\n        return helper(value)\n", "Worker.run", "helper", None),
        ("from service import helper\ndef handler(value):\n    from other import helper\n    return helper(value)\n", "handler", "helper", Some("other.py")),
        ("def outer():\n    from service import helper\n    def handler(value):\n        return helper(value)\n    return 0\n", "outer.handler", "helper", Some("service.py")),
        ("def handler(value):\n    from service import helper\n    return helper(value)\n", "handler", "helper", Some("service.py")),
        ("def outer():\n    from service import helper\n    class Worker:\n        def run(self, value):\n            return helper(value)\n", "outer.Worker.run", "helper", Some("service.py")),
        ("def loader():\n    import service as lib\n    return 0\ndef handler(value):\n    return lib.helper(value)\n", "handler", "lib.helper", None),
        ("from service import helper\ndef handler(value):\n    from missing import helper\n    return helper(value)\n", "handler", "helper", None),
    ] {
        f.write("routes.py", source);
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let symbols = snapshot.files.iter().flat_map(|file| &file.symbols).collect::<Vec<_>>();
        let owner = symbols.iter().find(|s| s.location.file == "routes.py" && s.qualified_name == target).unwrap();
        let edge = snapshot.edges.iter().find(|edge| edge.kind == "CALLS" && edge.from == owner.id && edge.name == call_name).unwrap();
        assert_eq!(edge.resolved, expected_file.is_some(), "{source}");
        if let Some(expected_file) = expected_file {
            let callee = symbols.iter().find(|s| s.id == edge.to).unwrap();
            assert_eq!(callee.location.file, expected_file);
            assert_eq!(callee.qualified_name, "helper");
        }
        assert!(snapshot.files.iter().find(|file| file.path == "routes.py").unwrap().imports.iter().any(|import| !import.scope.is_empty()));
    }
    let legacy: sentinel_core::security::ImportRecord = serde_json::from_str(
        r#"{"module":"service","imported":"helper","local":"helper","line":1}"#,
    )
    .unwrap();
    assert!(legacy.scope.is_empty());
}

#[test]
fn python_import_collisions_only_consider_visible_lexical_definitions() {
    let f = Fixture::new();
    f.write("service.py", "def helper(value):\n    return value\n");
    let e = Engine::open(&f.0).unwrap();
    for (source, target, resolved) in [
        ("class Worker:\n    def helper(self, value):\n        return value\n    def run(self, value):\n        return helper(value)\n", "Worker.run", true),
        ("def unrelated():\n    def helper(value):\n        return value\n    return 0\ndef handler(value):\n    return helper(value)\n", "handler", true),
        ("def helper(value):\n    return value\ndef handler(value):\n    return helper(value)\n", "handler", false),
        ("def handler(value):\n    def helper(item):\n        return item\n    return helper(value)\n", "handler", false),
        ("def outer():\n    def helper(value):\n        return value\n    class Worker:\n        def run(self, value):\n            return helper(value)\n", "outer.Worker.run", false),
    ] {
        f.write("routes.py", &format!("from service import helper\n{source}"));
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let owner = snapshot.files.iter().flat_map(|file| &file.symbols).find(|symbol| symbol.location.file == "routes.py" && symbol.qualified_name == target).unwrap();
        let edge = snapshot.edges.iter().find(|edge| edge.kind == "CALLS" && edge.from == owner.id && edge.name == "helper").unwrap();
        assert_eq!(edge.resolved, resolved, "{target}: {source}");
        if resolved {
            let callee = snapshot.files.iter().flat_map(|file| &file.symbols).find(|symbol| symbol.id == edge.to).unwrap();
            assert_eq!(callee.location.file, "service.py");
            assert_eq!(callee.qualified_name, "helper");
        }
    }
}

#[test]
fn python_method_bare_calls_skip_class_namespaces_but_keep_function_closures() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    let class_method = "    def helper(self, value):\n        return value\n";
    for (source, expected) in [
        (format!("def helper(value):\n    return value\nclass Worker:\n{class_method}    def run(self, value):\n        return helper(value)\n"), Some("helper")),
        (format!("class Worker:\n{class_method}    def run(self, value):\n        return helper(value)\n"), None),
        (format!("def helper(value):\n    return value\nclass Worker:\n{class_method}    def run(self, value):\n        def helper(item):\n            return item\n        return helper(value)\n"), Some("Worker.run.helper")),
    ] {
        f.write("methods.py", &source);
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let owner = snapshot.files[0].symbols.iter().find(|symbol| symbol.qualified_name == "Worker.run").unwrap();
        let call = snapshot.edges.iter().find(|edge| edge.kind == "CALLS" && edge.from == owner.id && edge.name == "helper").unwrap();
        assert_eq!(call.resolved, expected.is_some());
        if let Some(expected) = expected {
            let symbol = snapshot.files[0].symbols.iter().find(|symbol| symbol.id == call.to).unwrap();
            assert_eq!(symbol.qualified_name, expected);
        }
    }
}

#[test]
fn direct_receiver_calls_do_not_resolve_deeper_attribute_chains_to_own_methods() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for (file, source, direct, chain) in [
        ("methods.py", "class Worker:\n    def helper(self, value):\n        return value\n    def run(self, value):\n        self.helper(value)\n        return self.worker.helper(value)\n", "self.helper", "self.worker.helper"),
        ("methods.js", "class Worker { helper(value) { return value; } run(value) { this.helper(value); return this.worker.helper(value); } }\n", "this.helper", "this.worker.helper"),
    ] {
        f.write(file, source);
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let owner = snapshot.files.iter().flat_map(|file| &file.symbols).find(|symbol| symbol.location.file == file && symbol.qualified_name == "Worker.run").unwrap();
        let edge = |name: &str| snapshot.edges.iter().find(|edge| edge.kind == "CALLS" && edge.from == owner.id && edge.name == name).unwrap();
        assert!(edge(direct).resolved, "{file}");
        assert!(!edge(chain).resolved);
        let target = snapshot.files.iter().flat_map(|file| &file.symbols).find(|symbol| symbol.id == edge(direct).to).unwrap();
        assert_eq!(target.qualified_name, "Worker.helper");
        assert_eq!(target.location.file, file);
    }
}

#[test]
fn python_namespace_imports_require_direct_module_members_without_guessing_attribute_chains() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    let helper = "def helper(value):\n    return value\n";
    let method = "class Tools:\n    def helper(self, value):\n        return value\n";
    for (import, call, service, resolved) in [
        (
            "import service as lib",
            "lib.helper",
            format!("{helper}{method}"),
            true,
        ),
        (
            "import service as lib",
            "lib.helper",
            method.to_string(),
            false,
        ),
        (
            "from service import helper as run",
            "run.unrelated",
            helper.to_string(),
            false,
        ),
        (
            "import service as lib",
            "lib.Tools.helper",
            method.to_string(),
            false,
        ),
        (
            "import service as lib",
            "lib",
            "def lib(value):\n    return value\n".to_string(),
            false,
        ),
    ] {
        f.write("service.py", &service);
        f.write(
            "routes.py",
            &format!("{import}\ndef handler(value):\n    return {call}(value)\n"),
        );
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let edge = snapshot
            .edges
            .iter()
            .find(|edge| edge.kind == "CALLS" && edge.file == "routes.py")
            .unwrap();
        assert_eq!(edge.resolved, resolved, "{call}");
        if resolved {
            let symbol = snapshot
                .files
                .iter()
                .flat_map(|file| &file.symbols)
                .find(|symbol| symbol.id == edge.to)
                .unwrap();
            assert_eq!(symbol.qualified_name, "helper");
        }
    }
}

#[test]
fn python_named_imports_exclude_methods_and_nested_functions_with_the_same_short_name() {
    let f = Fixture::new();
    f.write(
        "routes.py",
        "from service import helper as run\ndef handler(value):\n    return run(value)\n",
    );
    let nested = "class Tools:\n    def helper(self, value):\n        return value\ndef outer():\n    def helper(value):\n        return value\n    return 0\n";
    let e = Engine::open(&f.0).unwrap();
    for (source, resolved) in [
        (
            format!("def helper(value):\n    return value\n{nested}"),
            true,
        ),
        (nested.to_string(), false),
        (
            "def helper(value):\n    return value\ndef helper(value):\n    return 0\n".into(),
            false,
        ),
    ] {
        f.write("service.py", &source);
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let call = snapshot
            .edges
            .iter()
            .find(|edge| edge.kind == "CALLS" && edge.name == "run")
            .unwrap();
        assert_eq!(call.resolved, resolved);
        if resolved {
            let target = snapshot
                .files
                .iter()
                .flat_map(|file| &file.symbols)
                .find(|symbol| symbol.id == call.to)
                .unwrap();
            assert_eq!(target.qualified_name, "helper");
            assert_eq!(target.location.file, "service.py");
        }
    }
}

#[test]
fn context_includes_uncalled_import_dependencies_without_guessing_ambiguous_modules() {
    use sentinel_graph::context::ContextEvidence;
    let f = Fixture::new();
    f.write("helper.py", "def unused():\n    return 1\n");
    f.write(
        "routes.py",
        "from helper import unused\ndef route():\n    return 0\n",
    );
    let e = Engine::open(&f.0).unwrap();
    let context = e.get_security_context("route", 200).unwrap();
    assert!(context.complete);
    let dependency = context.selected_items.iter().find(|item| matches!(&item.evidence,
        ContextEvidence::Symbol(symbol) if symbol.location.file == "helper.py" && symbol.name == "unused")).unwrap();
    assert_eq!(dependency.relevance_score, 50);
    assert_eq!(dependency.reason_selected, ["imported module dependency"]);
    let bounded = e.get_security_context("route", 1).unwrap();
    assert!(bounded.complete);
    assert_eq!(bounded.selected_items.len(), 1);
    assert!(bounded.omitted_count > 0);
    assert_eq!(bounded.source_snapshot, context.source_snapshot);

    std::fs::create_dir(f.0.join("helper")).unwrap();
    f.write("helper/__init__.py", "def unused():\n    return 2\n");
    let ambiguous = e.get_security_context("route", 200).unwrap();
    assert!(ambiguous
        .selected_items
        .iter()
        .all(|item| !matches!(&item.evidence,
        ContextEvidence::Symbol(symbol) if symbol.location.file.starts_with("helper"))));
    assert!(ambiguous
        .selected_items
        .iter()
        .any(|item| matches!(&item.evidence,
        ContextEvidence::Relationship(edge) if edge.kind == "IMPORTS" && !edge.resolved)));
    std::fs::remove_file(f.0.join("helper/__init__.py")).unwrap();
    let restored = e.get_security_context("route", 200).unwrap();
    assert!(restored.selected_items.iter().any(|item| matches!(&item.evidence,
        ContextEvidence::Symbol(symbol) if symbol.location.file == "helper.py" && symbol.name == "unused")));
    assert_eq!(restored.source_snapshot, context.source_snapshot);
}

#[test]
fn import_target_reuse_reconciles_new_ambiguity_for_every_call() {
    let f = Fixture::new();
    f.write("helper.py", "def helper(value):\n    return value\n");
    let calls = (0..20)
        .map(|i| format!("    helper({i})\n"))
        .collect::<String>();
    f.write(
        "routes.py",
        &format!("from helper import helper\ndef route():\n{calls}"),
    );
    let e = Engine::open(&f.0).unwrap();
    for expected_resolved in [true, false, true] {
        e.index().unwrap();
        let snapshot = e.snapshot().unwrap();
        let calls = snapshot
            .edges
            .iter()
            .filter(|edge| edge.kind == "CALLS" && edge.name == "helper")
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 20);
        assert!(calls.iter().all(|edge| edge.resolved == expected_resolved));
        let import = snapshot
            .edges
            .iter()
            .find(|edge| edge.kind == "IMPORTS" && edge.name == "helper")
            .unwrap();
        assert_eq!(import.resolved, expected_resolved);
        if expected_resolved && !f.0.join("helper").exists() {
            std::fs::create_dir(f.0.join("helper")).unwrap();
            f.write(
                "helper/__init__.py",
                "def helper(value):\n    return value\n",
            );
        } else if !expected_resolved {
            std::fs::remove_file(f.0.join("helper/__init__.py")).unwrap();
        }
    }
}

#[test]
fn flow_edges_keep_annotation_endpoints_across_warm_refresh_and_sink_removal() {
    let f = Fixture::new();
    let source = (0..24)
        .map(|i| format!("def handler_{i}(request):\n    value = request.args['name']\n    cursor.execute('SELECT ' + value)\n\n"))
        .collect::<String>();
    f.write("routes.py", &source);
    let e = Engine::open(&f.0).unwrap();
    assert!(e.index().unwrap().complete);
    let first = e.snapshot().unwrap();
    let flows = first
        .edges
        .iter()
        .filter(|edge| edge.kind == "FLOWS_TO")
        .collect::<Vec<_>>();
    assert_eq!(flows.len(), 24);
    let annotations = first
        .files
        .iter()
        .flat_map(|file| &file.annotations)
        .collect::<Vec<_>>();
    for edge in &flows {
        let from = annotations
            .iter()
            .find(|annotation| annotation.id == edge.from)
            .unwrap();
        let to = annotations
            .iter()
            .find(|annotation| annotation.id == edge.to)
            .unwrap();
        assert_eq!(from.kind, "source");
        assert_eq!(to.kind, "sink");
        assert_eq!(from.owner, to.owner);
        assert_eq!(to.location.start_line, edge.line);
    }
    assert_eq!(e.index().unwrap().unchanged_files, 1);
    assert_eq!(
        serde_json::to_value(&first.edges).unwrap(),
        serde_json::to_value(&e.snapshot().unwrap().edges).unwrap()
    );
    let repaired = source.replacen(
        "cursor.execute('SELECT ' + value)",
        "cursor.execute('SELECT ?', (value,))",
        1,
    );
    f.write("routes.py", &repaired);
    assert_eq!(e.index().unwrap().changed_files, 1);
    let refreshed = e.snapshot().unwrap();
    assert_eq!(
        refreshed
            .edges
            .iter()
            .filter(|edge| edge.kind == "FLOWS_TO")
            .count(),
        23
    );
    assert!(refreshed
        .edges
        .iter()
        .filter(|edge| edge.kind == "FLOWS_TO")
        .all(|edge| refreshed.files[0]
            .annotations
            .iter()
            .any(|annotation| annotation.id == edge.to)));
}

#[test]
fn incremental_index_and_cross_file_parameter_and_return_flow() {
    let f = Fixture::new();
    f.write("routes.py","from service import create_user\ndef handler(request):\n    name = request.args['name']\n    return create_user(name)\n");
    f.write("service.py","from repository import insert_user\ndef create_user(name):\n    return insert_user(name)\n");
    f.write(
        "repository.py",
        "def insert_user(value):\n    cursor.execute('SELECT ' + value)\n",
    );
    let e = Engine::open(&f.0).unwrap();
    let first = e.index().unwrap();
    assert_eq!(first.changed_files, 3);
    assert_eq!(first.call_edges, 2);
    let context = e.get_security_context("create_user", 200).unwrap();
    assert!(context.selected_items.iter().any(|item| matches!(
        item.evidence,
        sentinel_graph::context::ContextEvidence::Finding(_)
    )));
    let snapshot = e.snapshot().unwrap();
    let trace = sentinel_taint::interprocedural::trace_project(
        &snapshot.files,
        &snapshot.edges,
        TraceLimits::default(),
    );
    assert_eq!(trace.paths.len(), 1, "{trace:?}");
    assert_eq!(trace.paths[0].sink_type, "sql-injection");
    assert!(trace.paths[0]
        .path
        .iter()
        .any(|s| s.symbol == "create_user"));
    let before = e.find_symbols("create_user", 20).unwrap().symbols[0]
        .id
        .clone();
    let second = e.index().unwrap();
    assert_eq!(second.changed_files, 0);
    assert_eq!(second.unchanged_files, 3);
    f.write("service.py","\nfrom repository import insert_user\ndef create_user(name):\n    return insert_user(name)\n");
    let third = e.index().unwrap();
    assert_eq!(third.changed_files, 1);
    assert_eq!(third.unchanged_files, 2);
    assert_eq!(
        before,
        e.find_symbols("create_user", 20).unwrap().symbols[0].id
    );
    std::fs::remove_file(f.0.join("repository.py")).unwrap();
    let removed = e.index().unwrap();
    assert_eq!(removed.removed_files, 1);
    assert!(e
        .relationships("create_user", false, 20)
        .unwrap()
        .edges
        .iter()
        .all(|edge| !edge.resolved));
}
#[test]
fn baseline_evidence_tracks_source_identity_without_confirming_candidates() {
    use sentinel_core::evidence::CandidateAssessment;
    let fixture = Fixture::new();
    fixture.write("hash.py", "import hashlib\nvalue = hashlib.md5(password)\n");
    let engine = Engine::open(&fixture.0).unwrap();
    engine.create_baseline().unwrap();
    let first = engine.verify_patch(None).unwrap();
    let snapshot = first.comparison.after_snapshot.as_ref().unwrap();
    assert_eq!(
        first.comparison.before_snapshot.as_ref().unwrap().id,
        snapshot.id
    );
    assert!(!first.comparison.after_evidence.is_empty());
    for evidence in &first.comparison.after_evidence {
        assert_eq!(evidence.snapshot_id, snapshot.id);
        assert_eq!(evidence.assessment, CandidateAssessment::NeedsValidation);
        assert_eq!(evidence.detector.rule_set_id.len(), 64);
        assert_eq!(evidence.location.file, "hash.py");
    }
    fixture.write(
        "hash.py",
        "import hashlib\nvalue = hashlib.sha256(password)\n",
    );
    let fixed = engine.verify_patch(None).unwrap();
    assert_ne!(
        fixed.comparison.after_snapshot.as_ref().unwrap().id,
        snapshot.id
    );
    assert!(fixed.comparison.after_evidence.is_empty());
    assert!(!fixed.comparison.before_evidence.is_empty());
}
#[test]
fn legacy_baseline_is_readable_but_cannot_produce_a_provenance_backed_pass() {
    let fixture = Fixture::new();
    fixture.write("main.py", "value = 1\n");
    let engine = Engine::open(&fixture.0).unwrap();
    engine.create_baseline().unwrap();
    let raw: String = engine
        .db
        .connection()
        .query_row(
            "SELECT payload FROM security_baselines WHERE project_id=?1",
            [&engine.project_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut old: serde_json::Value = serde_json::from_str(&raw).unwrap();
    old.as_object_mut().unwrap().remove("snapshot");
    old.as_object_mut().unwrap().remove("evidence");
    engine
        .db
        .connection()
        .execute(
            "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
            rusqlite::params![serde_json::to_string(&old).unwrap(), engine.project_id],
        )
        .unwrap();
    let result = engine.verify_patch(None).unwrap();
    assert_eq!(result.verdict, sentinel_graph::verification::Verdict::Warn);
    assert!(result.comparison.before_snapshot.is_none());
    assert!(result
        .reasons
        .iter()
        .any(|reason| reason.contains("legacy")));
}
#[test]
fn static_jobs_resume_across_restarts_and_enforce_budgets_and_cancellation() {
    use sentinel_graph::jobs::JobState;
    let fixture = Fixture::new();
    fixture.write("a.py", "value = 1\n");
    fixture.write("b.py", "value = 2\n");
    let engine = Engine::open(&fixture.0).unwrap();
    assert!(engine.create_scan_job(0, 60).is_err());
    let job = engine.create_scan_job(2, 60).unwrap();
    let first = engine.resume_scan_job(&job.id, 1, false).unwrap();
    assert_eq!(first.state, JobState::Pending);
    assert_eq!(first.results.len(), 1);
    drop(engine);
    let engine = Engine::open(&fixture.0).unwrap();
    let completed = engine.resume_scan_job(&job.id, 1, false).unwrap();
    assert_eq!(completed.state, JobState::Completed);
    assert_eq!(completed.attempts_reserved, 2);
    assert_eq!(
        engine
            .resume_scan_job(&job.id, 1, false)
            .unwrap()
            .attempts_reserved,
        2
    );
    let limited = engine.create_scan_job(1, 60).unwrap();
    let exhausted = engine.resume_scan_job(&limited.id, 100, false).unwrap();
    assert_eq!(exhausted.state, JobState::BudgetExhausted);
    assert_eq!(exhausted.results.len(), 1);
    let cancelled = engine.create_scan_job(2, 60).unwrap();
    engine.cancel_scan_job(&cancelled.id).unwrap();
    let cancelled = engine.resume_scan_job(&cancelled.id, 1, false).unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
    assert_eq!(cancelled.attempts_reserved, 0);
    assert!(engine.resume_scan_job(&job.id, 0, false).is_err());
}

#[test]
fn static_jobs_reject_changed_sources_and_account_for_interrupted_attempts() {
    use sentinel_graph::jobs::JobState;
    let fixture = Fixture::new();
    fixture.write("a.py", "value = 1\n");
    let engine = Engine::open(&fixture.0).unwrap();
    let stale = engine.create_scan_job(2, 60).unwrap();
    fixture.write("a.py", "value = 2\n");
    assert_eq!(
        engine.resume_scan_job(&stale.id, 1, false).unwrap().state,
        JobState::Stale
    );
    let mut interrupted = engine.create_scan_job(2, 60).unwrap();
    interrupted.state = JobState::Running;
    interrupted.attempts_reserved = 1;
    interrupted.active_file = Some("a.py".into());
    engine
        .db
        .connection()
        .execute(
            "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
            rusqlite::params![serde_json::to_string(&interrupted).unwrap(), interrupted.id],
        )
        .unwrap();
    assert!(engine.resume_scan_job(&interrupted.id, 1, false).is_err());
    let recovered = engine.resume_scan_job(&interrupted.id, 1, true).unwrap();
    assert_eq!(recovered.state, JobState::BudgetExhausted);
    assert_eq!(recovered.attempts_reserved, 1);
    assert_eq!(recovered.elapsed_ms, recovered.max_elapsed_ms);
    assert!(recovered.results.is_empty());
}
#[test]
fn analysis_upgrades_reparse_unchanged_files_and_invalidate_old_detector_passes() {
    let fixture = Fixture::new();
    fixture.write("main.py", "value = 1\n");
    let engine = Engine::open(&fixture.0).unwrap();
    engine.index().unwrap();
    let raw: String = engine
        .db
        .connection()
        .query_row(
            "SELECT payload FROM files WHERE project_id=?1 AND path='main.py'",
            [&engine.project_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut legacy: serde_json::Value = serde_json::from_str(&raw).unwrap();
    legacy.as_object_mut().unwrap().remove("semantics_revision");
    engine
        .db
        .connection()
        .execute(
            "UPDATE files SET payload=?1 WHERE project_id=?2 AND path='main.py'",
            rusqlite::params![serde_json::to_string(&legacy).unwrap(), engine.project_id],
        )
        .unwrap();
    assert_eq!(engine.index().unwrap().changed_files, 1);
    assert_eq!(
        engine.snapshot().unwrap().files[0].semantics_revision,
        sentinel_core::security::ANALYSIS_SEMANTICS_REVISION
    );
    assert_eq!(engine.index().unwrap().unchanged_files, 1);
    engine.create_baseline().unwrap();
    let raw: String = engine
        .db
        .connection()
        .query_row(
            "SELECT payload FROM security_baselines WHERE project_id=?1",
            [&engine.project_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut old: serde_json::Value = serde_json::from_str(&raw).unwrap();
    old["detector"]["semantics_revision"] = serde_json::json!(0);
    engine
        .db
        .connection()
        .execute(
            "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
            rusqlite::params![serde_json::to_string(&old).unwrap(), engine.project_id],
        )
        .unwrap();
    let result = engine.verify_patch(None).unwrap();
    assert_eq!(result.verdict, sentinel_graph::verification::Verdict::Warn);
    assert!(result
        .reasons
        .iter()
        .any(|reason| reason.contains("Detector provenance")));
}
#[test]
fn category_specific_sanitizer_prevents_xss_without_hiding_raw_flow() {
    let f = Fixture::new();
    f.write("routes.ts","import { render } from './renderer';\nfunction handle(req) { return render(escapeHtml(req.query.name)); }\n");
    f.write(
        "renderer.ts",
        "function render(value) { res.send(value); }\n",
    );
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let s = e.snapshot().unwrap();
    let clean =
        sentinel_taint::interprocedural::trace_project(&s.files, &s.edges, TraceLimits::default());
    assert!(clean.paths.is_empty(), "{clean:?}");
    f.write("routes.ts","import { render } from './renderer';\nfunction handle(req) { return render(escapeHtml(req.query.name) + req.query.raw); }\n");
    e.index().unwrap();
    let s = e.snapshot().unwrap();
    let raw =
        sentinel_taint::interprocedural::trace_project(&s.files, &s.edges, TraceLimits::default());
    assert_eq!(raw.paths.len(), 1);
    assert_eq!(raw.paths[0].sink_type, "xss");
}
#[test]
fn parameterized_sql_and_guards_are_distinguished_from_unsafe_query_text() {
    let f = Fixture::new();
    f.write("routes.py","@login_required\ndef handler(request):\n    authorize(request)\n    name = request.args['name']\n    cursor.execute('SELECT ?', [name])\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let s = e.snapshot().unwrap();
    assert!(
        s.files[0]
            .annotations
            .iter()
            .filter(|a| a.kind == "security_guard")
            .count()
            >= 2
    );
    let trace =
        sentinel_taint::interprocedural::trace_project(&s.files, &s.edges, TraceLimits::default());
    assert!(trace.paths.is_empty());
}
#[test]
fn invalid_syntax_invalidates_stale_graph_and_limits_are_explicit() {
    let f = Fixture::new();
    f.write(
        "main.py",
        "def route(request):\n    return eval(request.args['x'])\n",
    );
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let s = e.snapshot().unwrap();
    let trace = sentinel_taint::interprocedural::trace_project(
        &s.files,
        &s.edges,
        TraceLimits {
            max_nodes_visited: 1,
            ..TraceLimits::default()
        },
    );
    assert!(!trace.complete);
    f.write("main.py", "def route(:\n");
    let broken = e.index().unwrap();
    assert!(!broken.complete);
    assert!(e.snapshot().unwrap().files.is_empty());
}
#[test]
fn baseline_debt_fix_and_regression_verdicts() {
    use sentinel_graph::verification::Verdict;
    let f = Fixture::new();
    let unsafe_code="def handler(request):\n    value = request.args['q']\n    cursor.execute('SELECT ' + value)\n";
    f.write("routes.py", unsafe_code);
    let engine = Engine::open(&f.0).unwrap();
    let baseline = engine.create_baseline().unwrap();
    assert!(baseline.findings > 0);
    let unchanged = engine.verify_patch(None).unwrap();
    assert_eq!(unchanged.verdict, Verdict::Pass);
    assert!(unchanged.comparison.new_findings.is_empty());
    f.write("routes.py","def handler(request):\n    value = request.args['q']\n    cursor.execute('SELECT ?', (value,))\n");
    let fixed = engine.verify_patch(None).unwrap();
    assert_eq!(fixed.verdict, Verdict::Pass);
    assert!(!fixed.comparison.resolved_findings.is_empty());
    f.write("routes.py", unsafe_code);
    let regression = engine.verify_patch(None).unwrap();
    assert_eq!(regression.verdict, Verdict::Fail);
    assert!(!regression.regressed_findings.is_empty());
    f.write("routes.py", "def broken(:\n");
    let partial = engine.verify_patch(None).unwrap();
    assert_eq!(partial.verdict, Verdict::Warn);
    assert!(!partial.comparison.complete);
    assert!(engine.create_baseline().is_err());
}
#[test]
fn source_returns_command_path_branches_and_shadowing() {
    let f = Fixture::new();
    f.write(
        "source.py",
        "def read_input(request):\n    return request.args['value']\n",
    );
    f.write("commands.py","from source import read_input as read\ndef route(request):\n    command = read(request)\n    subprocess.run(command, shell=True)\n    open(command)\n");
    let engine = Engine::open(&f.0).unwrap();
    let trace = engine
        .trace("commands.py", None, TraceLimits::default())
        .unwrap();
    assert!(trace
        .paths
        .iter()
        .any(|p| p.sink_type == "command-injection"));
    assert!(trace.paths.iter().any(|p| p.sink_type == "path-traversal"));
    let ctx = engine.get_security_context("commands.py:3", 3).unwrap();
    assert_eq!(ctx.selected_items.len(), 3);
    assert!(ctx.omitted_count > 0);
    assert!(ctx
        .selected_items
        .iter()
        .all(|i| !i.reason_selected.is_empty()));
    f.write("shadow.ts","function handler(req: any, res: any) { let value = req.query.q; { let value = 'safe'; res.send(value); } res.send(value); }\n");
    let trace = engine
        .trace("shadow.ts", Some("xss"), TraceLimits::default())
        .unwrap();
    assert_eq!(trace.paths.len(), 1);
}
#[test]
fn explicit_extension_import_is_resolved_and_path_budget_never_overshoots() {
    let f = Fixture::new();
    f.write(
        "output.ts",
        "export function render(value: string, res: any) { res.send(value); }\n",
    );
    f.write("route.ts","import { render } from './output.ts';\nfunction handler(req: any, res: any) { render(req.query.q, res); res.send(req.query.x + req.query.y); }\n");
    let engine = Engine::open(&f.0).unwrap();
    assert_eq!(engine.index().unwrap().call_edges, 1);
    let result = engine
        .trace(
            "route.ts",
            None,
            TraceLimits {
                max_paths: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(result.paths.len() <= 1);
    assert!(!result.complete);
}
#[test]
fn unsupported_control_flow_and_recursion_report_incomplete_coverage() {
    let f = Fixture::new();
    f.write("recursive.py","def recur(value):\n    return recur(value)\ndef route(request):\n    recur(request.args['q'])\n");
    let engine = Engine::open(&f.0).unwrap();
    let trace = engine
        .trace(
            "route",
            None,
            TraceLimits {
                max_call_depth: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(!trace.complete);
    f.write("recursive.py","def route(request):\n    try:\n        value = request.args['q']\n        cursor.execute(value)\n    except Exception:\n        pass\n");
    let stats = engine.index().unwrap();
    assert!(!stats.complete);
    assert!(stats
        .coverage_notes
        .iter()
        .any(|n| n.contains("try_statement")));
}
#[test]
fn html_assignment_is_a_sink_and_function_method_kinds_are_precise() {
    let f = Fixture::new();
    f.write(
        "html.ts",
        "function route(req: any, element: any) { element.innerHTML = req.query.q; }\n",
    );
    f.write("methods.py","class Controller:\n    def handle(self):\n        def nested():\n            return 1\n        return nested()\n");
    let engine = Engine::open(&f.0).unwrap();
    let trace = engine
        .trace("html.ts", Some("xss"), TraceLimits::default())
        .unwrap();
    assert_eq!(trace.paths.len(), 1);
    let symbols = engine.find_symbols("methods.py", 20).unwrap().symbols;
    assert!(symbols
        .iter()
        .any(|s| s.qualified_name == "Controller.handle" && s.kind == "method"));
    assert!(symbols
        .iter()
        .any(|s| s.qualified_name == "Controller.handle.nested" && s.kind == "function"));
}
#[test]
#[ignore = "manual reproducible latency measurement"]
fn security_service_latency_measurement() {
    use std::time::Instant;
    let f = Fixture::new();
    for i in 0..120 {
        f.write(&format!("module_{i}.py"),"def one(x):\n    return x\ndef two(x):\n    return x\ndef three(x):\n    return x\ndef four(x):\n    return x\n");
    }
    f.write("routes.py","from service import create_user\ndef route(request):\n    return create_user(request.args['name'])\n");
    f.write(
        "service.py",
        "def create_user(value):\n    cursor.execute('SELECT ' + value)\n",
    );
    let engine = Engine::open(&f.0).unwrap();
    let start = Instant::now();
    let initial = engine.index().unwrap();
    let first_us = start.elapsed().as_micros();
    let start = Instant::now();
    let cached = engine.index().unwrap();
    let cached_us = start.elapsed().as_micros();
    f.write("module_0.py", "def one(x):\n    return x\n");
    let start = Instant::now();
    let changed = engine.index().unwrap();
    let changed_us = start.elapsed().as_micros();
    let start = Instant::now();
    let scan = engine.scan_file("routes.py").unwrap();
    let scan_us = start.elapsed().as_micros();
    let start = Instant::now();
    let context = engine.get_security_context("create_user", 40).unwrap();
    let context_us = start.elapsed().as_micros();
    let start = Instant::now();
    let trace = engine
        .trace("create_user", None, TraceLimits::default())
        .unwrap();
    let trace_us = start.elapsed().as_micros();
    assert!(initial.complete);
    assert_eq!(cached.changed_files, 0);
    assert_eq!(changed.changed_files, 1);
    assert!(!scan.report.findings.is_empty());
    assert!(!context.selected_items.is_empty());
    assert_eq!(trace.paths.len(), 1);
    println!(
        "{}",
        serde_json::json!({"profile":"debug","files":initial.files_indexed,"symbols":initial.symbols,"initial_index_us":first_us,"unchanged_index_us":cached_us,"single_file_update_us":changed_us,"scan_file_us":scan_us,"context_query_us":context_us,"trace_us":trace_us})
    );
}
#[test]
fn git_patch_comparison_handles_line_moves_deletions_untracked_and_invalid_source() {
    use sentinel_graph::verification::Verdict;
    let f = Fixture::new();
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(&f.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "Fixture"]);
    let source = "def route(request):\n    cursor.execute('SELECT ' + request.args['q'])\n";
    f.write("routes.py", source);
    git(&["add", "routes.py"]);
    git(&["commit", "-qm", "baseline"]);
    let engine = Engine::open(&f.0).unwrap();
    f.write("routes.py", &format!("\n\n{source}"));
    let moved = engine.verify_patch(Some("HEAD")).unwrap();
    assert_eq!(moved.verdict, Verdict::Pass, "{moved:#?}");
    assert!(moved.comparison.new_findings.is_empty());
    assert!(!moved.comparison.unchanged_findings.is_empty());
    std::fs::remove_file(f.0.join("routes.py")).unwrap();
    let deleted = engine.verify_patch(Some("HEAD")).unwrap();
    assert_eq!(deleted.verdict, Verdict::Pass, "{deleted:#?}");
    assert!(!deleted.comparison.resolved_findings.is_empty());
    f.write("new.py", source);
    let introduced = engine.verify_patch(Some("HEAD")).unwrap();
    assert_eq!(introduced.verdict, Verdict::Fail);
    f.write("new.py", "def broken(:\n");
    let invalid = engine.verify_patch(Some("HEAD")).unwrap();
    assert_eq!(invalid.verdict, Verdict::Warn);
    assert!(!invalid.comparison.complete);
    assert!(invalid.comparison.resolved_findings.is_empty());
    assert!(engine.verify_patch(Some("--not-a-ref")).is_err());
}
#[test]
fn baseline_does_not_resolve_existing_debt_when_source_is_newly_ignored() {
    use sentinel_graph::verification::Verdict;
    let f = Fixture::new();
    let output = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&f.0)
        .output()
        .unwrap();
    assert!(output.status.success());
    f.write(
        "routes.py",
        "def route(request):\n    cursor.execute('SELECT ' + request.args['q'])\n",
    );
    let engine = Engine::open(&f.0).unwrap();
    engine.create_baseline().unwrap();
    f.write(".gitignore", "routes.py\n");
    let result = engine.verify_patch(None).unwrap();
    assert_eq!(result.verdict, Verdict::Warn);
    assert!(result.comparison.resolved_findings.is_empty());
}

#[test]
fn request_headers_and_cookies_reach_sql_only_when_used_as_query_text() {
    for (file, source, safe) in [
        (
            "routes.js",
            "function route(req) { return db.query('SELECT ' + req.headers['x-query']); }",
            "function route(req) { return db.query('SELECT ?', [req.headers['x-query']]); }",
        ),
        (
            "routes.js",
            "function route(req) { return db.query('SELECT ' + req.cookies.query); }",
            "function route(req) { return db.query('SELECT ?', [req.cookies.query]); }",
        ),
        (
            "routes.py",
            "def route(request):\n    cursor.execute('SELECT ' + request.headers['x-query'])\n",
            "def route(request):\n    cursor.execute('SELECT ?', (request.headers['x-query'],))\n",
        ),
        (
            "routes.py",
            "def route(request):\n    cursor.execute('SELECT ' + request.cookies['query'])\n",
            "def route(request):\n    cursor.execute('SELECT ?', (request.cookies['query'],))\n",
        ),
    ] {
        let f = Fixture::new();
        f.write(file, source);
        let engine = Engine::open(&f.0).unwrap();
        assert_eq!(
            engine
                .trace(file, Some("sql-injection"), TraceLimits::default())
                .unwrap()
                .paths
                .len(),
            1
        );
        f.write(file, safe);
        assert!(engine
            .trace(file, Some("sql-injection"), TraceLimits::default())
            .unwrap()
            .paths
            .is_empty());
    }
}

#[test]
fn lexical_resolution_namespace_aliases_and_async_returns_are_preserved() {
    let f = Fixture::new();
    f.write(
        "service.js",
        "export async function read(value) { return value; }\n",
    );
    f.write("routes.js", "import * as service from './service.js';\nasync function route(req) { const value = await service.read(req.query.q); return db.query('SELECT ' + value); }\n");
    f.write("nested.py", "def route(request):\n    def read(value):\n        return value\n    cursor.execute('SELECT ' + read(request.args['q']))\ndef other():\n    def read(value):\n        return 'fixed'\n    return read('safe')\n");
    let e = Engine::open(&f.0).unwrap();
    assert_eq!(
        e.trace("routes.js", Some("sql-injection"), TraceLimits::default())
            .unwrap()
            .paths
            .len(),
        1
    );
    assert_eq!(
        e.trace("nested.py", Some("sql-injection"), TraceLimits::default())
            .unwrap()
            .paths
            .len(),
        1
    );
}
#[test]
fn fastapi_string_route_parameters_require_constructor_and_are_not_sql_sanitizers() {
    let f = Fixture::new();
    f.write("routes.py", "from fastapi import FastAPI as Web\napp = Web()\n@app.get('/search')\nasync def route(q: str):\n    cursor.execute('SELECT ' + q)\n");
    let e = Engine::open(&f.0).unwrap();
    assert_eq!(
        e.trace("routes.py", Some("sql-injection"), TraceLimits::default())
            .unwrap()
            .paths
            .len(),
        1
    );
    f.write("routes.py", "from fastapi import FastAPI as Web\napp = Web()\n@app.get('/search')\nasync def route(q: str):\n    cursor.execute('SELECT ?', (q,))\n");
    assert!(e
        .trace("routes.py", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
    f.write(
        "routes.py",
        "@app.get('/search')\ndef route(q: str):\n    cursor.execute('SELECT ' + q)\n",
    );
    assert!(e
        .trace("routes.py", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
}

#[test]
fn literal_object_fields_distinguish_safe_values_and_invalidate_on_reassignment() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for (source,count) in [
        ("function route(req) { const box = { raw:req.query.q, safe:'fixed' }; db.query('SELECT ' + box.safe); }",0),
        ("function route(req) { const box = { raw:req.query.q, safe:'fixed' }; db.query('SELECT ' + box.raw); }",1),
        ("function route(req) { let box = { safe:'fixed' }; box=req.query; db.query('SELECT ' + box.safe); }",1),
        ("function route(req) { let box = { safe:'fixed' }; if (req.query.flag) { box=req.query; } db.query('SELECT ' + box.safe); }",1),
        ("function route(req) { const box = { safe:'fixed', [req.query.key]:req.query.q }; db.query('SELECT ' + box.safe); }",1),
    ] {
        f.write("routes.js",source);
        assert_eq!(e.trace("routes.js",Some("sql-injection"),TraceLimits::default()).unwrap().paths.is_empty(),count == 0, "{source}");
    }
}

#[test]
fn ambiguous_import_modules_and_default_exports_are_not_guessed() {
    let f = Fixture::new();
    std::fs::create_dir(f.0.join("src")).unwrap();
    f.write("service.js", "export function send(x) { return x; }\n");
    f.write(
        "src/service.js",
        "export function different(x) { return x; }\n",
    );
    f.write("routes.js", "import { send as run } from 'service';\nfunction route(req) { return run(req.query.q); }\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let snapshot = e.snapshot().unwrap();
    assert!(snapshot
        .edges
        .iter()
        .any(|edge| edge.kind == "IMPORTS" && !edge.resolved));
    assert!(snapshot
        .edges
        .iter()
        .any(|edge| edge.name == "run" && !edge.resolved));
    f.write(
        "routes.js",
        "import send from './service.js';\nfunction route(req) { return send(req.query.q); }\n",
    );
    e.index().unwrap();
    assert!(e
        .snapshot()
        .unwrap()
        .edges
        .iter()
        .any(|edge| edge.name == "send" && !edge.resolved));
}

#[test]
fn flask_path_string_parameters_are_sources_only_for_recognized_routes() {
    let f = Fixture::new();
    f.write("routes.py", "from flask import Flask\napp = Flask(__name__)\n@app.route('/files/<path:filename>')\ndef route(filename):\n    return open(filename)\n");
    let e = Engine::open(&f.0).unwrap();
    assert!(!e
        .trace("routes.py", Some("path-traversal"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
    f.write("routes.py", "from flask import Flask\napp = Flask(__name__)\n@app.route('/files/<path:filename>')\ndef route(filename):\n    return open('fixed.txt')\n");
    assert!(e
        .trace("routes.py", Some("path-traversal"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
}

#[test]
fn trace_backend_provenance_is_source_bound_and_legacy_provenance_is_unknown() {
    let f = Fixture::new();
    f.write(
        "routes.py",
        "def route(request):\n    return open(request.args['path'])\n",
    );
    let e = Engine::open(&f.0).unwrap();
    let before = e.trace("routes.py", None, TraceLimits::default()).unwrap();
    assert_eq!(before.backend.as_ref().unwrap().name, "sentinel-native");
    assert_eq!(
        before.backend.as_ref().unwrap().semantics_revision,
        sentinel_core::security::ANALYSIS_SEMANTICS_REVISION
    );
    f.write(
        "routes.py",
        "def route(request):\n    return open('fixed.txt')\n",
    );
    let after = e.trace("routes.py", None, TraceLimits::default()).unwrap();
    assert_ne!(before.source_snapshot, after.source_snapshot);
    let legacy: sentinel_core::security::TraceReport=serde_json::from_value(serde_json::json!({"paths":[],"nodes_visited":0,"duration_ms":0,"complete":true,"coverage_notes":[]})).unwrap();
    assert!(legacy.backend.is_none() && legacy.source_snapshot.is_none());
}

#[test]
fn unsupported_fastapi_parameters_are_explicitly_incomplete() {
    let f = Fixture::new();
    f.write("routes.py", "from fastapi import FastAPI, Depends\napp = FastAPI()\n@app.get('/search')\ndef route(q: str, db = Depends(connect)):\n    return db.execute(q)\n");
    let e = Engine::open(&f.0).unwrap();
    let report = e.trace("routes.py", None, TraceLimits::default()).unwrap();
    assert!(!report.complete);
    assert!(report
        .coverage_notes
        .iter()
        .any(|note| note.contains("Framework route/parameter")));
}

#[test]
fn flask_http_shortcuts_and_unsupported_routes_report_coverage() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for method in ["get", "post", "put", "patch", "delete"] {
        f.write("routes.py", &format!("from flask import Flask\napp = Flask(__name__)\n@app.{method}('/files/<path:filename>')\ndef route(filename):\n    return open(filename)\n"));
        let report = e
            .trace("routes.py", Some("path-traversal"), TraceLimits::default())
            .unwrap();
        assert!(report.complete, "{method}: {:?}", report.coverage_notes);
        assert!(!report.paths.is_empty(), "{method}");
    }
    for path in ["configured_path", "'/files/<custom:filename>'"] {
        f.write("routes.py", &format!("from flask import Flask\napp = Flask(__name__)\n@app.route({path})\ndef route(filename):\n    return open(filename)\n"));
        let report = e.trace("routes.py", None, TraceLimits::default()).unwrap();
        assert!(!report.complete, "{path}");
        assert!(report
            .coverage_notes
            .iter()
            .any(|note| note.contains("Framework route/parameter")));
    }
}

#[test]
fn flask_keyword_rules_are_sources_and_interpolated_rules_are_incomplete() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for decorator in [
        "app.route(rule='/files/<path:filename>')",
        "app.get(rule='/files/<path:filename>')",
    ] {
        f.write("routes.py", &format!("from flask import Flask\napp = Flask(__name__)\n@{decorator}\ndef route(filename):\n    return open(filename)\n"));
        let report = e
            .trace("routes.py", Some("path-traversal"), TraceLimits::default())
            .unwrap();
        assert!(report.complete, "{:?}", report.coverage_notes);
        assert!(!report.paths.is_empty());
    }
    for rule in [
        "f'/files/{converter}'",
        "rule=f'/files/{converter}'",
        "rule=configured_path",
    ] {
        f.write("routes.py", &format!("from flask import Flask\napp = Flask(__name__)\n@app.route({rule})\ndef route(filename):\n    return open(filename)\n"));
        let report = e.trace("routes.py", None, TraceLimits::default()).unwrap();
        assert!(!report.complete, "{rule}");
    }
}

#[test]
fn framework_namespace_constructors_and_rebindings_are_distinguished() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for (import, constructor, decorator, params) in [
        (
            "import fastapi as api",
            "api.FastAPI",
            "app.get('/search')",
            "q: str",
        ),
        (
            "import flask as web",
            "web.Flask",
            "app.route('/search/<q>')",
            "q",
        ),
        (
            "from fastapi import FastAPI",
            "FastAPI",
            "app.get('/search')",
            "q: str",
        ),
    ] {
        for rebound in [false, true] {
            let assignment = if rebound {
                format!("{constructor} = other\n")
            } else {
                String::new()
            };
            f.write("routes.py", &format!("{import}\n{assignment}app = {constructor}('test')\n@{decorator}\ndef route({params}):\n    return db.execute(q)\n"));
            let report = e
                .trace("routes.py", Some("sql-injection"), TraceLimits::default())
                .unwrap();
            assert_eq!(
                report.paths.is_empty(),
                rebound,
                "{constructor}: rebound={rebound}"
            );
        }
    }
}

#[test]
fn framework_imports_must_precede_routes_in_module_scope() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for prefix in [
        "def unrelated():\n    from fastapi import FastAPI\n",
        "def unrelated():\n    import fastapi as api\n",
    ] {
        let constructor = if prefix.contains("as api") {
            "api.FastAPI"
        } else {
            "FastAPI"
        };
        f.write("routes.py", &format!("{prefix}app = {constructor}()\n@app.get('/search')\ndef route(q: str):\n    return db.execute(q)\n"));
        assert!(e
            .trace("routes.py", Some("sql-injection"), TraceLimits::default())
            .unwrap()
            .paths
            .is_empty());
    }
    f.write("routes.py", "app = FastAPI()\n@app.get('/search')\ndef route(q: str):\n    return db.execute(q)\nfrom fastapi import FastAPI\n");
    assert!(e
        .trace("routes.py", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
    f.write("routes.py", "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/search')\ndef route(q: str):\n    return db.execute(q)\n");
    assert!(!e
        .trace("routes.py", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
}

#[test]
fn framework_import_and_assignment_order_controls_constructor_evidence() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for (prefix, has_source) in [
        ("app = FastAPI()\nfrom fastapi import FastAPI\n", false),
        ("from fastapi import FastAPI\nFastAPI = other\nfrom fastapi import FastAPI\napp = FastAPI()\n", true),
        ("from fastapi import FastAPI\nfrom unrelated import FastAPI\napp = FastAPI()\n", false),
        ("import fastapi as api\nimport unrelated as api\napp = api.FastAPI()\n", false),
        ("from fastapi import FastAPI\napp = FastAPI()\nfrom unrelated import app\n", false),
    ] {
        f.write("routes.py", &format!("{prefix}@app.get('/search')\ndef route(q: str):\n    return db.execute(q)\n"));
        let report = e.trace("routes.py", Some("sql-injection"), TraceLimits::default()).unwrap();
        assert_eq!(!report.paths.is_empty(), has_source, "{prefix}");
    }
}

#[test]
fn registered_js_route_receivers_support_renamed_requests_and_safe_parameters() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for framework in ["express", "fastify"] {
        for (handler, registration) in [
            (
                "",
                "app.get('/search', async (incoming, reply) => db.execute(incoming.query.q));",
            ),
            (
                "function route(incoming, reply) { return db.execute(incoming.query.q); }",
                "app.get('/search', route);",
            ),
            (
                "const route = (incoming, reply) => db.execute(incoming.query.q);",
                "app.get('/search', route);",
            ),
        ] {
            let source = format!("import factory from '{framework}';\nconst app = factory();\n{handler}\n{registration}\n");
            f.write("routes.js", &source);
            let report = e
                .trace("routes.js", Some("sql-injection"), TraceLimits::default())
                .unwrap();
            assert!(!report.paths.is_empty(), "{source}");
            assert!(report.complete, "{:?}", report.coverage_notes);
            f.write(
                "routes.js",
                &source.replace(
                    "db.execute(incoming.query.q)",
                    "db.execute('SELECT * FROM users WHERE id=?', [incoming.query.q])",
                ),
            );
            assert!(e
                .trace("routes.js", Some("sql-injection"), TraceLimits::default())
                .unwrap()
                .paths
                .is_empty());
        }
    }
}

#[test]
fn js_route_constructor_proof_and_unsupported_middleware_are_explicit() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    f.write(
        "routes.js",
        "const app = other();\napp.get('/search', (incoming) => db.execute(incoming.query.q));\n",
    );
    assert!(e
        .trace("routes.js", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
    f.write("routes.js", "import express from 'express';\nconst app = express();\napp.get('/search', auth, (incoming) => db.execute(incoming.query.q));\n");
    let report = e
        .trace("routes.js", Some("sql-injection"), TraceLimits::default())
        .unwrap();
    assert!(!report.complete);
    assert!(!report.paths.is_empty());
}

#[test]
fn commonjs_routers_aliases_and_fastify_plugins_trace_renamed_requests() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for source in [
        "const express = require('express'); const app = express(); app.get('/q', incoming => db.execute(incoming.query.q));",
        "const app = require('fastify')(); app.get('/q', incoming => db.execute(incoming.query.q));",
        "const express = require('express'); const router = express.Router(); const handle = incoming => db.execute(incoming.query.q); const alias = handle; router.get('/q', alias);",
        "const make = require('fastify'); const app = make(); app.register(async function plugin(server) { server.get('/q', incoming => db.execute(incoming.query.q)); });",
        "import make from 'fastify'; const app = make(); function plugin(server) { const handle = incoming => db.execute(incoming.query.q); const alias = handle; server.get('/q', alias); } app.register(plugin);",
        "const app = require('fastify')(); app.register(async function outer(server) { server.register(async function inner(child) { child.get('/q', incoming => db.execute(incoming.query.q)); }); });",
    ] {
        f.write("routes.js", source);
        let report = e.trace("routes.js", Some("sql-injection"), TraceLimits::default()).unwrap();
        assert!(report.complete, "{source}: {:?}", report.coverage_notes);
        assert!(!report.paths.is_empty(), "{source}");
        f.write("routes.js", &source.replace("db.execute(incoming.query.q)", "db.execute('SELECT * FROM users WHERE id=?', [incoming.query.q])"));
        assert!(e.trace("routes.js", Some("sql-injection"), TraceLimits::default()).unwrap().paths.is_empty());
    }
}

#[test]
fn opaque_plugins_and_shadowed_require_do_not_imply_complete_framework_proof() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    f.write("routes.js", "function require(name) { return other; } const make = require('express'); const app = make(); app.get('/q', incoming => db.execute(incoming.query.q));");
    assert!(e
        .trace("routes.js", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
    f.write(
        "routes.js",
        "const make = require('fastify'); const app = make(); app.register(importedPlugin);",
    );

    assert!(
        !e.trace("routes.js", None, TraceLimits::default())
            .unwrap()
            .complete
    );
    f.write("routes.js", "const app = require('fastify')(); function plugin(server) { server.register(plugin); } app.register(plugin);");
    assert!(
        !e.trace("routes.js", None, TraceLimits::default())
            .unwrap()
            .complete
    );
}

#[test]
fn plugin_scopes_preserve_outer_require_shadowing() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    f.write("routes.js", "import make from 'fastify'; const app = make(); const require = other; app.register(function plugin(server) { const router = require('express')(); router.get('/q', incoming => db.execute(incoming.query.q)); });");
    assert!(e
        .trace("routes.js", Some("sql-injection"), TraceLimits::default())
        .unwrap()
        .paths
        .is_empty());
}

#[test]
fn fastify_hooks_and_plugin_options_keep_coverage_incomplete() {
    let f = Fixture::new();
    let e = Engine::open(&f.0).unwrap();
    for source in [
        "const app = require('fastify')(); app.addHook('preHandler', auth); app.get('/q', incoming => db.execute(incoming.query.q));",
        "const app = require('fastify')(); app.register(function plugin(server) { server.get('/q', incoming => db.execute(incoming.query.q)); }, {prefix: '/api'});",
    ] {
        f.write("routes.js", source);
        let report = e.trace("routes.js", Some("sql-injection"), TraceLimits::default()).unwrap();
        assert!(!report.complete);
        assert!(!report.paths.is_empty());
    }
}

#[test]
fn stored_jobs_reject_contradictory_completion_results_and_reservations() {
    use sentinel_graph::jobs::JobState;
    let f = Fixture::new();
    f.write("a.py", "value = 1\n");
    f.write("b.py", "value = 2\n");
    let e = Engine::open(&f.0).unwrap();
    let original = e.create_scan_job(3, 60).unwrap();
    let partial = e.resume_scan_job(&original.id, 1, false).unwrap();
    let mut variants = Vec::new();
    let mut job = partial.clone();
    job.state = JobState::Completed;
    variants.push(job);
    let mut job = partial.clone();
    job.results.push(job.results[0].clone());
    job.attempts_reserved = 2;
    variants.push(job);
    let mut job = partial.clone();
    job.results[0].file = "outside.py".into();
    variants.push(job);
    let mut job = partial.clone();
    job.results[0].finding_count = 1;
    variants.push(job);
    let mut job = partial.clone();
    job.results[0].omitted_ids = usize::MAX;
    job.results[0].finding_ids.push("id".into());
    variants.push(job);
    let mut job = partial.clone();
    job.attempts_reserved = 0;
    variants.push(job);
    let mut job = partial.clone();
    job.state = JobState::Running;
    variants.push(job);
    let mut job = partial.clone();
    job.state = JobState::Running;
    job.attempts_reserved = 2;
    job.active_file = Some("a.py".into());
    variants.push(job);
    let mut job = partial.clone();
    job.active_file = Some("b.py".into());
    variants.push(job);
    for job in variants {
        e.db.connection()
            .execute(
                "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
                rusqlite::params![serde_json::to_string(&job).unwrap(), job.id],
            )
            .unwrap();
        assert!(e.scan_job_status(&job.id).is_err());
        assert!(e.list_scan_jobs(20).is_err());
        assert!(e.resume_scan_job(&job.id, 1, false).is_err());
        assert!(e.cancel_scan_job(&job.id).is_err());
    }
    // A cancelled worker's active reservation remains readable but cannot resume.
    let mut cancelled = partial.clone();
    cancelled.state = JobState::Cancelled;
    cancelled.attempts_reserved = 2;
    cancelled.active_file = Some("b.py".into());
    e.db.connection()
        .execute(
            "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
            rusqlite::params![serde_json::to_string(&cancelled).unwrap(), cancelled.id],
        )
        .unwrap();
    assert_eq!(
        e.resume_scan_job(&cancelled.id, 1, false).unwrap().state,
        JobState::Cancelled
    );
}

#[test]
fn cancelled_active_units_cannot_commit_results_or_admit_more_work() {
    use sentinel_graph::jobs::JobState;
    let f = Fixture::new();
    f.write(
        "a.py",
        "def route(request):\n    return db.execute(request.args.get('q'))\n",
    );
    f.write("b.py", "value = 2\n");
    let e = Engine::open(&f.0).unwrap();
    let job = e.create_scan_job(3, 60).unwrap();
    // Simulate cancellation by a second writer immediately after the worker
    // reserves its first unit. Its eventual CAS must reject the changed payload.
    e.db.connection().execute_batch("CREATE TEMP TRIGGER cancel_after_reservation AFTER UPDATE OF payload ON security_jobs WHEN json_extract(NEW.payload, '$.state') = 'running' BEGIN UPDATE security_jobs SET payload=json_set(NEW.payload, '$.state', 'cancelled') WHERE project_id=NEW.project_id AND job_id=NEW.job_id; END;").unwrap();
    let error = e.resume_scan_job(&job.id, 3, false).unwrap_err();
    assert!(error.to_string().contains("changed concurrently"));
    let stored = e.scan_job_status(&job.id).unwrap();
    assert_eq!(stored.state, JobState::Cancelled);
    assert_eq!(stored.attempts_reserved, 1);
    assert!(stored.results.is_empty());
    assert_eq!(stored.active_file.as_deref(), Some("a.py"));
    assert_eq!(e.list_scan_jobs(20).unwrap().jobs[0].units_recorded, 0);
    // A fresh connection sees cancellation and cannot admit a second unit.
    let restarted = Engine::open(&f.0).unwrap();
    let resumed = restarted.resume_scan_job(&job.id, 3, false).unwrap();
    assert_eq!(resumed.state, JobState::Cancelled);
    assert_eq!(resumed.attempts_reserved, 1);
    assert!(resumed.results.is_empty());
}

#[test]
fn cancelled_active_files_require_an_outstanding_reservation() {
    use sentinel_graph::jobs::JobState;
    let f = Fixture::new();
    f.write("a.py", "value = 1\n");
    let e = Engine::open(&f.0).unwrap();
    let mut job = e.create_scan_job(2, 60).unwrap();
    job.state = JobState::Cancelled;
    job.active_file = Some("a.py".into());
    e.db.connection()
        .execute(
            "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
            rusqlite::params![serde_json::to_string(&job).unwrap(), job.id],
        )
        .unwrap();
    assert!(e.scan_job_status(&job.id).is_err());
    job.attempts_reserved = 1;
    e.db.connection()
        .execute(
            "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
            rusqlite::params![serde_json::to_string(&job).unwrap(), job.id],
        )
        .unwrap();
    assert_eq!(
        e.scan_job_status(&job.id).unwrap().state,
        JobState::Cancelled
    );
}

#[test]
fn git_diff_expands_transitive_importers_across_deletions_without_widening_to_dependencies() {
    let f = Fixture::new();
    let git = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(&f.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "Fixture"]);
    f.write("leaf.py", "import utility\nVALUE = 1\n");
    f.write("bridge.py", "import leaf\nimport top\nVALUE = 2\n");
    f.write("top.py", "import bridge\nVALUE = 3\n");
    f.write("entry.py", "import top\nVALUE = 4\n");
    f.write("utility.py", "VALUE = 5\n");
    f.write("unrelated.py", "import missing\nVALUE = 6\n");
    git(&["add", "."]);
    git(&["commit", "-qm", "baseline"]);
    let engine = Engine::open(&f.0).unwrap();
    let expected = vec!["bridge.py", "entry.py", "leaf.py", "top.py"];
    f.write("leaf.py", "import utility\nVALUE = 10\n");
    let changed = engine.scan_diff(Some("HEAD")).unwrap();
    assert_eq!(changed.changed_files, vec!["leaf.py"]);
    assert_eq!(changed.affected_files, expected);
    std::fs::remove_file(f.0.join("leaf.py")).unwrap();
    let deleted = engine.scan_diff(Some("HEAD")).unwrap();
    assert_eq!(deleted.affected_files, expected);
    // The removed import exists only in the baseline, but still propagates to entry.
    f.write("leaf.py", "import utility\nVALUE = 1\n");
    f.write("bridge.py", "import top\nVALUE = 2\n");
    let removed_import = engine.scan_diff(Some("HEAD")).unwrap();
    assert_eq!(
        removed_import.affected_files,
        vec!["bridge.py", "entry.py", "top.py"]
    );
    // Editing an importer alone must not include its uncalled dependency files.
    f.write("bridge.py", "import leaf\nimport top\nVALUE = 2\n");
    f.write("entry.py", "import top\nVALUE = 40\n");
    let importer_only = engine.scan_diff(Some("HEAD")).unwrap();
    assert_eq!(importer_only.affected_files, vec!["entry.py"]);
}

#[test]
fn job_listing_bounds_and_validates_metadata_including_pagination_lookahead() {
    let f = Fixture::new();
    f.write("main.py", "VALUE = 1\n");
    let e = Engine::open(&f.0).unwrap();
    let older = e.create_scan_job(1, 60).unwrap();
    let newer = e.create_scan_job(1, 60).unwrap();
    let (rowid, timestamp): (i64, String) =
        e.db.connection()
            .query_row(
                "SELECT rowid,created_at FROM security_jobs WHERE job_id=?1",
                [&older.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
    for (id, time) in [
        ("a".repeat(1024 * 1024), timestamp.clone()),
        ("g".repeat(64), timestamp.clone()),
        (older.id.clone(), "x".repeat(1024 * 1024)),
        (older.id.clone(), "\u{e9}".repeat(1024 * 1024)),
        (older.id.clone(), "\u{1b}[2J".into()),
        (older.id.clone(), String::new()),
    ] {
        e.db.connection()
            .execute(
                "UPDATE security_jobs SET job_id=?1,created_at=?2 WHERE rowid=?3",
                rusqlite::params![id, time, rowid],
            )
            .unwrap();
        // The corrupt older row is only the lookahead at limit one.
        for limit in [1, 20] {
            assert!(e.list_scan_jobs(limit).is_err());
            assert!(e.db.connection().is_autocommit());
        }
        assert_eq!(e.scan_job_status(&newer.id).unwrap().attempts_reserved, 0);
    }
    e.db.connection()
        .execute(
            "UPDATE security_jobs SET job_id=?1,created_at=?2 WHERE rowid=?3",
            rusqlite::params![older.id, "x".repeat(64), rowid],
        )
        .unwrap();
    let listing = e.list_scan_jobs(1).unwrap();
    assert!(listing.has_more);
    assert!(!listing.source_freshness_checked);
    assert_eq!(listing.jobs[0].id, newer.id);
    let listing = e.list_scan_jobs(20).unwrap();
    assert_eq!(listing.jobs.len(), 2);
    assert_eq!(listing.jobs[1].created_at.len(), 64);
    assert_eq!(e.scan_job_status(&older.id).unwrap().attempts_reserved, 0);
}

#[test]
fn stored_job_reads_enforce_byte_limits_before_parsing_or_actions() {
    let f = Fixture::new();
    f.write("main.py", "VALUE = 1\n");
    let e = Engine::open(&f.0).unwrap();
    let job = e.create_scan_job(1, 60).unwrap();
    for payload in [" ".repeat(2 * 1024 * 1024 + 1), "é".repeat(1024 * 1024 + 1)] {
        e.db.connection()
            .execute(
                "UPDATE security_jobs SET payload=?1 WHERE job_id=?2",
                rusqlite::params![payload, job.id],
            )
            .unwrap();
        assert!(e
            .scan_job_status(&job.id)
            .unwrap_err()
            .to_string()
            .contains("exceeds 2 MiB"));
        assert!(e
            .list_scan_jobs(20)
            .unwrap_err()
            .to_string()
            .contains("exceeds 2 MiB"));
        assert!(e
            .resume_scan_job(&job.id, 1, false)
            .unwrap_err()
            .to_string()
            .contains("exceeds 2 MiB"));
        assert!(e
            .cancel_scan_job(&job.id)
            .unwrap_err()
            .to_string()
            .contains("exceeds 2 MiB"));
    }
}

#[test]
fn symbol_and_relationship_queries_report_incomplete_index_separately_from_output_limits() {
    let f = Fixture::new();
    f.write("a.py", "def helper():\n    return 1\n");
    f.write("b.py", "def helper():\n    return 2\n");
    f.write("broken.py", "def broken(:\n");
    let e = Engine::open(&f.0).unwrap();
    let symbols = e.find_symbols("helper", 1).unwrap();
    assert!(!symbols.index_complete);
    assert!(symbols
        .coverage_notes
        .iter()
        .any(|note| note.contains("broken.py")));
    assert_eq!(symbols.symbols.len(), 1);
    assert!(symbols.omitted_count > 0);
    for callers in [false, true] {
        let query = e.relationships("helper", callers, 1).unwrap();
        assert!(!query.index_complete);
        assert!(query
            .coverage_notes
            .iter()
            .any(|note| note.contains("broken.py")));
        assert_eq!(query.target.len(), 1);
        assert!(query.omitted_count > 0);
    }
    f.write("broken.py", "VALUE = 3\n");
    let complete = e.find_symbols("helper", 1).unwrap();
    assert!(complete.index_complete);
    assert!(complete.coverage_notes.is_empty());
    assert!(complete.omitted_count > 0); // A complete index is not an untruncated answer.
    let backend = complete.backend.as_ref().unwrap();
    assert_eq!(backend.name, "sentinel-native");
    assert_eq!(
        backend.semantics_revision,
        sentinel_core::security::ANALYSIS_SEMANTICS_REVISION
    );
    assert_eq!(complete.source_snapshot.as_ref().unwrap().len(), 64);
    assert_ne!(symbols.source_snapshot, complete.source_snapshot);
    let calls = e.relationships("helper", true, 20).unwrap();
    assert_eq!(calls.source_snapshot, complete.source_snapshot);
    assert_eq!(calls.backend, complete.backend);
    let trace = e.trace("helper", None, TraceLimits::default()).unwrap();
    assert_eq!(trace.source_snapshot, complete.source_snapshot);
    f.write("broken.py", "VALUE = 4\n");
    assert_ne!(
        e.find_symbols("helper", 20).unwrap().source_snapshot,
        complete.source_snapshot
    );
    let mut legacy = serde_json::to_value(&complete).unwrap();
    legacy.as_object_mut().unwrap().remove("index_complete");
    legacy.as_object_mut().unwrap().remove("coverage_notes");
    legacy.as_object_mut().unwrap().remove("backend");
    legacy.as_object_mut().unwrap().remove("source_snapshot");
    let legacy: sentinel_graph::Relationships = serde_json::from_value(legacy).unwrap();
    assert!(!legacy.index_complete); // Missing historical metadata cannot imply completeness.
    assert!(legacy.backend.is_none());
    assert!(legacy.source_snapshot.is_none());
}

#[test]
fn snapshot_joins_caller_transactions_and_releases_owned_transactions_on_failure() {
    let f = Fixture::new();
    f.write("main.py", "def helper():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let stats = e.status().unwrap().unwrap();
    let expected_symbols = stats.symbols;
    let original = serde_json::to_string(&stats).unwrap();
    let tx = e.db.connection().unchecked_transaction().unwrap();
    assert_eq!(e.snapshot().unwrap().files.len(), 1);
    assert!(!e.db.connection().is_autocommit());
    tx.execute(
        "UPDATE index_metadata SET payload='invalid' WHERE project_id=?1",
        [&e.project_id],
    )
    .unwrap();
    assert!(e.snapshot().is_err());
    assert!(!e.db.connection().is_autocommit());
    tx.rollback().unwrap();
    e.db.connection()
        .execute(
            "UPDATE index_metadata SET payload='invalid' WHERE project_id=?1",
            [&e.project_id],
        )
        .unwrap();
    assert!(e.snapshot().is_err());
    assert!(e.db.connection().is_autocommit());
    e.db.connection()
        .execute(
            "UPDATE index_metadata SET payload=?1 WHERE project_id=?2",
            rusqlite::params![original, e.project_id],
        )
        .unwrap();
    assert_eq!(e.snapshot().unwrap().stats.symbols, expected_symbols);
    assert!(e.db.connection().is_autocommit());
}

#[test]
fn snapshots_keep_files_edges_and_stats_consistent_during_another_connection_refresh() {
    use std::sync::{Arc, Barrier};
    let f = Fixture::new();
    let first = "def first():\n    return 1\n";
    let second = "def second():\n    return 2\ndef third():\n    return 3\n";
    f.write("main.py", first);
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let writer_barrier = barrier.clone();
    let root = f.0.clone();
    let writer = std::thread::spawn(move || {
        let writer = Engine::open(&root).unwrap();
        writer_barrier.wait();
        for i in 0..40 {
            std::fs::write(
                root.join("main.py"),
                if i % 2 == 0 { second } else { first },
            )
            .unwrap();
            assert!(writer.index().unwrap().complete);
            std::thread::yield_now();
        }
    });
    barrier.wait();
    for _ in 0..200 {
        let snapshot = e.snapshot().unwrap();
        let ids = snapshot
            .files
            .iter()
            .flat_map(|file| &file.symbols)
            .map(|symbol| symbol.id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(snapshot.stats.symbols, ids.len());
        assert_eq!(snapshot.stats.files_indexed, snapshot.files.len());
        for edge in snapshot.edges.iter().filter(|edge| edge.kind == "DEFINES") {
            assert!(
                ids.contains(edge.to.as_str()),
                "edge belongs to a different committed source view"
            );
        }
        assert!(e.db.connection().is_autocommit());
        std::thread::yield_now();
    }
    writer.join().unwrap();
}

#[test]
fn refresh_reserves_writer_before_loading_ir_and_rolls_back_failed_updates() {
    let f = Fixture::new();
    f.write("main.py", "def before():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let other = Engine::open(&f.0).unwrap();
    e.db.connection()
        .busy_timeout(std::time::Duration::ZERO)
        .unwrap();
    let payload: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM files WHERE project_id=?1 AND path='main.py'",
                [&e.project_id],
                |r| r.get(0),
            )
            .unwrap();
    e.db.connection()
        .execute(
            "UPDATE files SET payload='invalid' WHERE project_id=?1",
            [&e.project_id],
        )
        .unwrap();
    let writer = rusqlite::Transaction::new_unchecked(
        other.db.connection(),
        rusqlite::TransactionBehavior::Immediate,
    )
    .unwrap();
    // An active refresh must be rejected before reading even malformed reusable IR.
    // Deferred writer acquisition would fail with JSON parsing instead of Busy.
    let error = e.index().unwrap_err();
    let sql = error.downcast_ref::<rusqlite::Error>().unwrap();
    assert_eq!(
        sql.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy)
    );
    assert!(e.db.connection().is_autocommit());
    writer.rollback().unwrap();
    assert!(e.index().is_err());
    assert!(e.db.connection().is_autocommit());
    e.db.connection()
        .execute(
            "UPDATE files SET payload=?1 WHERE project_id=?2",
            rusqlite::params![payload, e.project_id],
        )
        .unwrap();
    let before = e.snapshot().unwrap();
    f.write("main.py", "def after():\n    return 2\n");
    e.db.connection().execute_batch(
        "CREATE TEMP TRIGGER reject_refresh BEFORE INSERT ON files BEGIN SELECT RAISE(ABORT,'test refresh failure'); END;",
    ).unwrap();
    assert!(e
        .index()
        .unwrap_err()
        .to_string()
        .contains("test refresh failure"));
    assert!(e.db.connection().is_autocommit());
    let rolled_back = e.snapshot().unwrap();
    assert_eq!(
        serde_json::to_value(&before.files).unwrap(),
        serde_json::to_value(&rolled_back.files).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&before.edges).unwrap(),
        serde_json::to_value(&rolled_back.edges).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&before.stats).unwrap(),
        serde_json::to_value(&rolled_back.stats).unwrap()
    );
    e.db.connection()
        .execute_batch("DROP TRIGGER reject_refresh")
        .unwrap();
    assert!(e.index().unwrap().complete);
    let after = e.snapshot().unwrap();
    assert_ne!(before.files[0].content_hash, after.files[0].content_hash);
    assert_eq!(after.stats.files_indexed, 1);
    assert!(e.db.connection().is_autocommit());
}

#[test]
fn static_job_admission_uses_completeness_from_the_manifest_snapshot() {
    use sentinel_graph::jobs::JobState;
    let f = Fixture::new();
    f.write("main.py", "def helper():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    let pending = e.create_scan_job(2, 60).unwrap();
    let stats = e.index().unwrap();
    assert!(stats.complete);
    let mut partial = stats;
    partial.complete = false;
    partial.coverage_notes = vec!["test replacement committed source view is incomplete".into()];
    let payload = serde_json::to_string(&partial).unwrap().replace("'", "''");
    // Emulate a replacement committed view between refresh statistics and admission.
    // The trigger changes persisted coverage while index() returns its complete stats.
    e.db.connection().execute_batch(&format!(
        "CREATE TEMP TRIGGER replace_coverage AFTER UPDATE ON index_metadata BEGIN UPDATE index_metadata SET payload='{payload}' WHERE project_id=NEW.project_id; END;"
    )).unwrap();
    assert!(e.index().unwrap().complete);
    assert!(!e.snapshot().unwrap().stats.complete);
    assert!(e
        .create_scan_job(2, 60)
        .unwrap_err()
        .to_string()
        .contains("complete indexed source scope"));
    assert_eq!(e.list_scan_jobs(20).unwrap().jobs.len(), 1);
    let stale = e.resume_scan_job(&pending.id, 1, false).unwrap();
    assert_eq!(stale.state, JobState::Stale);
    assert_eq!(stale.attempts_reserved, 0);
    assert!(stale.active_file.is_none());
    assert!(stale.results.is_empty());
    assert_eq!(stale.max_attempts, pending.max_attempts);
    assert_eq!(stale.max_elapsed_ms, pending.max_elapsed_ms);
    e.db.connection()
        .execute_batch("DROP TRIGGER replace_coverage")
        .unwrap();
    let fresh = e.create_scan_job(2, 60).unwrap();
    assert_eq!(fresh.state, JobState::Pending);
    assert_eq!(fresh.source_manifest, pending.source_manifest);
    assert_eq!(
        e.resume_scan_job(&fresh.id, 1, false).unwrap().state,
        JobState::Completed
    );
}

#[test]
fn source_byte_limits_preserve_exact_boundary_and_block_incomplete_baseline_passes() {
    use sentinel_graph::verification::Verdict;
    let f = Fixture::new();
    let source = format!("#{} ", "\u{e9}".repeat(524287));
    assert_eq!(source.len(), 1024 * 1024);
    f.write("main.py", &source);
    let e = Engine::open(&f.0).unwrap();
    assert!(e.index().unwrap().complete);
    assert!(e.create_baseline().unwrap().complete);
    assert_eq!(e.verify_patch(None).unwrap().verdict, Verdict::Pass);
    f.write("main.py", &format!("{source}\u{e9}"));
    let oversized = e.index().unwrap();
    assert!(!oversized.complete);
    assert!(oversized
        .coverage_notes
        .iter()
        .any(|note| note.contains("source exceeds 1 MiB")));
    assert!(e.create_baseline().is_err());
    let verification = e.verify_patch(None).unwrap();
    assert_ne!(verification.verdict, Verdict::Pass);
    assert!(verification
        .comparison
        .coverage_notes
        .iter()
        .any(|note| note.contains("source exceeds 1 MiB")));
    std::fs::write(f.0.join("main.py"), [0xff, 0xfe]).unwrap();
    assert!(!e.index().unwrap().complete);
    assert!(e.create_baseline().is_err());
    assert_ne!(e.verify_patch(None).unwrap().verdict, Verdict::Pass);
    f.write("main.py", "# repaired\n");
    assert!(e.create_baseline().unwrap().complete);
    assert_eq!(e.verify_patch(None).unwrap().verdict, Verdict::Pass);
}

#[test]
fn saved_baseline_reads_enforce_byte_limits_before_reassessment_or_lifecycle_updates() {
    use sentinel_graph::verification::Verdict;
    let f = Fixture::new();
    f.write("main.py", "# safe\n");
    let e = Engine::open(&f.0).unwrap();
    e.create_baseline().unwrap();
    let original: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM security_baselines WHERE project_id=?1",
                [&e.project_id],
                |row| row.get(0),
            )
            .unwrap();
    let index: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM index_metadata WHERE project_id=?1",
                [&e.project_id],
                |row| row.get(0),
            )
            .unwrap();
    f.write("main.py", "def broken(:\n");
    let limit = 16 * 1024 * 1024;
    for oversized in [" ".repeat(limit + 1), "\u{e9}".repeat(limit / 2 + 1)] {
        e.db.connection()
            .execute(
                "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
                rusqlite::params![oversized, e.project_id],
            )
            .unwrap();
        assert!(e
            .verify_patch(None)
            .unwrap_err()
            .to_string()
            .contains("baseline record exceeds 16 MiB"));
        let retained: String =
            e.db.connection()
                .query_row(
                    "SELECT payload FROM index_metadata WHERE project_id=?1",
                    [&e.project_id],
                    |row| row.get(0),
                )
                .unwrap();
        assert_eq!(retained, index); // Invalid stored evidence is rejected before scanning current source.
        assert_eq!(
            e.db.connection()
                .query_row(
                    "SELECT count(*) FROM baseline_findings WHERE project_id=?1",
                    [&e.project_id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }
    f.write("main.py", "# safe\n");
    let padded = format!("{original}{}", " ".repeat(limit - original.len()));
    assert_eq!(padded.len(), limit);
    e.db.connection()
        .execute(
            "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
            rusqlite::params![padded, e.project_id],
        )
        .unwrap();
    assert_eq!(e.verify_patch(None).unwrap().verdict, Verdict::Pass);
    e.db.connection()
        .execute(
            "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
            rusqlite::params![original, e.project_id],
        )
        .unwrap();
    assert_eq!(e.verify_patch(None).unwrap().verdict, Verdict::Pass);
}

#[test]
fn contradictory_saved_baselines_fail_before_resolving_existing_debt() {
    let f = Fixture::new();
    let unsafe_code = "def handler(request):\n    value = request.args['q']\n    cursor.execute('SELECT ' + value)\n";
    f.write("routes.py", unsafe_code);
    let e = Engine::open(&f.0).unwrap();
    assert!(e.create_baseline().unwrap().findings > 0);
    let raw: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM security_baselines WHERE project_id=?1",
                [&e.project_id],
                |r| r.get(0),
            )
            .unwrap();
    let original: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let index: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM index_metadata WHERE project_id=?1",
                [&e.project_id],
                |r| r.get(0),
            )
            .unwrap();
    f.write("routes.py", "# removed unsafe code\n");
    for change in 0..4 {
        let mut invalid = original.clone();
        match change {
            0 => {
                invalid["keys"].as_array_mut().unwrap().pop();
            }
            1 => invalid["snapshot"]["id"] = serde_json::json!("0".repeat(64)),
            2 => invalid["evidence"][0]["finding_id"] = serde_json::json!("unrelated"),
            _ => invalid["evidence"][0]["detector"]["semantics_revision"] = serde_json::json!(0),
        }
        e.db.connection()
            .execute(
                "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
                rusqlite::params![invalid.to_string(), e.project_id],
            )
            .unwrap();
        assert!(e
            .verify_patch(None)
            .unwrap_err()
            .to_string()
            .contains("baseline"));
        assert_eq!(e.db.connection().query_row("SELECT count(*) FROM baseline_findings WHERE project_id=?1 AND status='resolved'", [&e.project_id], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(
            e.db.connection()
                .query_row(
                    "SELECT payload FROM index_metadata WHERE project_id=?1",
                    [&e.project_id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            index
        );
    }
    e.db.connection()
        .execute(
            "UPDATE security_baselines SET payload=?1 WHERE project_id=?2",
            rusqlite::params![raw, e.project_id],
        )
        .unwrap();
    f.write("routes.py", unsafe_code);
    assert_eq!(
        e.verify_patch(None).unwrap().verdict,
        sentinel_graph::verification::Verdict::Pass
    );
}

#[test]
fn context_reads_only_related_active_history_and_fails_on_row_overflow() {
    use sentinel_graph::context::ContextEvidence;
    let f = Fixture::new();
    f.write(
        "routes.py",
        "from service import helper\ndef handler(value):\n    return helper(value)\n",
    );
    f.write("service.py", "def helper(value):\n    return value\n");
    f.write("other.py", "def unrelated(value):\n    return value\n");
    let e = Engine::open(&f.0).unwrap();
    let stored = |id: &str, file: &str, line: usize| sentinel_core::Finding {
        id: id.into(),
        severity: sentinel_core::Severity::High,
        confidence: 0.7,
        category: "history".into(),
        file: e.root.join(file),
        line,
        title: "stored".into(),
        description: String::new(),
        execution_path: vec![],
        affected_components: vec![],
        evidence: vec![],
        recommendation: String::new(),
    };
    for (id, file, line) in [
        ("stored-target", "routes.py", 1),
        ("stored-dependency", "service.py", 1),
        ("stored-outside", "other.py", 1),
        ("stored-resolved", "routes.py", 2),
    ] {
        e.db.insert_finding(&stored(id, file, line), "history")
            .unwrap();
    }
    e.db.resolve_finding("stored-resolved").unwrap();
    let oversized = "x".repeat(1024 * 1024 + 1);
    e.db.connection()
        .execute(
            "UPDATE findings SET evidence=?1 WHERE id='stored-outside'",
            [&oversized],
        )
        .unwrap();
    let context = e.get_security_context("handler", 200).unwrap();
    assert!(context.complete);
    let ids = context
        .selected_items
        .iter()
        .filter_map(|item| match &item.evidence {
            ContextEvidence::Finding(finding) => Some(finding.id.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(ids.contains(&"stored-target") && ids.contains(&"stored-dependency"));
    assert!(!ids.contains(&"stored-outside") && !ids.contains(&"stored-resolved"));
    assert!(e
        .get_security_context("unrelated", 200)
        .unwrap_err()
        .to_string()
        .contains("1 MiB"));
    let tx = e.db.connection().unchecked_transaction().unwrap();
    for line in 10..211 {
        e.db.insert_finding(
            &stored(&format!("history-{line}"), "routes.py", line),
            "history",
        )
        .unwrap();
    }
    tx.commit().unwrap();
    for max_items in [1, 200] {
        let error = e
            .get_security_context("handler", max_items)
            .unwrap_err()
            .to_string();
        assert!(error.contains("row limit"), "{error}");
    }
    let count: usize =
        e.db.connection()
            .query_row("SELECT count(*) FROM findings", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 205);
}

#[test]
fn oversized_stored_findings_fail_context_and_explanation_without_rewriting_history() {
    let f = Fixture::new();
    f.write("routes.py", "def handler(request):\n    value = request.args['q']\n    cursor.execute('SELECT ' + value)\n");
    let e = Engine::open(&f.0).unwrap();
    let scanned = e.scan_file("routes.py").unwrap();
    let id = &scanned.report.findings[0].id;
    let payload = format!("sensitive-invalid-json{}", "x".repeat(1024 * 1024));
    e.db.connection()
        .execute(
            "UPDATE findings SET evidence=?1 WHERE id=?2",
            rusqlite::params![payload, id],
        )
        .unwrap();
    for error in [
        e.get_security_context("handler", 40).unwrap_err(),
        e.explain_finding(id).unwrap_err(),
    ] {
        let message = error.to_string();
        assert!(message.contains("1 MiB"));
        assert!(!message.contains("sensitive-invalid-json"));
    }
    let retained: usize =
        e.db.connection()
            .query_row(
                "SELECT length(evidence) FROM findings WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(retained, payload.len());
    e.db.connection()
        .execute("UPDATE findings SET evidence='[]' WHERE id=?1", [id])
        .unwrap();
    assert!(e.get_security_context("handler", 40).is_ok());
    assert!(e.explain_finding(id).is_ok());
}

#[test]
fn finding_explanations_bind_graph_and_excerpt_identity_and_label_disagreement() {
    let f = Fixture::new();
    f.write("routes.py", "def handler(request):\n    value = request.args['q']\n    cursor.execute('SELECT ' + value)\n");
    let e = Engine::open(&f.0).unwrap();
    let scanned = e.scan_file("routes.py").unwrap();
    let id = &scanned.report.findings[0].id;
    let fresh = e.explain_finding(id).unwrap();
    assert!(fresh.excerpt_matches_graph && fresh.index_complete);
    assert_eq!(fresh.backend.as_ref().unwrap().name, "sentinel-native");
    assert!(fresh.excerpt_content_hash.is_some());
    assert_eq!(
        fresh.source_snapshot,
        e.trace(".", None, TraceLimits::default())
            .unwrap()
            .source_snapshot
    );
    // Keep the cache row internally consistent while injecting a different committed
    // source view; matching row/payload identity must not imply source freshness.
    e.db.connection().execute_batch("CREATE TEMP TRIGGER replace_excerpt_hash AFTER UPDATE ON index_metadata BEGIN UPDATE files SET content_hash='different-indexed-view',payload=json_set(payload,'$.content_hash','different-indexed-view'); END;").unwrap();
    let mixed = e.explain_finding(id).unwrap();
    assert!(!mixed.excerpt_matches_graph);
    assert_eq!(mixed.excerpt_content_hash, fresh.excerpt_content_hash);
    assert_ne!(mixed.source_snapshot, fresh.source_snapshot);
    assert!(mixed
        .coverage_notes
        .iter()
        .any(|note| note.contains("differs from the graph snapshot")));
    e.db.connection()
        .execute_batch("DROP TRIGGER replace_excerpt_hash")
        .unwrap();
    f.write("routes.py", "# repaired historical source\n");
    let repaired = e.explain_finding(id).unwrap();
    assert!(repaired.excerpt_matches_graph);
    assert_ne!(repaired.excerpt_content_hash, fresh.excerpt_content_hash);
    assert!(repaired
        .coverage_notes
        .iter()
        .any(|note| note.contains("Finding history can predate")));
    std::fs::remove_file(f.0.join("routes.py")).unwrap();
    let missing = e.explain_finding(id).unwrap();
    assert!(!missing.excerpt_matches_graph);
    assert!(missing.excerpt_content_hash.is_none());
    assert!(missing.affected_code.is_empty());
    let mut legacy = serde_json::to_value(&fresh).unwrap();
    for field in [
        "backend",
        "source_snapshot",
        "index_complete",
        "excerpt_content_hash",
        "excerpt_matches_graph",
    ] {
        legacy.as_object_mut().unwrap().remove(field);
    }
    let legacy: sentinel_graph::analysis::FindingEvidence = serde_json::from_value(legacy).unwrap();
    assert!(legacy.backend.is_none() && legacy.source_snapshot.is_none());
    assert!(!legacy.index_complete && !legacy.excerpt_matches_graph);
    assert!(legacy.excerpt_content_hash.is_none());
}

#[test]
fn security_context_provenance_is_stable_across_limits_and_changes_with_indexed_source() {
    let f = Fixture::new();
    f.write("main.py", "def helper():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    let focused = e.get_security_context("helper", 1).unwrap();
    let expanded = e.get_security_context("main.py", 50).unwrap();
    assert_eq!(focused.source_snapshot, expanded.source_snapshot);
    assert_eq!(focused.backend, expanded.backend);
    assert_eq!(focused.backend.as_ref().unwrap().name, "sentinel-native");
    assert_eq!(focused.source_snapshot.as_ref().unwrap().len(), 64);
    assert_eq!(
        focused.source_snapshot,
        e.trace(".", None, TraceLimits::default())
            .unwrap()
            .source_snapshot
    );
    assert!(focused.omitted_count > 0);
    f.write("unrelated.py", "VALUE = 2\n");
    let changed = e.get_security_context("helper", 1).unwrap();
    assert_ne!(focused.source_snapshot, changed.source_snapshot);
    f.write("broken.py", "def invalid(:\n");
    let partial = e.get_security_context("helper", 1).unwrap();
    assert!(!partial.complete);
    assert!(partial.source_snapshot.is_some());
    let mut legacy = serde_json::to_value(focused).unwrap();
    legacy.as_object_mut().unwrap().remove("backend");
    legacy.as_object_mut().unwrap().remove("source_snapshot");
    let legacy: sentinel_graph::context::SecurityContext = serde_json::from_value(legacy).unwrap();
    assert!(legacy.backend.is_none() && legacy.source_snapshot.is_none());
}

#[test]
fn project_file_cleanup_indexes_upgrade_existing_v7_without_changing_graph_payloads() {
    let f = Fixture::new();
    f.write("main.py", "def first():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let original = e.snapshot().unwrap();
    e.db.connection()
        .execute_batch(
            "DROP INDEX idx_symbols_project_file; DROP INDEX idx_annotations_project_file; DROP INDEX idx_findings_file_active;",
        )
        .unwrap();
    drop(e);
    let e = Engine::open(&f.0).unwrap();
    assert_eq!(
        e.db.connection()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(
        serde_json::to_value(&e.snapshot().unwrap().files).unwrap(),
        serde_json::to_value(&original.files).unwrap()
    );
    for (table, expected) in [
        ("symbols", "idx_symbols_project_file"),
        ("security_annotations", "idx_annotations_project_file"),
    ] {
        let mut statement =
            e.db.connection()
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN DELETE FROM {table} WHERE project_id=?1 AND file=?2"
                ))
                .unwrap();
        let plans = statement
            .query_map(rusqlite::params![e.project_id, "main.py"], |r| {
                r.get::<_, String>(3)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plans.iter().any(|plan| plan.contains(expected)),
            "{plans:?}"
        );
    }
    let plans = e.db.connection().prepare("EXPLAIN QUERY PLAN SELECT id FROM findings WHERE replace(file,char(92),'/') IN (?1) AND resolved_at IS NULL ORDER BY id LIMIT 2").unwrap().query_map(["main.py"], |row| row.get::<_, String>(3)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(
        plans
            .iter()
            .any(|plan| plan.contains("idx_findings_file_active")),
        "{plans:?}"
    );
    f.write("main.py", "def replacement():\n    return 2\n");
    f.write("added.py", "def added():\n    return 3\n");
    let changed = e.index().unwrap();
    assert_eq!(changed.changed_files, 2);
    assert_eq!(e.find_symbols("first", 20).unwrap().symbols.len(), 0);
    assert_eq!(e.find_symbols("replacement", 20).unwrap().symbols.len(), 1);
    std::fs::remove_file(f.0.join("main.py")).unwrap();
    assert_eq!(e.index().unwrap().removed_files, 1);
    assert!(e
        .find_symbols("replacement", 20)
        .unwrap()
        .symbols
        .is_empty());
    assert_eq!(e.find_symbols("added", 20).unwrap().symbols.len(), 1);
}

#[test]
fn oversized_index_statistics_fail_status_and_snapshot_until_native_refresh() {
    let f = Fixture::new();
    f.write("main.py", "def handler(value):\n    return value\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let before = e.snapshot().unwrap();
    let corrupt = format!("sensitive-invalid-json{}", "x".repeat(1024 * 1024));
    e.db.connection()
        .execute(
            "UPDATE index_metadata SET payload=?1 WHERE project_id=?2",
            rusqlite::params![corrupt, e.project_id],
        )
        .unwrap();
    for error in [e.status().unwrap_err(), e.snapshot().unwrap_err()] {
        let message = error.to_string();
        assert!(message.contains("1 MiB"));
        assert!(!message.contains("sensitive-invalid-json"));
        assert!(e.db.connection().is_autocommit());
    }
    let retained: usize =
        e.db.connection()
            .query_row(
                "SELECT length(payload) FROM index_metadata WHERE project_id=?1",
                [&e.project_id],
                |row| row.get(0),
            )
            .unwrap();
    assert_eq!(retained, corrupt.len());
    let refreshed = e.index().unwrap();
    assert_eq!(refreshed.changed_files, 0);
    assert_eq!(refreshed.unchanged_files, 1);
    let after = e.snapshot().unwrap();
    assert!(after.stats.complete);
    assert_eq!(
        serde_json::to_value(after.files).unwrap(),
        serde_json::to_value(before.files).unwrap()
    );
    assert_eq!(
        serde_json::to_value(after.edges).unwrap(),
        serde_json::to_value(before.edges).unwrap()
    );
}

#[test]
fn cached_edge_identity_mismatches_fail_snapshots_until_refresh_without_rewriting_history() {
    let f = Fixture::new();
    f.write(
        "main.py",
        "def helper():\n    return 1\ndef handler():\n    return helper()\n",
    );
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let before = e.snapshot().unwrap();
    let original = serde_json::to_value(
        before
            .edges
            .iter()
            .find(|edge| edge.kind == "CALLS")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(original["resolved"], true);
    for field in ["from", "to", "kind", "file", "line", "name", "resolved"] {
        let mut corrupt = original.clone();
        corrupt[field] = match field {
            "line" => 999.into(),
            "resolved" => false.into(),
            _ => "private-conflicting-edge".into(),
        };
        let payload = corrupt.to_string();
        e.db.connection()
            .execute(
                "UPDATE symbol_edges SET payload=?1 WHERE project_id=?2 AND kind='CALLS'",
                rusqlite::params![payload, e.project_id],
            )
            .unwrap();
        let error = e.snapshot().unwrap_err().to_string();
        assert!(error.contains("cached edge identity mismatch"));
        assert!(!error.contains("private-conflicting-edge"));
        assert!(e.db.connection().is_autocommit());
        let retained: String =
            e.db.connection()
                .query_row(
                    "SELECT payload FROM symbol_edges WHERE project_id=?1 AND kind='CALLS'",
                    [&e.project_id],
                    |row| row.get(0),
                )
                .unwrap();
        assert_eq!(retained, payload);
        let tx = e.db.connection().unchecked_transaction().unwrap();
        assert!(e.snapshot().is_err());
        assert!(!e.db.connection().is_autocommit());
        tx.rollback().unwrap();
        assert_eq!(e.index().unwrap().unchanged_files, 1);
        assert_eq!(
            serde_json::to_value(e.snapshot().unwrap().edges).unwrap(),
            serde_json::to_value(&before.edges).unwrap()
        );
    }
    // SQLite booleans must be canonical; nonzero is not necessarily valid `true`.
    for sql in [
        "UPDATE symbol_edges SET resolved=2 WHERE kind='CALLS'",
        "UPDATE symbol_edges SET line=-1 WHERE kind='CALLS'",
    ] {
        e.db.connection().execute_batch(sql).unwrap();
        assert!(e
            .snapshot()
            .unwrap_err()
            .to_string()
            .contains("cached edge identity mismatch"));
        assert!(e.db.connection().is_autocommit());
        e.index().unwrap();
    }
    assert_eq!(
        serde_json::to_value(e.snapshot().unwrap().files).unwrap(),
        serde_json::to_value(before.files).unwrap()
    );
}

#[test]
fn explicit_index_rebuild_recovers_corrupt_cache_atomically_and_preserves_history() {
    let f = Fixture::new();
    f.write(
        "routes.py",
        "def handler(request):\n    cursor.execute('SELECT ' + request.args['q'])\n",
    );
    let e = Engine::open(&f.0).unwrap();
    assert!(!e.scan_file("routes.py").unwrap().report.findings.is_empty());
    e.create_baseline().unwrap();
    e.create_scan_job(2, 30).unwrap();
    let before = e.snapshot().unwrap();
    let conn = e.db.connection();
    conn.execute_batch("INSERT INTO memory(key,value) VALUES('retained','history');
        INSERT INTO audit_revisions(project_id,revision_id,run_id,source_snapshot,status,payload) VALUES('retained','r','run','snapshot','partial','{}');
        INSERT INTO audit_latest VALUES('retained','r');
        INSERT INTO audit_coverage VALUES('retained','r','c','planned','{}');
        INSERT INTO audit_attempts VALUES('retained','r','c',1,'{}');
        INSERT INTO audit_candidates VALUES('retained','r','f','needs_validation','{}');
        INSERT INTO audit_reviews VALUES('retained','r','f','{}');
        INSERT INTO audit_artifacts VALUES('retained','r','artifact','{}');
        INSERT INTO files(project_id,path,language,content_hash,payload) VALUES('other','other.py','python','hash','foreign-cache');
        INSERT INTO symbols(id,project_id,file,name,qualified_name,kind,start_line,end_line,language,content_hash,payload) VALUES('other-symbol','other','other.py','other','other','function',1,1,'python','hash','foreign-symbol');
        INSERT INTO security_annotations(id,project_id,file,owner,kind,category,payload) VALUES('other-annotation','other','other.py','other-symbol','source','sql','foreign-annotation');
        INSERT INTO symbol_edges VALUES('other','other.py','a','b','CALLS',1,'other',0,'foreign-edge');
        INSERT INTO index_metadata(project_id,payload) VALUES('other','foreign-statistics');").unwrap();
    for table in [
        "audit_revisions",
        "audit_latest",
        "audit_coverage",
        "audit_attempts",
        "audit_candidates",
        "audit_reviews",
        "audit_artifacts",
    ] {
        conn.execute(
            &format!("UPDATE {table} SET project_id=?1"),
            [&e.project_id],
        )
        .unwrap();
    }
    // Capture all persistent tables, including history not interpreted by rebuilding.
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let dump = || {
        tables
            .iter()
            .map(|table| {
                let mut stmt = conn
                    .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                    .unwrap();
                let columns = stmt.column_count();
                let rows = stmt
                    .query_map([], |row| {
                        (0..columns)
                            .map(|i| row.get::<_, rusqlite::types::Value>(i))
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>();
                (table.clone(), rows)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let intact = dump();
    conn.execute(
        "UPDATE files SET payload='corrupt-cache' WHERE project_id=?1",
        [&e.project_id],
    )
    .unwrap();
    conn.execute(
        "UPDATE index_metadata SET payload='corrupt-statistics' WHERE project_id=?1",
        [&e.project_id],
    )
    .unwrap();
    assert!(e.index().is_err());
    let corrupt = dump();
    conn.execute_batch("CREATE TEMP TRIGGER fail_rebuild BEFORE INSERT ON symbols BEGIN SELECT RAISE(ABORT,'rebuild write failure'); END;").unwrap();
    assert!(e
        .rebuild_index()
        .unwrap_err()
        .to_string()
        .contains("rebuild write failure"));
    assert!(conn.is_autocommit());
    assert_eq!(dump(), corrupt); // Cache clearing and partial new inserts rolled back.
    conn.execute_batch("DROP TRIGGER fail_rebuild").unwrap();
    let rebuilt = e.rebuild_index().unwrap();
    assert!(rebuilt.complete);
    assert_eq!(rebuilt.changed_files, 1);
    assert_eq!(rebuilt.unchanged_files, 0);
    let after = e.snapshot().unwrap();
    assert_eq!(
        serde_json::to_value(after.files).unwrap(),
        serde_json::to_value(before.files).unwrap()
    );
    assert_eq!(
        serde_json::to_value(after.edges).unwrap(),
        serde_json::to_value(before.edges).unwrap()
    );
    let recovered = dump();
    for (table, rows) in &intact {
        if [
            "files",
            "symbols",
            "security_annotations",
            "symbol_edges",
            "index_metadata",
        ]
        .contains(&table.as_str())
        {
            // The unrelated project's deliberately malformed cache is untouched.
            let project_column = if table == "symbols" || table == "security_annotations" {
                1
            } else {
                0
            };
            let foreign = |rows: &Vec<Vec<rusqlite::types::Value>>| {
                rows.iter()
                    .filter(|row| {
                        row[project_column] == rusqlite::types::Value::Text("other".into())
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            };
            assert_eq!(foreign(rows), foreign(&recovered[table]));
        } else {
            assert_eq!(rows, &recovered[table], "retained table {table}");
        }
    }
    assert_eq!(e.index().unwrap().unchanged_files, 1);
}

#[test]
fn cached_file_identity_mismatches_fail_refresh_and_snapshot_without_writes() {
    let f = Fixture::new();
    f.write("main.py", "def handler(value):\n    return value\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let before = e.snapshot().unwrap();
    let original = serde_json::to_value(&before.files[0]).unwrap();
    for field in ["path", "language", "content_hash"] {
        let stats = serde_json::to_value(e.status().unwrap().unwrap()).unwrap();
        let mut corrupt = original.clone();
        corrupt[field] = "private-conflicting-cache-value".into();
        let payload = corrupt.to_string();
        e.db.connection()
            .execute(
                "UPDATE files SET payload=?1 WHERE project_id=?2 AND path='main.py'",
                rusqlite::params![payload, e.project_id],
            )
            .unwrap();
        for error in [e.snapshot().unwrap_err(), e.index().unwrap_err()] {
            assert!(error.to_string().contains("cached file identity mismatch"));
            assert!(!error
                .to_string()
                .contains("private-conflicting-cache-value"));
            assert!(e.db.connection().is_autocommit());
        }
        assert_eq!(
            serde_json::to_value(e.status().unwrap().unwrap()).unwrap(),
            stats
        );
        let retained: String =
            e.db.connection()
                .query_row(
                    "SELECT payload FROM files WHERE project_id=?1 AND path='main.py'",
                    [&e.project_id],
                    |row| row.get(0),
                )
                .unwrap();
        assert_eq!(retained, payload);
        let tx = e.db.connection().unchecked_transaction().unwrap();
        assert!(e.snapshot().is_err());
        assert!(!e.db.connection().is_autocommit());
        tx.rollback().unwrap();
        e.db.connection()
            .execute(
                "UPDATE files SET payload=?1 WHERE project_id=?2 AND path='main.py'",
                rusqlite::params![original.to_string(), e.project_id],
            )
            .unwrap();
        let refreshed = e.index().unwrap();
        assert_eq!(refreshed.unchanged_files, 1);
        let after = e.snapshot().unwrap();
        assert_eq!(
            serde_json::to_value(after.files).unwrap(),
            serde_json::to_value(&before.files).unwrap()
        );
        assert_eq!(
            serde_json::to_value(after.edges).unwrap(),
            serde_json::to_value(&before.edges).unwrap()
        );
    }
}

#[test]
fn index_statistics_reject_mismatched_repository_identity_without_rewriting_history() {
    let f = Fixture::new();
    f.write("main.py", "def handler(value):\n    return value\n");
    let e = Engine::open(&f.0).unwrap();
    assert!(e.status().unwrap().is_none());
    let valid = e.index().unwrap();
    let before = e.snapshot().unwrap();
    for field in ["project_id", "repository"] {
        for value in ["", "private-other-project"] {
            let mut corrupt = serde_json::to_value(&valid).unwrap();
            corrupt[field] = value.into();
            e.db.set_index_metadata(&e.project_id, &corrupt).unwrap();
            // Reads neither trust a valid-looking `complete` flag nor repair history.
            for error in [e.status().unwrap_err(), e.snapshot().unwrap_err()] {
                assert!(error.to_string().contains("do not match this repository"));
                assert!(!error.to_string().contains("private-other-project"));
                assert!(e.db.connection().is_autocommit());
            }
            assert_eq!(
                e.db.get_index_metadata::<serde_json::Value>(&e.project_id)
                    .unwrap()
                    .unwrap(),
                corrupt
            );
            // A failed snapshot must leave a caller's transaction open and reversible.
            let tx = e.db.connection().unchecked_transaction().unwrap();
            assert!(e.snapshot().is_err());
            assert!(!e.db.connection().is_autocommit());
            tx.rollback().unwrap();
            let refreshed = e.index().unwrap();
            assert_eq!(refreshed.changed_files, 0);
            assert_eq!(refreshed.unchanged_files, 1);
            let after = e.snapshot().unwrap();
            assert_eq!(after.stats.project_id, e.project_id);
            assert_eq!(after.stats.repository, e.root.to_string_lossy());
            assert_eq!(
                serde_json::to_value(&after.files).unwrap(),
                serde_json::to_value(&before.files).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&after.edges).unwrap(),
                serde_json::to_value(&before.edges).unwrap()
            );
        }
    }
}

#[test]
fn index_stage_timings_survive_status_and_legacy_stats_keep_unknown_timings() {
    let f = Fixture::new();
    f.write("main.py", "def helper():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    let cold = e.index().unwrap();
    let timings = cold.timings.as_ref().unwrap();
    assert!(
        timings.source_read_ms.unwrap() + timings.source_extract_ms.unwrap()
            <= timings.source_refresh_ms
    );
    assert!(
        timings.source_refresh_ms + timings.relationship_analysis_ms + timings.persistence_ms
            <= cold.duration_ms
    );
    assert_eq!(
        serde_json::to_value(&cold).unwrap(),
        serde_json::to_value(e.status().unwrap().unwrap()).unwrap()
    );
    let warm = e.index().unwrap();
    assert_eq!(warm.changed_files, 0);
    assert!(warm.timings.is_some());
    assert_eq!(warm.timings.as_ref().unwrap().source_extract_ms, Some(0));
    let mut legacy = serde_json::to_value(warm).unwrap();
    let mut intermediate = legacy.clone();
    intermediate["timings"]
        .as_object_mut()
        .unwrap()
        .remove("source_read_ms");
    intermediate["timings"]
        .as_object_mut()
        .unwrap()
        .remove("source_extract_ms");
    let intermediate: sentinel_graph::IndexStats = serde_json::from_value(intermediate).unwrap();
    assert!(intermediate.timings.unwrap().source_read_ms.is_none());
    legacy.as_object_mut().unwrap().remove("timings");
    e.db.connection()
        .execute(
            "UPDATE index_metadata SET payload=?1 WHERE project_id=?2",
            rusqlite::params![legacy.to_string(), e.project_id],
        )
        .unwrap();
    assert!(e.status().unwrap().unwrap().timings.is_none());
    assert!(e.snapshot().unwrap().stats.timings.is_none());
    assert!(e.index().unwrap().timings.is_some());
}

#[test]
fn batched_source_reads_keep_lexical_budget_admission_and_ordered_failures() {
    let f = Fixture::new();
    let source = format!("#{}", " ".repeat(1024 * 1024 - 1));
    for i in 0..20 {
        f.write(&format!("unit_{i:02}.py"), &source);
    }
    std::fs::write(f.0.join("unit_02.py"), [0xff, 0xfe]).unwrap();
    let e = Engine::open(&f.0).unwrap();
    let stats = e.index().unwrap();
    assert!(!stats.complete);
    assert_eq!(stats.files_indexed, 16);
    assert!(stats.coverage_notes[0].contains("unit_02.py"));
    assert!(stats
        .coverage_notes
        .iter()
        .any(|note| note.contains("source read budget reached")));
    let snapshot = e.snapshot().unwrap();
    let paths = snapshot
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"unit_16.py"));
    assert!(!paths.contains(&"unit_17.py"));
    assert!(!paths.contains(&"unit_02.py"));
    assert!(snapshot.files.iter().all(
        |file| file.semantics_revision == sentinel_core::security::ANALYSIS_SEMANTICS_REVISION
    ));
    let repeat = e.index().unwrap();
    assert_eq!(repeat.changed_files, 0);
    assert_eq!(repeat.unchanged_files, 16);
    assert_eq!(repeat.coverage_notes, stats.coverage_notes);
    assert_eq!(
        e.snapshot()
            .unwrap()
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        paths
    );
}

#[test]
fn reused_edge_insert_rolls_back_partial_refresh_and_allows_retry() {
    let f = Fixture::new();
    f.write("main.py", "def before():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    e.index().unwrap();
    let original = e.snapshot().unwrap();
    f.write("main.py", "def after():\n    return 2\n");
    f.write("new.py", "def added():\n    return 3\n");
    e.db.connection().execute_batch("CREATE TEMP TRIGGER reject_edge_insert BEFORE INSERT ON symbol_edges BEGIN SELECT RAISE(ABORT,'test edge persistence failure'); END;").unwrap();
    assert!(e
        .index()
        .unwrap_err()
        .to_string()
        .contains("test edge persistence failure"));
    assert!(e.db.connection().is_autocommit());
    let rolled_back = e.snapshot().unwrap();
    assert_eq!(
        serde_json::to_value(&original.files).unwrap(),
        serde_json::to_value(&rolled_back.files).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&original.edges).unwrap(),
        serde_json::to_value(&rolled_back.edges).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&original.stats).unwrap(),
        serde_json::to_value(&rolled_back.stats).unwrap()
    );
    e.db.connection()
        .execute_batch("DROP TRIGGER reject_edge_insert")
        .unwrap();
    assert_eq!(e.index().unwrap().changed_files, 2);
    let refreshed = e.snapshot().unwrap();
    assert_eq!(refreshed.files.len(), 2);
    let ids = refreshed
        .files
        .iter()
        .flat_map(|file| &file.symbols)
        .map(|symbol| &symbol.id)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(refreshed
        .edges
        .iter()
        .filter(|edge| edge.kind == "DEFINES")
        .all(|edge| ids.contains(&edge.to)));
}

#[test]
fn diff_context_labels_unknown_missing_and_deleted_scope_and_bounds_changed_metadata() {
    use sentinel_graph::context::ContextEvidence;
    let f = Fixture::new();
    f.write("main.py", "def helper():\n    return 1\n");
    let e = Engine::open(&f.0).unwrap();
    assert!(!e.get_security_context("diff", 200).unwrap().complete);
    assert!(e.get_security_context("helper", 200).unwrap().complete);
    let git = |args: &[&str]| {
        let result = std::process::Command::new("git")
            .args([
                "-c",
                "core.hooksPath=.git/no-hooks",
                "-c",
                "commit.gpgsign=false",
                "-C",
            ])
            .arg(&f.0)
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "fixture@example.invalid"]);
    git(&["config", "user.name", "Fixture"]);
    git(&["add", "main.py"]);
    git(&["commit", "-qm", "baseline"]);
    assert!(e.get_security_context("diff", 200).unwrap().complete);
    f.write("main.py", "def helper():\n    return 2\n");
    let current_change = e.get_security_context("diff", 200).unwrap();
    assert!(current_change.complete);
    assert!(current_change.selected_items.iter().any(
        |item| matches!(&item.evidence, ContextEvidence::ChangedFile {file} if file == "main.py")
    ));
    std::fs::remove_file(f.0.join("main.py")).unwrap();
    let deleted = e.get_security_context("diff", 200).unwrap();
    assert!(!deleted.complete);
    assert!(deleted
        .coverage_notes
        .iter()
        .any(|note| note.contains("Deleted paths")));
    assert!(deleted.selected_items.iter().any(
        |item| matches!(&item.evidence, ContextEvidence::ChangedFile {file} if file == "main.py")
    ));
    f.write("main.py", "def helper():\n    return 1\n");
    for i in 0..201 {
        f.write(&format!("change_{i:03}.custom"), "configuration\n");
    }
    let unsupported = e.get_security_context("diff", 200).unwrap();
    assert!(!unsupported.complete);
    assert!(unsupported
        .coverage_notes
        .iter()
        .any(|note| note.contains("outside the current indexed scope")));
    let metadata_count = unsupported
        .selected_items
        .iter()
        .filter(|item| matches!(item.evidence, ContextEvidence::ChangedFile { .. }))
        .count();
    assert_eq!(unsupported.selected_items.len(), 200);
    assert!(metadata_count > 0 && metadata_count <= 200);
    // Higher-ranked evidence can displace change metadata; all omissions remain visible.
    assert_eq!(unsupported.omitted_count, 1 + (200 - metadata_count));
}

#[test]
fn large_file_context_keeps_unique_ranked_evidence_and_stable_truncation() {
    let f = Fixture::new();
    let source = (0..500)
        .map(|i| format!("def helper_{i}():\n    return {i}\n"))
        .collect::<String>();
    f.write("large.py", &source);
    let e = Engine::open(&f.0).unwrap();
    let first = e.get_security_context("large.py", 200).unwrap();
    let repeat = e.get_security_context("large.py", 200).unwrap();
    assert!(first.complete && first.omitted_count > 0);
    assert_eq!(first.selected_items.len(), 200);
    assert_eq!(first.target_symbols.len(), 200);
    assert_eq!(first.omitted_target_symbols, Some(301));
    assert_eq!(
        serde_json::to_value(&first.selected_items).unwrap(),
        serde_json::to_value(&repeat.selected_items).unwrap()
    );
    assert_eq!(first.omitted_count, repeat.omitted_count);
    assert_eq!(first.source_snapshot, repeat.source_snapshot);
    let focused = e.get_security_context("large.py", 1).unwrap();
    assert_eq!(focused.target_symbols.len(), 1);
    assert_eq!(focused.omitted_target_symbols, Some(500));
    assert_eq!(focused.source_snapshot, first.source_snapshot);
    let mut legacy = serde_json::to_value(&first).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("omitted_target_symbols");
    let legacy: sentinel_graph::context::SecurityContext = serde_json::from_value(legacy).unwrap();
    assert!(legacy.omitted_target_symbols.is_none());
    let mut evidence = std::collections::BTreeSet::new();
    for item in &first.selected_items {
        assert!(evidence.insert(serde_json::to_string(&item.evidence).unwrap()));
        let reasons = item
            .reason_selected
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(reasons.len(), item.reason_selected.len());
    }
    assert!(first
        .selected_items
        .windows(2)
        .all(|items| items[0].relevance_score >= items[1].relevance_score));
}
