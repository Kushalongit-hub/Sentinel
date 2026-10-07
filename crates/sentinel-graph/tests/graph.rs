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
            "sentinel-graph-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
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
