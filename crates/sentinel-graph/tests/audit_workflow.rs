use sentinel_graph::{
    audit_workflow::{render_report, AuditRun},
    Engine,
};
use serde_json::{json, Value};
use std::path::PathBuf;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sentinel-audit-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("repo")).unwrap();
        std::fs::write(
            path.join("repo/app.py"),
            "def run(value):\n    return value\n",
        )
        .unwrap();
        Self(path)
    }
    fn engine(&self) -> Engine {
        Engine::open(self.0.join("repo")).unwrap()
    }
    fn run(&self) -> PathBuf {
        self.0.join("run")
    }
    fn save(&self, run: &AuditRun) {
        for (name, value) in [
            (
                "run-metadata.json",
                serde_json::to_value(&run.metadata).unwrap(),
            ),
            ("coverage-ledger.json", run.coverage.clone()),
            ("findings.json", run.findings.clone()),
            ("verification.json", run.verification.clone()),
        ] {
            std::fs::write(
                self.run().join(name),
                serde_json::to_vec_pretty(&value).unwrap(),
            )
            .unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let root = self.0.canonicalize().unwrap();
        assert!(root.starts_with(std::env::temp_dir().canonicalize().unwrap()));
        assert!(root
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("sentinel-audit-test-"));
        let _ = std::fs::remove_dir_all(root);
    }
}
#[test]
fn planned_run_is_partial_imports_persists_and_goes_stale() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let run = e.validate_audit_run(&f.run()).unwrap();
    assert_eq!(run.coverage.as_array().unwrap().len(), 1);
    let status = e.import_audit_run(&f.run()).unwrap();
    assert!(status.available && status.partial_coverage && !status.stale);
    assert_eq!(status.coverage_counts["planned"], 1);
    assert!(f
        .run()
        .join("skill/upstream/security-audit/AI-AND-LLM.md")
        .exists());
    std::fs::write(f.0.join("repo/app.py"), "def changed():\n    return 1\n").unwrap();
    assert!(e
        .validate_audit_run(&f.run())
        .unwrap_err()
        .to_string()
        .contains("stale"));
    assert!(f.engine().audit_status().unwrap().stale);
    assert!(render_report(&e.audit_status().unwrap())
        .unwrap()
        .contains("SOURCE CHANGED"));
}
#[test]
fn imports_preserve_revisions_are_idempotent_and_roll_back_on_failure() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let count = || {
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_revisions", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
    };
    assert_eq!(count(), 1);
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    run.findings = json!([candidate(&mut run, "needs_validation")]);
    f.save(&run);
    e.db.connection().execute_batch("CREATE TRIGGER reject_candidate BEFORE INSERT ON audit_candidates BEGIN SELECT RAISE(ABORT,'test interruption'); END;").unwrap();
    assert!(e.import_audit_run(&f.run()).is_err());
    assert_eq!(count(), 1);
    assert!(e.audit_status().unwrap().finding_counts.is_empty());
    e.db.connection()
        .execute_batch("DROP TRIGGER reject_candidate;")
        .unwrap();
    e.import_audit_run(&f.run()).unwrap();
    assert_eq!(count(), 2);
    let history = e.audit_history(1).unwrap();
    assert!(history.has_more && !history.source_freshness_checked);
    assert_eq!(history.revisions.len(), 1);
    assert!(history.revisions[0].is_latest);
    let history = e.audit_history(100).unwrap();
    assert!(!history.has_more);
    assert_eq!(history.revisions[0].run_id, history.revisions[1].run_id);
    assert_ne!(
        history.revisions[0].revision_id,
        history.revisions[1].revision_id
    );
    assert!(!history.revisions[1].is_latest);
    assert!(e.audit_history(101).is_err());
    assert_eq!(
        e.audit_status().unwrap().finding_counts["needs_validation"],
        1
    );
    assert_eq!(
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_coverage", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_candidates", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn schema_upgrade_preserves_legacy_audit_without_promoting_unvalidated_records() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let run = e.validate_audit_run(&f.run()).unwrap();
    e.db.set_memory(
        "audit-workflow.latest.v1",
        &serde_json::to_string(&run).unwrap(),
    )
    .unwrap();
    e.db.connection().execute_batch("DROP TABLE audit_reviews; DROP TABLE audit_candidates; DROP TABLE audit_attempts; DROP TABLE audit_coverage; DROP TABLE audit_latest; DROP TABLE audit_revisions; PRAGMA user_version=4;").unwrap();
    drop(e);
    let e = f.engine();
    assert!(e.audit_status().unwrap().available);
    assert_eq!(
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_revisions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    e.import_audit_run(&f.run()).unwrap();
    assert_eq!(
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_revisions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn output_and_input_bounds_and_schema_are_enforced() {
    let f = Fixture::new();
    let e = f.engine();
    let inside = f.0.join("repo/run");
    assert!(e.init_audit_run(&inside, vec![]).is_err());
    assert!(!inside.exists());
    e.init_audit_run(&f.run(), vec![]).unwrap();
    assert!(e.init_audit_run(&f.run(), vec![]).is_err());
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    run.coverage[0]["coverage_id"] = json!("made-up");
    f.save(&run);
    assert!(e
        .validate_audit_run(&f.run())
        .unwrap_err()
        .to_string()
        .contains("schema"));
    std::fs::write(
        f.run().join("findings.json"),
        vec![b' '; 2 * 1024 * 1024 + 1],
    )
    .unwrap();
    assert!(e.validate_audit_run(&f.run()).is_err());
}
fn candidate(run: &mut AuditRun, verdict: &str) -> Value {
    let loc = json!({"file":"app.py","line":1,"description":"The entry point accepts caller-controlled values."});
    run.coverage[0]["status"] = json!("candidate");
    run.coverage[0]["agent_id"] = json!("hunter-1");
    run.coverage[0]["reviewed_paths"] = json!(["app.py"]);
    run.coverage[0]["result_fingerprints"] = json!(["app-test"]);
    run.coverage[0]["local_checks"] = json!([{"agent_id":"hunter-1","reviewed_paths":["app.py"],"invariant":"Input is validated before a protected operation.","method":"source","result":"Source trace examined; runtime effect requires independent validation.","artifact":null}]);
    json!({"verdict":verdict,"fingerprint":"app-test","title":"Test candidate","description":"A candidate for a protected boundary failure.","claimed_root_cause":"The entry point may omit a required check.","trace":[{"kind":"entrypoint","file":"app.py","line":1,"scope":"run","description":"Input arrives at run."},{"kind":"sink","file":"app.py","line":2,"scope":"run","description":"Value reaches the return."}],"evidence":[loc],"blockers":["No isolated runtime reproduction is available."],"validation_plan":{"local":"Validate in an OS-enforced sandbox with dummy values."}})
}
#[test]
fn candidates_require_accounting_and_confirmations_require_independent_sandbox_attestation() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    let mut finding = candidate(&mut run, "needs_validation");
    run.findings = json!([finding.clone()]);
    f.save(&run);
    e.validate_audit_run(&f.run()).unwrap();
    run.coverage[0]["result_fingerprints"] = json!(["unaccounted"]);
    f.save(&run);
    assert!(e.validate_audit_run(&f.run()).is_err());
    run.coverage[0]["result_fingerprints"] = json!(["app-test"]);
    finding["verdict"] = json!("confirmed");
    let obj = finding.as_object_mut().unwrap();
    obj.remove("claimed_root_cause");
    obj.remove("blockers");
    obj.remove("validation_plan");
    obj.insert(
        "root_cause".into(),
        json!("A required validation check is missing."),
    );
    obj.insert(
        "intended_behavior".into(),
        json!("Validate before changing protected state."),
    );
    obj.insert("conditions".into(), json!([]));
    obj.insert("execution".into(),json!({"attacker_perspective":"A dummy unprivileged local user.","payloads":["dummy value"],"instructions":["Send the dummy value to the isolated fixture."],"observed_result":"Dummy protected state changed."}));
    obj.insert(
        "remediation".into(),
        json!({"strategy":"Validate ownership before changing state."}),
    );
    obj.insert("severity".into(),json!({"likelihood":{"score":"medium","reason":"The entry point is reachable."},"impact":{"score":"medium","reason":"One dummy object changes."},"overall_severity":"medium"}));
    obj.insert(
        "confidence".into(),
        json!({"score":"high","reason":"The bounded fixture was independently reviewed."}),
    );
    run.findings = json!([finding]);
    f.save(&run);
    assert!(e
        .validate_audit_run(&f.run())
        .unwrap_err()
        .to_string()
        .contains("attestation"));
    run.verification = json!([{"fingerprint":"app-test","discoverer":"hunter-1","verifier":"hunter-1","source_snapshot":run.metadata.source_snapshot,"method":"sandboxed-local","observed_result":"Dummy protected state changed.","sandbox":{"network_disabled":true,"environment_allowlisted":true,"read_only_target":true,"scratch_only_writes":true,"resource_limited":true,"limits":"Recorded dummy test limits, 1 second."}}]);
    f.save(&run);
    assert!(e.validate_audit_run(&f.run()).is_err());
    run.verification[0]["verifier"] = json!("verifier-1");
    f.save(&run);
    e.validate_audit_run(&f.run()).unwrap();
    run.verification[0]["sandbox"]["network_disabled"] = json!(false);
    f.save(&run);
    assert!(e.validate_audit_run(&f.run()).is_err());
}
#[test]
fn complete_claims_and_evidence_locations_are_checked() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    run.metadata.run_status = "complete".into();
    f.save(&run);
    assert!(e.validate_audit_run(&f.run()).is_err());
    run.metadata.run_status = "in_progress".into();
    let mut finding = candidate(&mut run, "needs_validation");
    finding["evidence"][0]["line"] = json!(999);
    run.findings = json!([finding]);
    f.save(&run);
    assert!(e
        .validate_audit_run(&f.run())
        .unwrap_err()
        .to_string()
        .contains("line"));
    run.findings[0]["evidence"][0]["line"] = json!(1);
    run.findings[0]["trace"][0]["file"] = json!("../outside.py");
    f.save(&run);
    assert!(e.validate_audit_run(&f.run()).is_err());
}
#[test]
fn explicit_hidden_files_and_lexicographic_units_are_supported() {
    let f = Fixture::new();
    let e = f.engine();
    std::fs::write(f.0.join("repo/.policy"), "restricted=true\n").unwrap();
    std::fs::write(f.0.join("repo/src.py"), "def root():\n    return 1\n").unwrap();
    std::fs::create_dir(f.0.join("repo/src")).unwrap();
    std::fs::write(
        f.0.join("repo/src/nested.py"),
        "def nested():\n    return 1\n",
    )
    .unwrap();
    let metadata = e.init_audit_run(&f.run(), vec![".policy".into()]).unwrap();
    assert!(metadata.source_manifest.contains_key(".policy"));
    assert_eq!(
        e.validate_audit_run(&f.run())
            .unwrap()
            .coverage
            .as_array()
            .unwrap()
            .len(),
        3
    );
    e.import_audit_run(&f.run()).unwrap();
    std::fs::write(f.0.join("repo/.policy"), "restricted=false\n").unwrap();
    assert!(e.audit_status().unwrap().stale);
}
#[test]
fn malformed_record_diagnostics_do_not_echo_terminal_controls() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    run.coverage[0]["result_fingerprints"] = json!(["\u{1b}[2Jhidden"]);
    f.save(&run);
    let error = e.validate_audit_run(&f.run()).unwrap_err().to_string();
    assert!(!error.contains('\u{1b}'));
    run.coverage[0]["result_fingerprints"] = json!([]);
    run.coverage[0]["starting_paths"] = json!(["\u{1b}[2Jhidden"]);
    f.save(&run);
    let error = e.validate_audit_run(&f.run()).unwrap_err().to_string();
    assert!(!error.contains('\u{1b}'));
}
