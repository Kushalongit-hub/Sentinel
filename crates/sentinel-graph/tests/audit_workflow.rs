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
            "sentinel-audit-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
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
        4 // The explicitly included policy receives its own planned review unit.
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

#[test]
fn artifact_descriptors_are_revision_scoped_and_transactional() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let run = e.validate_audit_run(&f.run()).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    let artifacts = e.audit_artifacts(&revision).unwrap();
    assert_eq!(artifacts.len(), 4);
    let findings = artifacts
        .iter()
        .find(|a| a.name == "findings.json")
        .unwrap();
    assert_eq!(
        findings.content_hash,
        sentinel_core::security::identity(&run.findings)
    );
    assert_eq!(
        findings.size_bytes,
        serde_json::to_vec(&run.findings).unwrap().len()
    );
    assert!(artifacts
        .iter()
        .all(|a| !a.execution_observed && a.source_snapshot == run.metadata.source_snapshot));
    e.import_audit_run(&f.run()).unwrap();
    assert_eq!(
        e.db.connection()
            .query_row("SELECT count(*) FROM audit_artifacts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert!(e.audit_artifacts("../outside").is_err());
    assert!(e.audit_artifacts(&"f".repeat(64)).is_err());
    let other = Fixture::new();
    assert!(other.engine().audit_artifacts(&revision).is_err());
    let mut changed = run;
    changed.findings = json!([candidate(&mut changed, "needs_validation")]);
    f.save(&changed);
    e.db.connection().execute_batch("CREATE TRIGGER reject_artifact BEFORE INSERT ON audit_artifacts BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(e.import_audit_run(&f.run()).is_err());
    assert_eq!(e.audit_history(100).unwrap().revisions.len(), 1);
    assert_eq!(
        e.audit_history(1).unwrap().revisions[0].revision_id,
        revision
    );
}
#[test]
fn version_six_upgrade_describes_retained_payload_without_original_files() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    let expected = e.audit_artifacts(&revision).unwrap();
    e.db.connection()
        .execute_batch("DROP TABLE audit_artifacts; PRAGMA user_version=6;")
        .unwrap();
    drop(e);
    std::fs::remove_dir_all(f.run()).unwrap();
    let e = f.engine();
    let actual = e.audit_artifacts(&revision).unwrap();
    assert_eq!(actual.len(), 4);
    for item in actual {
        assert!(expected.contains(&item));
    }
    assert_eq!(
        e.db.connection()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(
        e.audit_history(1).unwrap().revisions[0].revision_id,
        revision
    );
}

#[test]
fn legacy_export_requires_explicit_revalidation_and_preserves_memory() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let run = e.validate_audit_run(&f.run()).unwrap();
    let encoded = serde_json::to_string(&run).unwrap();
    e.db.set_memory("audit-workflow.latest.v1", &encoded)
        .unwrap();
    let output = f.0.join("recovered");
    e.export_legacy_audit_run(&output).unwrap();
    assert!(e.audit_history(20).unwrap().revisions.is_empty());
    assert_eq!(
        e.db.get_memory("audit-workflow.latest.v1")
            .unwrap()
            .unwrap(),
        encoded
    );
    assert!(e.export_legacy_audit_run(&output).is_err());
    assert!(e
        .export_legacy_audit_run(&f.0.join("repo/forbidden"))
        .is_err());
    e.validate_audit_run(&output).unwrap();
    std::fs::write(f.0.join("repo/app.py"), "def changed():\n    return 1\n").unwrap();
    assert!(e.import_audit_run(&output).is_err());
    assert!(e.audit_history(20).unwrap().revisions.is_empty());
}

#[test]
fn retained_revision_details_survive_source_changes_and_reject_payload_corruption() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let first = e.validate_audit_run(&f.run()).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    let mut second = first.clone();
    second.metadata.incomplete_reason = Some("second imported revision".into());
    f.save(&second);
    e.import_audit_run(&f.run()).unwrap();
    let latest = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    assert_ne!(latest, revision);
    std::fs::remove_dir_all(f.run()).unwrap();
    std::fs::write(f.0.join("repo/app.py"), "def changed():\n    return 2\n").unwrap();
    let detail = e.audit_revision(&revision).unwrap();
    assert!(!detail.source_freshness_checked);
    assert!(!detail.execution_observed);
    assert_eq!(
        serde_json::to_value(detail.run).unwrap(),
        serde_json::to_value(&first).unwrap()
    );
    assert_eq!(e.audit_history(1).unwrap().revisions[0].revision_id, latest);
    assert!(e.audit_revision("../outside").is_err());
    assert!(Fixture::new().engine().audit_revision(&revision).is_err());
    e.db.connection()
        .execute(
            "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
            rusqlite::params![serde_json::to_string(&second).unwrap(), revision],
        )
        .unwrap();
    assert!(e.audit_revision(&revision).is_err());
    assert!(e.audit_artifacts(&revision).is_err());
    e.db.connection()
        .execute(
            "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
            rusqlite::params![" ".repeat(2 * 1024 * 1024 + 1), revision],
        )
        .unwrap();
    assert!(e
        .audit_revision(&revision)
        .unwrap_err()
        .to_string()
        .contains("size limit"));
}

#[test]
fn stored_audit_reads_enforce_byte_limits_and_latest_identity_without_legacy_fallback() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    let original: String =
        e.db.connection()
            .query_row(
                "SELECT payload FROM audit_revisions WHERE revision_id=?1",
                [&revision],
                |row| row.get(0),
            )
            .unwrap();
    // Modern status ignores legacy content instead of eagerly loading it.
    e.db.set_memory("audit-workflow.latest.v1", &"é".repeat(1024 * 1024 + 1))
        .unwrap();
    assert!(e.audit_status().unwrap().available);
    for payload in [" ".repeat(2 * 1024 * 1024 + 1), "é".repeat(1024 * 1024 + 1)] {
        e.db.connection()
            .execute(
                "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
                rusqlite::params![payload, revision],
            )
            .unwrap();
        assert!(e
            .audit_revision(&revision)
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert!(e
            .audit_status()
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert!(e.audit_artifacts(&revision).is_err());
    }
    e.db.connection()
        .execute(
            "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
            rusqlite::params![original, revision],
        )
        .unwrap();
    let mut changed: serde_json::Value = serde_json::from_str(&original).unwrap();
    changed["metadata"]["run_id"] = serde_json::json!("corrupted-run");
    e.db.connection()
        .execute(
            "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
            rusqlite::params![changed.to_string(), revision],
        )
        .unwrap();
    assert!(e
        .audit_status()
        .unwrap_err()
        .to_string()
        .contains("revision identity"));
    e.db.connection()
        .execute(
            "UPDATE audit_revisions SET payload=?1 WHERE revision_id=?2",
            rusqlite::params![original, revision],
        )
        .unwrap();
    e.db.connection().execute("INSERT INTO audit_artifacts(project_id,revision_id,name,payload) VALUES(?1,?2,'zz-extra','{}')", rusqlite::params![e.project_id, revision]).unwrap();
    assert!(e
        .audit_artifacts(&revision)
        .unwrap_err()
        .to_string()
        .contains("count exceeds"));
    e.db.connection()
        .execute(
            "DELETE FROM audit_artifacts WHERE revision_id=?1 AND name='zz-extra'",
            [&revision],
        )
        .unwrap();
    e.db.connection()
        .execute(
            "UPDATE audit_artifacts SET payload=?1 WHERE revision_id=?2",
            rusqlite::params!["é".repeat(1024 * 1024 + 1), revision],
        )
        .unwrap();
    assert!(e
        .audit_artifacts(&revision)
        .unwrap_err()
        .to_string()
        .contains("size limit"));
    e.db.connection()
        .execute(
            "DELETE FROM audit_latest WHERE project_id=?1",
            [&e.project_id],
        )
        .unwrap();
    assert!(e
        .audit_status()
        .unwrap_err()
        .to_string()
        .contains("size limit"));
}

#[test]
fn legacy_export_and_status_share_bounded_repository_validation_before_writes() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    let output = f.0.join("recovered");
    for value in [" ".repeat(2 * 1024 * 1024 + 1), "é".repeat(1024 * 1024 + 1)] {
        e.db.set_memory("audit-workflow.latest.v1", &value).unwrap();
        assert!(e
            .export_legacy_audit_run(&output)
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert!(e
            .audit_status()
            .unwrap_err()
            .to_string()
            .contains("size limit"));
        assert!(!output.exists());
        assert_eq!(
            e.db.get_memory("audit-workflow.latest.v1")
                .unwrap()
                .unwrap(),
            value
        );
    }
    run.metadata.repo = "another-repository".into();
    e.db.set_memory(
        "audit-workflow.latest.v1",
        &serde_json::to_string(&run).unwrap(),
    )
    .unwrap();
    assert!(e
        .export_legacy_audit_run(&output)
        .unwrap_err()
        .to_string()
        .contains("another repository"));
    assert!(e
        .audit_status()
        .unwrap_err()
        .to_string()
        .contains("another repository"));
    assert!(!output.exists());
    assert!(e.audit_history(20).unwrap().revisions.is_empty());
}

#[test]
fn planned_coverage_includes_all_selected_text_surfaces_without_static_coverage_claims() {
    use std::collections::BTreeSet;
    let f = Fixture::new();
    std::fs::write(f.0.join("repo/app.py"), "def broken(:\n").unwrap();
    for (name, source) in [
        ("README.md", "# Threat boundaries\n"),
        ("settings.custom", "permissions = unrestricted\n"),
        (".agent.json", "{}\n"),
        ("Cargo.lock", "version = 4\n"),
    ] {
        std::fs::write(f.0.join("repo").join(name), source).unwrap();
    }
    std::fs::write(f.0.join("repo/opaque.bin"), [0xff, 0xfe]).unwrap();
    let e = f.engine();
    let metadata = e
        .init_audit_run(
            &f.run(),
            vec![
                "README.md".into(),
                "settings.custom".into(),
                ".agent.json".into(),
                "Cargo.lock".into(),
                "opaque.bin".into(),
            ],
        )
        .unwrap();
    let expected: BTreeSet<_> = [
        "app.py",
        "README.md",
        "settings.custom",
        ".agent.json",
        "Cargo.lock",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        metadata
            .source_manifest
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(metadata
        .snapshot_notes
        .iter()
        .any(|note| note.contains("Non-UTF8 file omitted: opaque.bin")));
    let run = e.validate_audit_run(&f.run()).unwrap();
    let units = run.coverage.as_array().unwrap();
    let planned = units
        .iter()
        .map(|unit| {
            assert_eq!(unit["status"], "planned");
            assert!(unit["attempts"].as_array().unwrap().is_empty());
            assert!(unit["reviewed_paths"].as_array().unwrap().is_empty());
            assert_eq!(unit["starting_paths"].as_array().unwrap().len(), 1);
            unit["starting_paths"][0].as_str().unwrap().to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(planned, expected);
    assert_eq!(units.len(), expected.len());
    let index: Value =
        serde_json::from_slice(&std::fs::read(f.run().join("index-evidence.json")).unwrap())
            .unwrap();
    assert_eq!(index["complete"], false);
    assert_eq!(index["files_indexed"], 0);
    let status = e.import_audit_run(&f.run()).unwrap();
    assert!(status.partial_coverage);
    assert_eq!(status.coverage_counts["planned"], expected.len());
}

#[test]
fn complete_audits_account_for_selected_paths_and_status_requires_reviewed_coverage() {
    let f = Fixture::new();
    std::fs::write(f.0.join("repo/extra.py"), "VALUE = 1\n").unwrap();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    let _ = candidate(&mut run, "needs_validation");
    run.coverage[0]["status"] = json!("covered");
    run.coverage[0]["result_fingerprints"] = json!([]);
    run.coverage.as_array_mut().unwrap().truncate(1);
    run.metadata.run_status = "complete".into();
    f.save(&run);
    assert!(e
        .validate_audit_run(&f.run())
        .unwrap_err()
        .to_string()
        .contains("omits selected source paths"));
    assert!(e.import_audit_run(&f.run()).is_err());
    assert!(e.audit_history(20).unwrap().revisions.is_empty());
    // Previously retained legacy attestations must also stay partial when paths disappear.
    e.db.set_memory(
        "audit-workflow.latest.v1",
        &serde_json::to_string(&run).unwrap(),
    )
    .unwrap();
    assert!(e.audit_status().unwrap().partial_coverage);
    // A merged unit may account for both paths without claiming both were reviewed.
    run.coverage[0]["starting_paths"] = json!(["app.py", "extra.py"]);
    f.save(&run);
    e.validate_audit_run(&f.run()).unwrap();
    assert!(e.import_audit_run(&f.run()).unwrap().partial_coverage);
    run.coverage[0]["reviewed_paths"] = json!(["app.py", "extra.py"]);
    run.coverage[0]["local_checks"][0]["reviewed_paths"] = json!(["app.py", "extra.py"]);
    f.save(&run);
    assert!(!e.import_audit_run(&f.run()).unwrap().partial_coverage);
    assert_eq!(e.audit_status().unwrap().coverage_counts["covered"], 1);
}

#[test]
fn legacy_status_does_not_report_fresh_coverage_for_an_inconsistent_source_identity() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    let mut run = e.validate_audit_run(&f.run()).unwrap();
    let _ = candidate(&mut run, "needs_validation");
    run.coverage[0]["status"] = json!("covered");
    run.coverage[0]["result_fingerprints"] = json!([]);
    run.metadata.run_status = "complete".into();
    f.save(&run);
    e.validate_audit_run(&f.run()).unwrap();
    let original = run.metadata.source_snapshot.clone();
    e.db.set_memory(
        "audit-workflow.latest.v1",
        &serde_json::to_string(&run).unwrap(),
    )
    .unwrap();
    assert!(!e.audit_status().unwrap().stale);
    assert!(!e.audit_status().unwrap().partial_coverage);
    for invalid in ["".to_owned(), "0".repeat(64)] {
        run.metadata.source_snapshot = invalid;
        let encoded = serde_json::to_string(&run).unwrap();
        e.db.set_memory("audit-workflow.latest.v1", &encoded)
            .unwrap();
        let status = e.audit_status().unwrap();
        assert!(status.stale && status.partial_coverage);
        assert!(status
            .notes
            .iter()
            .any(|note| note.contains("STORED SNAPSHOT INCONSISTENT")));
        assert_eq!(
            e.db.get_memory("audit-workflow.latest.v1")
                .unwrap()
                .unwrap(),
            encoded
        );
    }
    // Recovery preserves invalid legacy records for explicit correction/revalidation.
    let recovered = f.0.join("recovered-invalid-identity");
    e.export_legacy_audit_run(&recovered).unwrap();
    assert!(e.validate_audit_run(&recovered).is_err());
    assert!(e.audit_history(20).unwrap().revisions.is_empty());
    run.metadata.source_snapshot = original;
    e.db.set_memory(
        "audit-workflow.latest.v1",
        &serde_json::to_string(&run).unwrap(),
    )
    .unwrap();
    assert!(!e.audit_status().unwrap().stale);
    assert!(!e.audit_status().unwrap().partial_coverage);
}

#[test]
fn audit_history_bounds_metadata_before_returning_retained_summaries() {
    let f = Fixture::new();
    let e = f.engine();
    e.init_audit_run(&f.run(), vec![]).unwrap();
    e.import_audit_run(&f.run()).unwrap();
    let history = e.audit_history(20).unwrap();
    let original = &history.revisions[0];
    let revision = original.revision_id.clone();
    for (column, restored) in [
        ("run_id", original.run_id.clone()),
        ("source_snapshot", original.source_snapshot.clone()),
        ("status", original.run_status.clone()),
        ("imported_at", original.imported_at.clone()),
    ] {
        for invalid in [
            "x".repeat(1024 * 1024),
            "\u{e9}".repeat(1024 * 1024),
            "\u{1b}[2J".into(),
        ] {
            e.db.connection()
                .execute(
                    &format!("UPDATE audit_revisions SET {column}=?1 WHERE revision_id=?2"),
                    rusqlite::params![invalid, revision],
                )
                .unwrap();
            assert!(e.audit_history(20).is_err(), "{column}");
        }
        e.db.connection()
            .execute(
                &format!("UPDATE audit_revisions SET {column}=?1 WHERE revision_id=?2"),
                rusqlite::params![restored, revision],
            )
            .unwrap();
    }
    let restored = e.audit_history(20).unwrap();
    assert_eq!(restored.revisions.len(), 1);
    assert_eq!(restored.revisions[0].revision_id, revision);
    assert!(restored.revisions[0].is_latest);
    assert!(!restored.source_freshness_checked);
    assert!(e.audit_revision(&revision).is_ok());
}
