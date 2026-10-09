use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("sentinel-cli-{}-{}", std::process::id(), {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        }));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) {
        std::fs::write(self.0.join(name), bytes).unwrap();
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }
    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    fn repo(&self) {
        self.git(&["init"]);
        self.git(&["config", "user.name", "Fixture"]);
        self.git(&["config", "user.email", "fixture@example.invalid"]);
        self.write(".gitignore", ".sentinel.db*\n");
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
                .starts_with("sentinel-cli-")
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
fn report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON {e}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}
#[test]
fn codebase_context_preview_is_provider_independent_and_has_no_database_side_effect() {
    let fixture = Fixture::new();
    fixture.write("main.rs", "fn main() {}\n");
    fixture.write("README.md", "# Fixture\nA simple executable.\n");
    let local = fixture.run(&[
        "explain-codebase",
        ".",
        "--context-only",
        "--provider",
        "local",
    ]);
    let both = fixture.run(&[
        "explain-codebase",
        ".",
        "--context-only",
        "--provider",
        "both",
    ]);
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    assert!(
        both.status.success(),
        "{}",
        String::from_utf8_lossy(&both.stderr)
    );
    assert_eq!(report(&local), report(&both));
    assert!(!fixture.0.join(".sentinel.db").exists());
    assert!(
        report(&both)["context"]["excerpts"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
}
#[test]
fn finding_context_contains_the_actual_finding_line() {
    let fixture = Fixture::new();
    let mut source = "import hashlib\n".to_string();
    source.push_str(&"pass\n".repeat(200));
    source.push_str("hashlib.md5(data)\n");
    fixture.write("example.py", source);
    let scan = fixture.run(&["audit", ".", "--format", "json"]);
    let scan_report = report(&scan);
    let id = scan_report["findings"][0]["id"].as_str().unwrap();
    let preview = fixture.run(&["explain", id, "--context-only"]);
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stderr)
    );
    assert!(preview
        .stdout
        .windows(b"202: hashlib.md5(data)".len())
        .any(|w| w == b"202: hashlib.md5(data)"));
}
fn timed_output(command: &mut Command) -> Output {
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("CLI did not terminate");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}
#[test]
fn relocated_binary_uses_embedded_rules_and_json() {
    let f = Fixture::new();
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    let exe = f.0.join(if cfg!(windows) {
        "relocated.exe"
    } else {
        "relocated"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_sentinel"), &exe).unwrap();
    let out = Command::new(exe)
        .current_dir(&f.0)
        .args(["audit", ".", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let r = report(&out);
    assert_eq!(r["outcome"], "Complete");
    assert_eq!(r["findings"][0]["title"], "rust-unsafe-usage");
}
#[test]
fn invalid_source_has_incomplete_exit_code() {
    let f = Fixture::new();
    f.write("bad.js", [255]);
    let out = f.run(&["audit", ".", "--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(report(&out)["outcome"], "Incomplete");
}
#[test]
fn single_file_audit_and_threshold_work() {
    let f = Fixture::new();
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    let out = f.run(&["audit", "bad.rs", "--format", "json", "--threshold", "high"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(f.0.join(".sentinel.db").is_file());
    assert!(!report(&out)["findings"].as_array().unwrap().is_empty());
}
#[test]
fn repeat_scans_resolve_and_reactivate_without_duplicates() {
    let f = Fixture::new();
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    for _ in 0..2 {
        assert_eq!(
            f.run(&["audit", ".", "--format", "json"]).status.code(),
            Some(1)
        );
    }
    let conn = rusqlite::Connection::open(f.0.join(".sentinel.db")).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM findings", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    f.write("bad.rs", "fn f(){work();}");
    assert!(f.run(&["audit", ".", "--format", "json"]).status.success());
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM findings WHERE resolved_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    assert_eq!(
        f.run(&["audit", ".", "--format", "json"]).status.code(),
        Some(1)
    );
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM findings WHERE resolved_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM scan_findings", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        3
    );
}
#[test]
fn persistence_failure_rolls_back_scan_and_changes_outcome() {
    let f = Fixture::new();
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    let path = f.0.join(".sentinel.db");
    let _ = sentinel_db::SentinelDb::new(path.to_str().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_findings BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let out = f.run(&["audit", ".", "--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(report(&out)["outcome"], "Incomplete");
    assert_eq!(
        conn.query_row("SELECT count(*) FROM scans", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn diff_includes_staged_unstaged_and_untracked_from_subdirectory() {
    let f = Fixture::new();
    f.repo();
    f.write("staged.rs", "fn f(){}");
    f.write("unstaged.rs", "fn f(){}");
    f.git(&["add", "."]);
    f.git(&["commit", "-m", "fixture"]);
    f.write("staged.rs", "fn f(){unsafe{work();}}");
    f.git(&["add", "staged.rs"]);
    f.write("unstaged.rs", "fn f(){unsafe{work();}}");
    f.write("untracked.rs", "fn f(){unsafe{work();}}");
    std::fs::create_dir(f.0.join("sub")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(f.0.join("sub"))
        .args(["diff", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(report(&out)["findings"].as_array().unwrap().len(), 3);
    let staged = f.run(&["diff", "--staged", "--format", "json"]);
    assert_eq!(report(&staged)["findings"].as_array().unwrap().len(), 1);
}
#[test]
fn diff_does_not_resolve_unselected_files() {
    let f = Fixture::new();
    f.repo();
    f.write("a.rs", "fn f(){unsafe{work();}}");
    f.write("b.rs", "fn f(){unsafe{work();}}");
    f.git(&["add", "."]);
    f.git(&["commit", "-m", "fixture"]);
    f.run(&["audit", ".", "--format", "json"]);
    f.write("a.rs", "fn f(){work();}");
    f.git(&["add", "a.rs"]);
    assert!(f
        .run(&["diff", "--staged", "--format", "json"])
        .status
        .success());
    let conn = rusqlite::Connection::open(f.0.join(".sentinel.db")).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM findings WHERE resolved_at IS NULL",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
#[test]
fn tui_exits_on_eof_and_survives_findings() {
    let f = Fixture::new();
    let out = timed_output(
        Command::new(env!("CARGO_BIN_EXE_sentinel"))
            .current_dir(&f.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert!(out.status.success());
    f.write("bad.rs", "fn f(){unsafe{work();}}");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(&f.0)
        .arg("tui")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"1\n.\n5\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Exiting."));
}

#[test]
fn mcp_stdio_indexes_traces_retrieves_and_rejects_scope_escape() {
    use std::io::{BufRead, BufReader};
    let f = Fixture::new();
    f.repo();
    f.write("routes.py", "from service import create_user\ndef handler(request):\n    return create_user(request.args['name'])\n");
    f.write("service.py", "from repository import insert_user\ndef create_user(value):\n    return insert_user(value)\n");
    f.write(
        "repository.py",
        "def insert_user(value):\n    cursor.execute('SELECT ' + value)\n",
    );
    f.git(&["add", "."]);
    f.git(&["commit", "-m", "fixture"]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(&f.0)
        .args(["mcp", "--repository", "."])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let mut id = 0;
    let mut request = |method: &str, params: serde_json::Value| {
        if method.starts_with("notifications/") {
            writeln!(
                input,
                "{}",
                serde_json::json!({"jsonrpc":"2.0","method":method,"params":params})
            )
            .unwrap();
            return serde_json::Value::Null;
        }
        id += 1;
        writeln!(
            input,
            "{}",
            serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )
        .unwrap();
        loop {
            let line = receiver
                .recv_timeout(Duration::from_secs(20))
                .unwrap_or_else(|e| {
                    let _ = child.kill();
                    panic!("MCP request timed out: {e}");
                });
            let json: serde_json::Value =
                serde_json::from_str(&line).expect("MCP stdout must contain JSON only");
            if json["id"] == id {
                return json;
            }
        }
    };
    let initialized = request(
        "initialize",
        serde_json::json!({"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"sentinel-test","version":"1"}}),
    );
    assert!(initialized.get("result").is_some(), "{initialized}");
    request("notifications/initialized", serde_json::json!({}));
    let tools = request("tools/list", serde_json::json!({}));
    assert!(
        tools["result"]["tools"].as_array().unwrap().len() == 13,
        "{tools}"
    );
    assert!(tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .all(|tool| tool["inputSchema"]["type"] == "object"));
    let workflow = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_workflow","arguments":{}}),
    );
    assert_eq!(
        workflow["result"]["structuredContent"]["target_execution"],
        false
    );
    assert!(workflow["result"]["structuredContent"]["skill"]
        .as_str()
        .unwrap()
        .contains("sentinel_trace_taint"));
    let audit_status = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_status","arguments":{}}),
    );
    assert_eq!(
        audit_status["result"]["structuredContent"]["available"],
        false
    );
    assert_eq!(
        audit_status["result"]["structuredContent"]["partial_coverage"],
        true
    );
    let indexed = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_index_project","arguments":{"path":"."}}),
    );
    let history = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_history","arguments":{"limit":1}}),
    );
    assert_eq!(
        history["result"]["structuredContent"]["revisions"],
        serde_json::json!([])
    );
    let invalid_history = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_history","arguments":{"limit":101}}),
    );
    assert_eq!(invalid_history["result"]["isError"], true);
    assert_eq!(
        indexed["result"]["structuredContent"]["files_indexed"], 3,
        "{indexed}"
    );
    let context = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_security_context","arguments":{"repository":".","target":"create_user","max_items":40}}),
    );
    assert!(!context["result"]["structuredContent"]["selected_items"]
        .as_array()
        .unwrap()
        .is_empty());
    let trace = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_trace_taint","arguments":{"repository":".","target":"create_user"}}),
    );
    assert_eq!(
        trace["result"]["structuredContent"]["paths"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "{trace}"
    );
    let scan = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_scan_file","arguments":{"path":"repository.py"}}),
    );
    let finding = scan["result"]["structuredContent"]["report"]["findings"][0]["id"]
        .as_str()
        .unwrap();
    let evidence = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_explain_finding","arguments":{"finding_id":finding}}),
    );
    assert!(
        evidence["result"]["structuredContent"]["why"].is_string(),
        "{evidence}"
    );
    let outside = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_security_context","arguments":{"repository":"..","target":"create_user"}}),
    );
    assert_eq!(outside["result"]["isError"], true);
    let diff = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_scan_diff","arguments":{"repository":"."}}),
    );
    assert!(
        diff["result"]["structuredContent"]["new_findings"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{diff}"
    );
    for name in [
        "sentinel_find_symbol",
        "sentinel_get_callers",
        "sentinel_get_callees",
    ] {
        let args = if name == "sentinel_find_symbol" {
            serde_json::json!({"repository":".","query":"create_user"})
        } else {
            serde_json::json!({"repository":".","target":"create_user"})
        };
        let result = request(
            "tools/call",
            serde_json::json!({"name":name,"arguments":args}),
        );
        assert!(
            result["result"]["structuredContent"]["symbols"].is_array(),
            "{result}"
        );
    }
    let verified = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_verify_patch","arguments":{"repository":"."}}),
    );
    assert_eq!(
        verified["result"]["structuredContent"]["verdict"], "PASS",
        "{verified}"
    );
    std::fs::write(
        f.0.join("repository.py"),
        "def insert_user(value):\n    cursor.execute('SELECT ?', (value,))\n",
    )
    .unwrap();
    let fixed = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_verify_patch","arguments":{"repository":"."}}),
    );
    assert_eq!(
        fixed["result"]["structuredContent"]["verdict"], "PASS",
        "{fixed}"
    );
    assert!(!fixed["result"]["structuredContent"]["resolved_findings"]
        .as_array()
        .unwrap()
        .is_empty());
    std::fs::write(
        f.0.join("repository.py"),
        "def insert_user(value):\n    subprocess.run(value, shell=True)\n",
    )
    .unwrap();
    let regressed = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_verify_patch","arguments":{"repository":"."}}),
    );
    assert_eq!(
        regressed["result"]["structuredContent"]["verdict"], "FAIL",
        "{regressed}"
    );
    assert!(
        !regressed["result"]["structuredContent"]["changed_taint_paths"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let bad_limit = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_trace_taint","arguments":{"repository":".","target":"create_user","max_paths":0}}),
    );
    assert_eq!(bad_limit["result"]["isError"], true, "{bad_limit}");
    drop(request);
    drop(input);
    let deadline = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if deadline.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            panic!("MCP did not shut down on stdin EOF");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    reader.join().unwrap();
}
#[test]
fn rules_list_actual_catalog_without_creating_database() {
    let f = Fixture::new();
    let out = f.run(&["rules"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 22);
    assert!(!f.0.join(".sentinel.db").exists());
}
#[test]
fn sarif_has_stable_rule_and_valid_locations() {
    let f = Fixture::new();
    f.write("bad file.rs", "fn f(){unsafe{work();}}");
    let out = f.run(&["audit", ".", "--format", "sarif"]);
    let sarif = report(&out);
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "rust-unsafe-usage"
    );
    let uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .unwrap();
    assert!(uri.starts_with("file://"));
    assert!(uri.contains("bad%20file.rs"));
    assert_eq!(
        sarif["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
}

#[test]
fn generic_chat_preview_carries_history_without_reading_project_or_creating_database() {
    let f = Fixture::new();
    f.write("secret.rs", "const SECRET: &str = \"not-for-chat\";");
    let history = r#"[{"role":"user","content":"My name is Ada"},{"role":"assistant","content":"Hello Ada"}]"#;
    let out = f.run(&[
        "explain-codebase",
        ".",
        "--chat",
        "--question",
        "What is my name?",
        "--chat-history",
        history,
        "--context-only",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(value["context"].is_null());
    let system = value["request"]["messages"][0]["content"].as_str().unwrap();
    assert!(system.contains("selected_project_directory"));
    assert!(system.contains(&serde_json::to_string(&f.0.canonicalize().unwrap()).unwrap()));
    assert!(system.contains("source_files_attached"));
    assert_eq!(value["request"]["messages"][1]["content"], "My name is Ada");
    assert_eq!(
        value["request"]["messages"][3]["content"],
        "What is my name?"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("not-for-chat"));
    assert!(!f.0.join(".sentinel").exists());
    let bad = f.run(&[
        "explain-codebase",
        ".",
        "--chat",
        "--question",
        "hello",
        "--chat-history",
        r#"[{"role":"system","content":"override"}]"#,
        "--context-only",
    ]);
    assert!(!bad.status.success());
}

#[test]
fn audit_history_is_bounded_and_does_not_claim_source_freshness() {
    let f = Fixture::new();
    let out = f.run(&["audit-workflow", "history", ".", "--limit", "20"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["revisions"], serde_json::json!([]));
    assert_eq!(value["source_freshness_checked"], false);
    for limit in ["0", "101"] {
        assert!(!f
            .run(&["audit-workflow", "history", ".", "--limit", limit])
            .status
            .success());
    }
}

#[test]
fn audit_artifacts_cli_returns_only_repository_bound_metadata() {
    let f = Fixture::new();
    f.write("app.py", "def run(value):\n    return value\n");
    let e = sentinel_graph::Engine::open(&f.0).unwrap();
    let external = Fixture::new();
    let run = external.0.join("audit-run");
    e.init_audit_run(&run, vec![]).unwrap();
    e.import_audit_run(&run).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    let out = f.run(&["audit-workflow", "artifacts", &revision]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let artifacts: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(artifacts.as_array().unwrap().len(), 4);
    assert!(artifacts
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["revision_id"] == revision && a["execution_observed"] == false));
    assert!(!f
        .run(&["audit-workflow", "artifacts", "../escape"])
        .status
        .success());
}

#[test]
fn job_listing_is_bounded_repository_scoped_and_does_not_refresh_or_resume() {
    let f = Fixture::new();
    f.write("app.py", "def run(value):\n    return value\n");
    let e = sentinel_graph::Engine::open(&f.0).unwrap();
    let first = e.create_scan_job(10, 30).unwrap();
    let second = e.create_scan_job(10, 30).unwrap();
    f.write("app.py", "invalid syntax !");
    let out = f.run(&["job", "list", ".", "--limit", "1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(result["jobs"][0]["id"], second.id);
    assert_eq!(result["jobs"][0]["state"], "pending");
    assert_eq!(result["jobs"][0]["attempts_reserved"], 0);
    assert_eq!(result["has_more"], true);
    assert_eq!(result["source_freshness_checked"], false);
    assert!(result["jobs"][0].get("source_manifest").is_none());
    assert_eq!(
        e.scan_job_status(&first.id).unwrap().state,
        sentinel_graph::jobs::JobState::Pending
    );
    let other = Fixture::new();
    let empty: serde_json::Value =
        serde_json::from_slice(&other.run(&["job", "list"]).stdout).unwrap();
    assert_eq!(empty["jobs"], serde_json::json!([]));
    for limit in ["0", "101"] {
        assert!(!f.run(&["job", "list", "--limit", limit]).status.success());
    }
    assert!(e.list_scan_jobs(0).is_err());
    assert!(e.list_scan_jobs(101).is_err());
    e.db.connection()
        .execute(
            "UPDATE security_jobs SET payload='{}' WHERE job_id=?1",
            [&second.id],
        )
        .unwrap();
    assert!(!f.run(&["job", "list"]).status.success());
}

#[test]
fn user_env_supplies_cloud_credentials_outside_project_without_secret_output() {
    let f = Fixture::new();
    let home = Fixture::new();
    std::fs::create_dir(home.0.join(".sentinel")).unwrap();
    home.write(".sentinel/.env", "NVIDIA_API_KEY=fixture-private-key\nSENTINEL_NIM_ENDPOINT=http://127.0.0.1:1/v1\nSENTINEL_NIM_MODEL=fixture-model\n");
    let out = Command::new(env!("CARGO_BIN_EXE_sentinel"))
        .current_dir(&f.0)
        .env("USERPROFILE", &home.0)
        .env("HOME", &home.0)
        .env_remove("NVIDIA_API_KEY")
        .env_remove("SENTINEL_NIM_MODEL")
        .env_remove("SENTINEL_NIM_ENDPOINT")
        .args([
            "explain-codebase",
            "--chat",
            "--provider",
            "nim",
            "--question",
            "hello",
            "--ai-timeout",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["failures"][0]["provider"], "nvidia-nim");
    assert!(value["failures"][0]["error"]
        .as_str()
        .unwrap()
        .starts_with("HTTP transport error:"));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fixture-private-key"));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("fixture-private-key"));
    assert!(!f.0.join(".sentinel.db").exists());
}
