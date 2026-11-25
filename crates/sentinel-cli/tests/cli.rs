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
fn index_rebuild_cli_is_explicit_and_keeps_partial_coverage_exit_status() {
    let fixture = Fixture::new();
    fixture.write("main.py", "def helper():\n    return 1\n");
    assert!(fixture.run(&["index"]).status.success());
    let db = rusqlite::Connection::open(fixture.0.join(".sentinel.db")).unwrap();
    db.execute_batch("UPDATE files SET payload='invalid-cache'; INSERT INTO memory(key,value) VALUES('keep','history');").unwrap();
    assert!(!fixture.run(&["index"]).status.success());
    let rebuilt = fixture.run(&["index", "--rebuild"]);
    assert!(
        rebuilt.status.success(),
        "{}",
        String::from_utf8_lossy(&rebuilt.stderr)
    );
    let stats = report(&rebuilt);
    assert_eq!(stats["changed_files"], 1);
    assert_eq!(stats["unchanged_files"], 0);
    assert_eq!(
        db.query_row("SELECT value FROM memory WHERE key='keep'", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap(),
        "history"
    );
    fixture.write("main.py", "def broken(:\n");
    let partial = fixture.run(&["index", ".", "--rebuild"]);
    assert_eq!(partial.status.code(), Some(2));
    assert_eq!(report(&partial)["complete"], false);
}

#[test]
fn trace_cli_preserves_static_paths_provenance_budgets_and_safe_repairs() {
    let fixture = Fixture::new();
    fixture.write("routes.py", "from repository import insert\ndef handler(request):\n    value = request.args['name']\n    return insert(value)\n");
    fixture.write(
        "repository.py",
        "def insert(value):\n    cursor.execute('SELECT ' + value)\n",
    );
    let out = fixture.run(&[
        "trace",
        "handler",
        "--project",
        ".",
        "--sink",
        "sql-injection",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let trace = report(&out);
    assert_eq!(trace["complete"], true);
    assert_eq!(trace["paths"].as_array().unwrap().len(), 1);
    assert_eq!(trace["paths"][0]["source"]["location"]["file"], "routes.py");
    assert_eq!(
        trace["paths"][0]["sink"]["location"]["file"],
        "repository.py"
    );
    assert_eq!(trace["paths"][0]["sink_type"], "sql-injection");
    assert_eq!(trace["backend"]["name"], "sentinel-native");
    assert_eq!(trace["source_snapshot"].as_str().unwrap().len(), 64);
    let filtered = fixture.run(&["trace", "handler", "--sink", "command-injection"]);
    assert_eq!(filtered.status.code(), Some(0));
    assert!(report(&filtered)["paths"].as_array().unwrap().is_empty());
    let bounded = fixture.run(&["trace", "handler", "--max-nodes-visited", "1"]);
    assert_eq!(bounded.status.code(), Some(2));
    let bounded = report(&bounded);
    assert_eq!(bounded["complete"], false);
    assert!(!bounded["coverage_notes"].as_array().unwrap().is_empty());
    assert_eq!(bounded["source_snapshot"], trace["source_snapshot"]);
    fixture.write(
        "repository.py",
        "def insert(value):\n    cursor.execute('SELECT ?', (value,))\n",
    );
    let repaired = fixture.run(&["trace", "handler"]);
    assert_eq!(repaired.status.code(), Some(0));
    let repaired = report(&repaired);
    assert!(repaired["paths"].as_array().unwrap().is_empty());
    assert_ne!(repaired["source_snapshot"], trace["source_snapshot"]);
    for (flag, value) in [
        ("--max-call-depth", "33"),
        ("--max-paths", "0"),
        ("--max-nodes-visited", "100001"),
    ] {
        let rejected = fixture.run(&["trace", "handler", flag, value]);
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
    }
    let missing = fixture.run(&["trace", "absent_handler"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(missing.stdout.is_empty());
}

#[test]
fn named_graph_queries_preserve_direction_bounds_provenance_and_partial_scope() {
    let fixture = Fixture::new();
    fixture.write("service.py", "def helper(value):\n    return value\n");
    fixture.write("routes.py", "from service import helper\ndef first():\n    return helper('one')\ndef second():\n    return helper('two')\ndef opaque():\n    return missing('three')\n");
    let callers = fixture.run(&["callers", "helper", "--max-items", "1"]);
    assert_eq!(callers.status.code(), Some(0));
    let callers = report(&callers);
    assert_eq!(callers["target"][0]["name"], "helper");
    assert_eq!(callers["edges"].as_array().unwrap().len(), 1);
    assert_eq!(callers["edges"][0]["resolved"], true);
    assert_eq!(callers["omitted_count"], 1);
    let caller = callers["symbols"][0]["name"].as_str().unwrap();
    assert!(matches!(caller, "first" | "second"));
    let callees = fixture.run(&["callees", caller, "--project", "."]);
    assert_eq!(callees.status.code(), Some(0));
    let callees = report(&callees);
    assert_eq!(callees["symbols"][0]["name"], "helper");
    assert_eq!(callees["source_snapshot"], callers["source_snapshot"]);
    assert_eq!(callees["backend"], callers["backend"]);
    assert_eq!(callees["edges"][0]["from"], callers["edges"][0]["from"]);
    assert_eq!(callees["edges"][0]["to"], callers["edges"][0]["to"]);
    let opaque = report(&fixture.run(&["callees", "opaque"]));
    assert_eq!(opaque["edges"][0]["resolved"], false);
    assert!(opaque["symbols"].as_array().unwrap().is_empty());
    let symbols = fixture.run(&["symbols", "helper"]);
    assert_eq!(symbols.status.code(), Some(0));
    assert_eq!(
        report(&symbols)["symbols"][0]["location"]["file"],
        "service.py"
    );
    fixture.write("broken.py", "def broken(:\n");
    for command in ["symbols", "callers", "callees"] {
        let partial = fixture.run(&[command, "helper"]);
        assert_eq!(partial.status.code(), Some(2));
        let partial = report(&partial);
        assert_eq!(partial["index_complete"], false);
        assert!(!partial["coverage_notes"].as_array().unwrap().is_empty());
        for limit in ["0", "201"] {
            let rejected = fixture.run(&[command, "helper", "--max-items", limit]);
            assert_eq!(rejected.status.code(), Some(2));
            assert!(rejected.stdout.is_empty());
        }
    }
}

#[test]
fn static_context_cli_keeps_provenance_omissions_and_partial_scope_explicit() {
    let fixture = Fixture::new();
    fixture.write(
        "main.py",
        "def helper():\n    return 1\n\ndef other():\n    return helper()\n",
    );
    let complete = fixture.run(&["context", "main.py", "--max-items", "1"]);
    assert_eq!(complete.status.code(), Some(0));
    let context = report(&complete);
    assert_eq!(context["complete"], true);
    assert_eq!(context["target_symbols"].as_array().unwrap().len(), 1);
    assert_eq!(context["selected_items"].as_array().unwrap().len(), 1);
    assert!(context["omitted_target_symbols"].as_u64().unwrap() > 0);
    assert!(context["omitted_count"].as_u64().unwrap() > 0);
    assert_eq!(context["backend"]["name"], "sentinel-native");
    assert_eq!(context["source_snapshot"].as_str().unwrap().len(), 64);

    fixture.write("broken.py", "def broken(:\n");
    let partial = fixture.run(&["context", "helper", "--project", "."]);
    assert_eq!(partial.status.code(), Some(2));
    let partial = report(&partial);
    assert_eq!(partial["complete"], false);
    assert!(!partial["coverage_notes"].as_array().unwrap().is_empty());
    // Invalid files have no indexed IR: scope completeness changes independently
    // of the retained valid-source identity.
    assert_eq!(partial["source_snapshot"], context["source_snapshot"]);
    for limit in ["0", "201"] {
        let rejected = fixture.run(&["context", "helper", "--max-items", limit]);
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
    }
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
fn audit_reports_provider_secret_candidates_without_echoing_tokens() {
    let f = Fixture::new();
    let candidates = [
        "AKIA7Q5N2M4R8D3T6V1C",
        "ghp_4Qm7Zp2Vx9Kc5Nw8Rt3Yj6Ha1Bs4Df7G",
        "AIzaSyD7xPq9Lm2Nv5Bc8Rk4Tz1Wh6Fg3Jd0Qa2",
        "xoxb-4-1234567890-1234567890-abcdefghijklmnopqrstuv",
        "npm_0123456789ABCDEF0123456789ABCDEF0123",
    ];
    let source = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| format!("const CREDENTIAL_{index}: &str = \"{candidate}\";"))
        .collect::<Vec<_>>()
        .join("\n");
    f.write("credentials.rs", source.as_bytes());

    let out = f.run(&["audit", ".", "--format", "json"]);
    let serialized = String::from_utf8_lossy(&out.stdout);
    let report = report(&out);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), candidates.len());
    assert!(findings
        .iter()
        .all(|finding| finding["category"] == "secret-candidate"));
    for candidate in candidates {
        assert!(!serialized.contains(candidate));
    }
}

#[test]
fn deps_inventories_supported_npm_lockfiles_and_labels_gaps() {
    let f = Fixture::new();
    f.write(
        "package-lock.json",
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"},"node_modules/@scope/lib":{"version":"2.3.4","optional":true},"node_modules/app/node_modules/dep":{"version":"1.2.0","dev":true}}}"#,
    );
    let out = f.run(&["deps", "."]);
    assert_eq!(out.status.code(), Some(0));
    let inventory = report(&out);
    assert_eq!(inventory["ecosystem"], "npm");
    assert_eq!(inventory["lockfile_version"], 3);
    assert_eq!(inventory["package_count"], 2);
    assert!(inventory["complete"].as_bool().unwrap());
    let packages = inventory["packages"].as_array().unwrap();
    assert!(packages.iter().any(|package| {
        package["name"] == "@scope/lib"
            && package["version"] == "2.3.4"
            && package["optional"].as_bool() == Some(true)
    }));
    assert!(packages.iter().any(|package| {
        package["name"] == "dep"
            && package["version"] == "1.2.0"
            && package["development"].as_bool() == Some(true)
    }));
    assert!(inventory["coverage_notes"][0]
        .as_str()
        .unwrap()
        .contains("no advisory database"));
    assert!(!f.0.join(".sentinel.db").exists());

    f.write(
        "package-lock.json",
        r#"{"lockfileVersion":1,"dependencies":{}}"#,
    );
    let unsupported = f.run(&["deps"]);
    assert_eq!(unsupported.status.code(), Some(2));
    assert_eq!(report(&unsupported)["complete"], false);
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
        tools["result"]["tools"].as_array().unwrap().len() == 15,
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
    let audit_engine = sentinel_graph::Engine::open(&f.0).unwrap();
    let external = Fixture::new();
    let audit_run = external.0.join("audit-run");
    audit_engine.init_audit_run(&audit_run, vec![]).unwrap();
    audit_engine.import_audit_run(&audit_run).unwrap();
    let revision = audit_engine.audit_history(1).unwrap().revisions[0]
        .revision_id
        .clone();
    std::fs::remove_dir_all(&audit_run).unwrap();
    let retained = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_revision","arguments":{"revision_id":revision}}),
    );
    assert_eq!(
        retained["result"]["structuredContent"]["revision_id"],
        revision
    );
    assert_eq!(
        retained["result"]["structuredContent"]["source_freshness_checked"],
        false
    );
    assert_eq!(
        retained["result"]["structuredContent"]["execution_observed"],
        false
    );
    let artifacts = request(
        "tools/call",
        serde_json::json!({"name":"sentinel_get_audit_artifacts","arguments":{"revision_id":revision}}),
    );
    assert_eq!(
        artifacts["result"]["structuredContent"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    for tool in [
        "sentinel_get_audit_revision",
        "sentinel_get_audit_artifacts",
    ] {
        for invalid in ["../outside".to_string(), "f".repeat(64)] {
            let reply = request(
                "tools/call",
                serde_json::json!({"name":tool,"arguments":{"revision_id":invalid}}),
            );
            assert_eq!(reply["result"]["isError"], true, "{reply}");
        }
        let widened = request(
            "tools/call",
            serde_json::json!({"name":tool,"arguments":{"revision_id":revision,"repository":external.0}}),
        );
        assert!(
            widened.get("error").is_some() || widened["result"]["isError"] == true,
            "{widened}"
        );
    }
    assert_eq!(
        audit_engine.audit_history(1).unwrap().revisions[0].revision_id,
        revision
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
    assert_eq!(
        context["result"]["structuredContent"]["omitted_target_symbols"],
        0
    );
    assert_eq!(
        context["result"]["structuredContent"]["backend"],
        trace["result"]["structuredContent"]["backend"]
    );
    assert_eq!(
        context["result"]["structuredContent"]["source_snapshot"],
        trace["result"]["structuredContent"]["source_snapshot"]
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
    let provenance = &evidence["result"]["structuredContent"];
    assert_eq!(
        provenance["backend"],
        trace["result"]["structuredContent"]["backend"]
    );
    assert_eq!(
        provenance["source_snapshot"],
        trace["result"]["structuredContent"]["source_snapshot"]
    );
    assert_eq!(provenance["index_complete"], true);
    assert_eq!(provenance["excerpt_matches_graph"], true);
    assert_eq!(
        provenance["excerpt_content_hash"].as_str().unwrap().len(),
        64
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
        assert_eq!(
            result["result"]["structuredContent"]["backend"]["name"],
            "sentinel-native"
        );
        assert_eq!(
            result["result"]["structuredContent"]["source_snapshot"],
            trace["result"]["structuredContent"]["source_snapshot"]
        );
        assert!(
            result["result"]["structuredContent"]["index_complete"].is_boolean(),
            "{result}"
        );
        assert!(
            result["result"]["structuredContent"]["coverage_notes"].is_array(),
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
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().count(), 27);
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

#[test]
fn audit_revision_cli_reads_retained_content_without_promoting_it() {
    let f = Fixture::new();
    f.write("app.py", "value = 1\n");
    let e = sentinel_graph::Engine::open(&f.0).unwrap();
    let external = Fixture::new();
    let run = external.0.join("run");
    e.init_audit_run(&run, vec![]).unwrap();
    e.import_audit_run(&run).unwrap();
    let revision = e.audit_history(1).unwrap().revisions[0].revision_id.clone();
    f.write("app.py", "value = 2\n");
    let out = f.run(&["audit-workflow", "revision", &revision]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["revision_id"], revision);
    assert_eq!(value["source_freshness_checked"], false);
    assert_eq!(value["execution_observed"], false);
    assert_eq!(value["run"]["metadata"]["run_status"], "in_progress");
    assert_eq!(
        e.audit_history(1).unwrap().revisions[0].revision_id,
        revision
    );
    assert!(!external
        .run(&["audit-workflow", "revision", &revision])
        .status
        .success());
}

#[test]
fn job_cli_pending_batch_and_cancellation_retain_existing_budgets() {
    let f = Fixture::new();
    f.write("a.py", "value = 1\n");
    f.write("b.py", "value = 2\n");
    let created = f.run(&[
        "job",
        "create",
        ".",
        "--max-attempts",
        "2",
        "--max-seconds",
        "60",
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let job: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let id = job["id"].as_str().unwrap();
    let partial = f.run(&["job", "resume", id, "--max-units", "1"]);
    assert_eq!(partial.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(value["state"], "pending");
    assert_eq!(value["attempts_reserved"], 1);
    assert_eq!(value["max_attempts"], 2);
    assert_eq!(value["max_elapsed_ms"], 60000);
    assert_eq!(value["results"].as_array().unwrap().len(), 1);
    let cancelled = f.run(&["job", "cancel", id]);
    assert!(cancelled.status.success());
    let terminal = f.run(&["job", "resume", id, "--max-units", "1"]);
    assert_eq!(terminal.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&terminal.stdout).unwrap();
    assert_eq!(value["state"], "cancelled");
    assert_eq!(value["attempts_reserved"], 1);
    assert_eq!(value["results"].as_array().unwrap().len(), 1);
}
