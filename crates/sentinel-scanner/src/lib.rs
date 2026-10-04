use sentinel_core::{Finding, Severity};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("scanner execution failed: {0}")]
    Execution(String),
    #[error("scanner output invalid: {0}")]
    Parse(String),
}
pub type Result<T> = std::result::Result<T, ScannerError>;
#[derive(Default)]
pub struct ScannerRegistry;
impl ScannerRegistry {
    pub fn new() -> Self {
        Self
    }
    pub fn available_scanners(&self) -> Vec<String> {
        ["semgrep", "bandit"]
            .into_iter()
            .filter(|name| find_executable(name).is_some())
            .map(String::from)
            .collect()
    }
    pub fn is_available(&self, name: &str) -> bool {
        find_executable(name).is_some()
    }
}
fn find_executable(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        let path = dir.join(if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.into()
        });
        path.is_file().then_some(path)
    })
}
#[derive(Debug)]
pub struct ScannerProcess {
    pub stdout: String,
    pub execution_error: Option<String>,
}
pub struct SubprocessRunner;
impl SubprocessRunner {
    pub fn run_command(
        command: &mut Command,
        timeout: Duration,
        max_output: usize,
    ) -> Result<ScannerProcess> {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command
            .spawn()
            .map_err(|e| ScannerError::Execution(e.to_string()))?;
        let overflow = Arc::new(AtomicBool::new(false));
        let reader = |mut pipe: Box<dyn Read + Send>, limit: usize, flag: Arc<AtomicBool>| {
            let (send, receive) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = (|| {
                    let mut bytes = vec![];
                    let mut chunk = [0u8; 8192];
                    loop {
                        match pipe.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                if bytes.len() + n > limit {
                                    flag.store(true, Ordering::SeqCst);
                                    break;
                                }
                                bytes.extend_from_slice(&chunk[..n]);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(bytes)
                })();
                let _ = send.send(result);
            });
            receive
        };
        let stdout = reader(
            Box::new(child.stdout.take().unwrap()),
            max_output,
            overflow.clone(),
        );
        let stderr = reader(
            Box::new(child.stderr.take().unwrap()),
            64 * 1024,
            overflow.clone(),
        );
        let start = Instant::now();
        let mut failure = None;
        let status = loop {
            if start.elapsed() >= timeout || overflow.load(Ordering::SeqCst) {
                failure = Some(if overflow.load(Ordering::SeqCst) {
                    "output limit exceeded"
                } else {
                    "timeout exceeded"
                });
                terminate(&mut child);
                break child
                    .wait()
                    .map_err(|e| ScannerError::Execution(e.to_string()))?;
            }
            match child
                .try_wait()
                .map_err(|e| ScannerError::Execution(e.to_string()))?
            {
                Some(status) => break status,
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        let read = |receiver: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>| {
            receiver
                .recv_timeout(
                    timeout
                        .saturating_sub(start.elapsed())
                        .max(Duration::from_millis(1)),
                )
                .map_err(|_| {
                    ScannerError::Execution("scanner pipes did not close before timeout".into())
                })?
                .map_err(|e| ScannerError::Execution(e.to_string()))
        };
        let out = match read(stdout) {
            Ok(bytes) => bytes,
            Err(e) => {
                terminate(&mut child);
                return Err(e);
            }
        };
        let err = match read(stderr) {
            Ok(bytes) => bytes,
            Err(e) => {
                terminate(&mut child);
                return Err(e);
            }
        };
        if let Some(reason) = failure {
            return Err(ScannerError::Execution(reason.into()));
        }
        if overflow.load(Ordering::SeqCst) {
            return Err(ScannerError::Execution("output limit exceeded".into()));
        }
        // Semgrep --error and Bandit use 1 to indicate findings, not an execution failure.
        let execution_error = (!matches!(status.code(), Some(0 | 1)))
            .then(|| format!("exit {status}: {}", String::from_utf8_lossy(&err)));
        let stdout = String::from_utf8(out).map_err(|e| ScannerError::Parse(e.to_string()))?;
        Ok(ScannerProcess {
            stdout,
            execution_error,
        })
    }

    pub fn run(
        scanner: &str,
        files: &[PathBuf],
        config: Option<&Path>,
        timeout: Duration,
    ) -> Result<ScannerProcess> {
        let executable = find_executable(scanner)
            .ok_or_else(|| ScannerError::Execution(format!("{scanner} unavailable")))?;
        let mut command = Command::new(executable);
        match scanner {
            "semgrep" => {
                let config=config.ok_or_else(||ScannerError::Execution("Semgrep requires --semgrep-config pointing to a local rule file or directory".into()))?;
                if !config.exists() {
                    return Err(ScannerError::Execution(
                        "Semgrep configuration does not exist".into(),
                    ));
                }
                command
                    .args([
                        "scan",
                        "--json",
                        "--error",
                        "--metrics=off",
                        "--disable-version-check",
                        "--config",
                    ])
                    .arg(config)
                    .arg("--")
                    .args(files);
            }
            "bandit" => {
                command.args(["-f", "json", "--"]).args(
                    files
                        .iter()
                        .filter(|p| p.extension().map(|e| e == "py").unwrap_or(false)),
                );
            }
            _ => {
                return Err(ScannerError::Execution(format!(
                    "unsupported scanner {scanner}"
                )))
            }
        }
        Self::run_command(&mut command, timeout, 8 * 1024 * 1024)
    }
}
fn terminate(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill")
            .creation_flags(0x08000000)
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}
pub struct NormalizedScan {
    pub findings: Vec<Finding>,
    pub coverage_notes: Vec<String>,
}
pub fn normalize_findings(raw: &str, scanner: &str) -> Result<NormalizedScan> {
    let json: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| ScannerError::Parse(e.to_string()))?;
    let results = json
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ScannerError::Parse("missing results array".into()))?;
    let mut findings = vec![];
    let mut notes = vec![];
    if let Some(errors) = json.get("errors").and_then(|v| v.as_array()) {
        for e in errors {
            notes.push(format!("{scanner}: {e}"));
        }
    }
    for item in results {
        match parse_item(item, scanner) {
            Ok(f) => findings.push(f),
            Err(e) => notes.push(e.to_string()),
        }
    }
    Ok(NormalizedScan {
        findings,
        coverage_notes: notes,
    })
}
fn parse_item(v: &serde_json::Value, scanner: &str) -> Result<Finding> {
    let (path, line, column, title, message, severity, confidence) = match scanner {
        "semgrep" => (
            v.get("path"),
            v.pointer("/start/line"),
            v.pointer("/start/col"),
            v.get("check_id"),
            v.pointer("/extra/message"),
            v.pointer("/extra/severity"),
            0.9,
        ),
        "bandit" => (
            v.get("filename"),
            v.get("line_number"),
            v.get("col_offset"),
            v.get("test_id").or_else(|| v.get("issue_id")),
            v.get("issue_text"),
            v.get("issue_severity"),
            match v.get("issue_confidence").and_then(|v| v.as_str()) {
                Some("HIGH") => 0.9,
                Some("MEDIUM") => 0.7,
                _ => 0.5,
            },
        ),
        _ => {
            return Err(ScannerError::Parse(format!(
                "unsupported scanner {scanner}"
            )))
        }
    };
    let required = |v: Option<&serde_json::Value>, name: &str| {
        v.and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(|| ScannerError::Parse(format!("{scanner}: missing {name}")))
    };
    let line = line
        .and_then(|v| v.as_u64())
        .filter(|n| *n > 0)
        .ok_or_else(|| ScannerError::Parse(format!("{scanner}: invalid line")))?
        as usize;
    let severity: Severity = required(severity, "severity")?
        .parse()
        .map_err(ScannerError::Parse)?;
    let mut f = Finding {
        id: String::new(),
        severity,
        confidence,
        category: scanner.into(),
        file: PathBuf::from(required(path, "path")?),
        line,
        title: required(title, "rule id")?,
        description: required(message, "message")?,
        execution_path: vec![],
        affected_components: vec![],
        evidence: vec![format!(
            "column {}",
            column
                .and_then(|v| v.as_u64())
                .unwrap_or(if scanner == "semgrep" { 1 } else { 0 })
                + u64::from(scanner == "bandit")
        )],
        recommendation: String::new(),
    };
    f.stabilize_id();
    Ok(f)
}
pub mod pipeline;
pub mod rules;
pub use pipeline::{run_scan, ScanOptions, ScanPipelineResult};
pub use rules::{RuleEngine, RuleError as RulesError};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_all_semgrep_occurrences() {
        let raw = r#"{"results":[{"path":"a.rs","start":{"line":1,"col":1},"check_id":"r","extra":{"message":"m","severity":"ERROR"}},{"path":"b.rs","start":{"line":2,"col":1},"check_id":"r","extra":{"message":"m","severity":"ERROR"}}]}"#;
        let result = normalize_findings(raw, "semgrep").unwrap();
        assert_eq!(result.findings.len(), 2);
        assert_ne!(result.findings[0].id, result.findings[1].id);
    }
    #[test]
    fn empty_results_are_clean() {
        assert!(normalize_findings(r#"{"results":[]}"#, "bandit")
            .unwrap()
            .findings
            .is_empty());
    }
    #[test]
    fn partial_output_keeps_findings_and_errors() {
        let raw = r#"{"errors":[{"message":"parse failed"}],"results":[{"filename":"a.py","line_number":2,"test_id":"B1","issue_text":"test","issue_severity":"HIGH"}]}"#;
        let result = normalize_findings(raw, "bandit").unwrap();
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.coverage_notes.len(), 1);
    }
}
#[cfg(test)]
mod subprocess_tests {
    use super::*;
    fn script(windows: &str, unix: &str) -> Command {
        if cfg!(windows) {
            let mut c = Command::new("powershell.exe");
            c.args(["-NoProfile", "-NonInteractive", "-Command", windows]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", unix]);
            c
        }
    }
    #[test]
    fn finding_exit_preserves_json() {
        let p = SubprocessRunner::run_command(
            &mut script(
                "Write-Output '{\"results\":[]}'; exit 1",
                "printf '%s' '{\"results\":[]}'; exit 1",
            ),
            Duration::from_secs(10),
            1024,
        )
        .unwrap();
        assert!(p.execution_error.is_none());
        assert!(normalize_findings(&p.stdout, "semgrep")
            .unwrap()
            .findings
            .is_empty());
    }
    #[test]
    fn error_exit_preserves_partial_json() {
        let p = SubprocessRunner::run_command(
            &mut script(
                "Write-Output '{\"results\":[]}'; exit 2",
                "printf '%s' '{\"results\":[]}'; exit 2",
            ),
            Duration::from_secs(10),
            1024,
        )
        .unwrap();
        assert!(p.execution_error.is_some());
        assert!(normalize_findings(&p.stdout, "semgrep").is_ok());
    }
    #[test]
    fn scanner_timeout_is_bounded() {
        let started = Instant::now();
        let result = SubprocessRunner::run_command(
            &mut script("Start-Sleep -Seconds 30", "sleep 30"),
            Duration::from_millis(200),
            1024,
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn scanner_output_is_bounded() {
        let result = SubprocessRunner::run_command(
            &mut script("Write-Output ('x' * 4096)", "printf '%4096s' x"),
            Duration::from_secs(10),
            64,
        );
        assert!(result.unwrap_err().to_string().contains("output limit"));
    }
}
