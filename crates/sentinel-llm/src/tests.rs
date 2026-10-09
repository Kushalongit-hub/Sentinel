use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    time::Instant,
};

struct Mock {
    endpoint: String,
    request: mpsc::Receiver<(String, serde_json::Value)>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Mock {
    fn new(status: u16, body: serde_json::Value) -> Self {
        Self::with_gate(status, body, None)
    }
    fn with_gate(
        status: u16,
        body: serde_json::Value,
        gate: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let (sender, request) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let start = Instant::now();
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && start.elapsed() < Duration::from_secs(5) =>
                    {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("mock did not receive a request: {e}"),
                }
            };
            // Accepted sockets inherit nonblocking mode on Windows.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut input = vec![];
            let (header_end, length) = loop {
                let mut chunk = [0; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                input.extend_from_slice(&chunk[..n]);
                assert!(input.len() < 256 * 1024);
                if let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header = String::from_utf8_lossy(&input[..end]).to_lowercase();
                    let length = header
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|n| n.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while input.len() < header_end + length {
                let mut chunk = [0; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                input.extend_from_slice(&chunk[..n]);
            }
            let headers = String::from_utf8(input[..header_end].to_vec()).unwrap();
            let json = serde_json::from_slice(&input[header_end..header_end + length]).unwrap();
            sender.send((headers, json)).unwrap();
            if let Some(gate) = gate {
                use std::sync::atomic::Ordering;
                gate.fetch_add(1, Ordering::SeqCst);
                let start = Instant::now();
                while gate.load(Ordering::SeqCst) < 2 {
                    assert!(
                        start.elapsed() < Duration::from_secs(3),
                        "both mode must dispatch concurrently"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let body = serde_json::to_vec(&body).unwrap();
            write!(socket,"HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            socket.write_all(&body).unwrap();
        });
        Self {
            endpoint,
            request,
            worker: Some(worker),
        }
    }
    fn received(mut self) -> (String, serde_json::Value) {
        let request = self.request.recv_timeout(Duration::from_secs(5)).unwrap();
        self.worker.take().unwrap().join().unwrap();
        request
    }
    fn config(&self, nim: bool) -> ProviderConfig {
        ProviderConfig {
            endpoint: if nim {
                format!("{}/v1", self.endpoint)
            } else {
                self.endpoint.clone()
            },
            model: "test-model".into(),
            api_key: nim.then(|| "fixture-only-key".into()),
        }
    }
}
fn request() -> ExplanationRequest {
    ExplanationRequest {
        context_id: "one-shared-context".into(),
        messages: vec![
            Message {
                role: "system".into(),
                content: "Use the same evidence".into(),
            },
            Message {
                role: "user".into(),
                content: "Explain the architecture".into(),
            },
        ],
    }
}
fn local_body() -> serde_json::Value {
    serde_json::json!({"message":{"content":"Local answer"},"done":true})
}
fn nim_body() -> serde_json::Value {
    serde_json::json!({"choices":[{"message":{"content":"Cloud answer"},"finish_reason":"stop"}]})
}

#[test]
fn both_providers_receive_identical_messages_and_keep_separate_answers() {
    let gate = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let local = Mock::with_gate(200, local_body(), Some(gate.clone()));
    let nim = Mock::with_gate(200, nim_body(), Some(gate));
    let batch = HybridClient::new(
        local.config(false),
        Some(nim.config(true)),
        ProviderMode::Both,
        Duration::from_secs(5),
    )
    .unwrap()
    .explain(&request());
    assert_eq!(batch.responses.len(), 2);
    assert!(batch.failures.is_empty());
    assert!(batch
        .responses
        .iter()
        .all(|r| r.context_id == batch.context_id));
    let (local_headers, local_request) = local.received();
    let (nim_headers, nim_request) = nim.received();
    assert!(local_headers.starts_with("POST /api/chat "));
    assert!(nim_headers.starts_with("POST /v1/chat/completions "));
    assert!(nim_headers
        .to_lowercase()
        .contains("authorization: bearer fixture-only-key"));
    assert!(!local_headers.to_lowercase().contains("authorization:"));
    assert_eq!(local_request["messages"], nim_request["messages"]);
    assert_ne!(batch.responses[0].text, batch.responses[1].text);
}
#[test]
fn both_mode_preserves_success_when_other_provider_fails() {
    let local = Mock::new(503, serde_json::json!({"error":"unavailable"}));
    let nim = Mock::new(200, nim_body());
    let batch = HybridClient::new(
        local.config(false),
        Some(nim.config(true)),
        ProviderMode::Both,
        Duration::from_secs(5),
    )
    .unwrap()
    .explain(&request());
    assert_eq!(batch.responses.len(), 1);
    assert_eq!(batch.responses[0].provider, "nvidia-nim");
    assert_eq!(batch.failures[0].provider, "ollama");
    local.received();
    nim.received();
}
#[test]
fn local_mode_does_not_call_cloud_and_nim_mode_does_not_call_local() {
    let local = Mock::new(200, local_body());
    let batch = HybridClient::new(
        local.config(false),
        None,
        ProviderMode::Local,
        Duration::from_secs(5),
    )
    .unwrap()
    .explain(&request());
    assert_eq!(batch.responses[0].provider, "ollama");
    local.received();
    let nim = Mock::new(200, nim_body());
    let unused_local = ProviderConfig {
        endpoint: "not-a-url".into(),
        model: String::new(),
        api_key: None,
    };
    let batch = HybridClient::new(
        unused_local,
        Some(nim.config(true)),
        ProviderMode::Nim,
        Duration::from_secs(5),
    )
    .unwrap()
    .explain(&request());
    assert_eq!(batch.responses[0].provider, "nvidia-nim");
    nim.received();
}
#[test]
fn rejects_truncated_cloud_answers_and_redacts_keys_in_debug() {
    let nim = Mock::new(
        200,
        serde_json::json!({"choices":[{"message":{"content":"Partial"},"finish_reason":"length"}]}),
    );
    let config = nim.config(true);
    assert!(!format!("{config:?}").contains("fixture-only-key"));
    let batch = HybridClient::new(
        config.clone(),
        Some(config),
        ProviderMode::Nim,
        Duration::from_secs(5),
    )
    .unwrap()
    .explain(&request());
    assert!(batch.responses.is_empty());
    assert_eq!(batch.failures.len(), 1);
    nim.received();
}

struct Project(std::path::PathBuf);
impl Project {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "sentinel-context-{}-{}-{}",
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
        std::fs::create_dir(&root).unwrap();
        Self(root)
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
                .starts_with("sentinel-context-")
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
#[test]
fn context_is_deterministic_changes_with_source_and_respects_exclusions() {
    let root = Project::new();
    std::fs::write(root.0.join("main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.0.join("credentials.rs"), "SECRET").unwrap();
    std::fs::write(root.0.join(".env"), "SECRET").unwrap();
    std::fs::create_dir(root.0.join("target")).unwrap();
    std::fs::write(root.0.join("target/generated.rs"), "SECRET").unwrap();
    let first = context::build_context(&root.0, "Explain main", None).unwrap();
    let second = context::build_context(&root.0, "Explain main", None).unwrap();
    assert_eq!(first.snapshot_id, second.snapshot_id);
    assert_eq!(first.files.len(), 1);
    assert!(!serde_json::to_string(&first).unwrap().contains("SECRET"));
    std::fs::write(
        root.0.join("main.rs"),
        "fn main() { println!(\"changed\"); }\n",
    )
    .unwrap();
    let changed = context::build_context(&root.0, "Explain main", None).unwrap();
    assert_ne!(first.snapshot_id, changed.snapshot_id);
}
#[test]
fn context_budget_preserves_focused_source_lines() {
    let root = Project::new();
    let file = root.0.join("main.py");
    let mut source = (0..200).map(|_| "pass\n").collect::<String>();
    source.push_str("dangerous_call(user_input)\n");
    std::fs::write(&file, source).unwrap();
    let context =
        context::build_context_with_budget(&root.0, "Explain finding", Some((&file, 201)), 4096)
            .unwrap();
    assert!(serde_json::to_vec(&context).unwrap().len() <= 4096);
    let excerpt = &context.excerpts[0];
    assert!(excerpt.start_line <= 201 && excerpt.end_line >= 201);
    assert!(excerpt.text.contains("201: dangerous_call(user_input)"));
}

#[test]
fn local_openai_protocol_uses_v1_without_cloud_credentials() {
    let mock = Mock::new(200, nim_body());
    let mut local = mock.config(false);
    local.endpoint.push_str("/v1/");
    let router =
        HybridClient::new(local, None, ProviderMode::Local, Duration::from_secs(3)).unwrap();
    let result = router.explain(&request());
    assert!(result.failures.is_empty());
    assert_eq!(result.responses[0].provider, "local-openai");
    let (headers, body) = mock.request.recv().unwrap();
    assert!(headers.starts_with("POST /v1/chat/completions "));
    assert!(!headers.to_lowercase().contains("authorization:"));
    assert_eq!(
        body["messages"],
        serde_json::to_value(request().messages).unwrap()
    );
    assert_eq!(body["stream"], false);
    assert!(body.get("options").is_none());
}

#[test]
fn nim_glm_receives_bounded_reasoning_and_preserves_shared_messages() {
    let mock = Mock::new(200, nim_body());
    let mut nim = mock.config(true);
    nim.model = "z-ai/glm-5.3".into();
    let result = HybridClient::new(
        mock.config(false),
        Some(nim),
        ProviderMode::Nim,
        Duration::from_secs(3),
    )
    .unwrap()
    .explain(&request());
    assert!(result.failures.is_empty());
    let (headers, body) = mock.request.recv().unwrap();
    assert!(headers.starts_with("POST /v1/chat/completions "));
    assert_eq!(body["model"], "z-ai/glm-5.3");
    assert_eq!(body["reasoning_effort"], "low");
    assert_eq!(body["max_tokens"], 8192);
    assert_eq!(
        body["messages"],
        serde_json::to_value(request().messages).unwrap()
    );
}
