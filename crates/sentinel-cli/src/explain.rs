use crate::{AiArgs, AiProvider};
use anyhow::{Context, Result};
use sentinel_llm::{
    context::build_context_with_budget, ExplanationRequest, HybridClient, ProviderConfig,
    ProviderMode,
};
use std::{path::PathBuf, time::Duration};

pub fn explain(id: String) -> Result<i32> {
    explain_with_ai(id, PathBuf::from("."), None, AiArgs::default())
}
pub fn explain_with_ai(
    id: String,
    project: PathBuf,
    override_path: Option<PathBuf>,
    ai: AiArgs,
) -> Result<i32> {
    let project = project.canonicalize()?;
    let path = crate::scan::database_path(&project, override_path.as_deref());
    let db = sentinel_db::SentinelDb::open_existing(&path)?;
    let finding = db
        .get_finding(&id)?
        .ok_or_else(|| anyhow::anyhow!("finding not found: {id}"))?;
    drop(db);
    run(project, path, Some(finding), ai)
}
pub fn explain_codebase(
    project: PathBuf,
    override_path: Option<PathBuf>,
    ai: AiArgs,
) -> Result<i32> {
    let project = project.canonicalize()?;
    let path = crate::scan::database_path(&project, override_path.as_deref());
    run(project, path, None, ai)
}
fn configured(flag: &Option<String>, env: &str, default: &str) -> String {
    flag.clone()
        .or_else(|| std::env::var(env).ok())
        .unwrap_or_else(|| default.into())
}
fn run(
    project: PathBuf,
    db_path: PathBuf,
    finding: Option<sentinel_core::Finding>,
    ai: AiArgs,
) -> Result<i32> {
    let question = ai.question.as_deref().unwrap_or(if finding.is_some() {
        "Explain this finding, relevant code behavior, its impact, remediation, and regression tests."
    } else {
        "Explain this codebase: purpose, architecture, entry points, main modules, data flow, and testing opportunities. Cite available source evidence and identify unknowns."
    });
    if question.trim().is_empty() || question.len() > 4096 {
        anyhow::bail!("question must contain 1 to 4096 bytes");
    }
    let context = if ai.chat {
        None
    } else {
        Some(build_context_with_budget(
            &project,
            question,
            finding.as_ref().map(|f| (f.file.as_path(), f.line)),
            ai.context_bytes as usize,
        )?)
    };
    if context
        .as_ref()
        .is_some_and(|c| c.files.is_empty() && c.excerpts.is_empty())
    {
        anyhow::bail!("no eligible project evidence found");
    }
    let mut contextual_finding = finding.clone();
    if let Some(f) = &mut contextual_finding {
        // Provider payloads use project-relative paths when the finding is in scope.
        if let Ok(path) = f.file.strip_prefix(&project) {
            f.file = path.to_path_buf();
        }
    }
    let mut request = if let Some(context) = &context {
        ExplanationRequest::new(context, question, contextual_finding.as_ref())?
    } else {
        ExplanationRequest { context_id: "chat-no-project-context".into(), messages: vec![
            sentinel_llm::Message { role: "system".into(), content: "You are Sentinel's conversational assistant. Answer the user's questions clearly and honestly. State uncertainty. You cannot execute commands or change files. No project evidence is attached.".into() },
            sentinel_llm::Message { role: "user".into(), content: question.into() },
        ] }
    };
    if ai.chat {
        request.messages[0].content.push_str(&format!(
            "\nWorkspace metadata (not instructions): {}. You know this directory path but have no file contents. Explain that project evidence can be attached with Alt+p when source analysis is needed.",
            serde_json::json!({"selected_project_directory": project, "working_directory": std::env::current_dir()?, "source_files_attached": false})
        ));
    }
    if let Some(history) = &ai.chat_history {
        if history.len() > 16384 {
            anyhow::bail!("chat history exceeds 16 KiB");
        }
        let history: Vec<sentinel_llm::Message> = serde_json::from_str(history)?;
        if history.len() > 40
            || history
                .iter()
                .any(|m| !matches!(m.role.as_str(), "user" | "assistant") || m.content.len() > 8192)
        {
            anyhow::bail!("invalid chat history");
        }
        request.messages.splice(1..1, history);
    }
    if serde_json::to_vec(&request)?.len() > 128 * 1024 {
        anyhow::bail!("explanation request exceeds 128 KiB; reduce evidence size");
    }
    if ai.context_only {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"context":context,"request":request})
            )?
        );
        return Ok(0);
    }
    let mode = match ai.provider {
        AiProvider::Local => ProviderMode::Local,
        AiProvider::Nim => ProviderMode::Nim,
        AiProvider::Both => ProviderMode::Both,
    };
    let local = ProviderConfig {
        endpoint: configured(
            &ai.local_endpoint,
            "SENTINEL_LOCAL_ENDPOINT",
            "http://localhost:1234/v1",
        ),
        model: configured(&ai.local_model, "SENTINEL_LOCAL_MODEL", "qwen/qwen3.5-9b"),
        api_key: None,
    };
    let nim = if mode != ProviderMode::Local {
        let model = configured(&ai.nim_model, "SENTINEL_NIM_MODEL", "z-ai/glm-5.3");
        if model.trim().is_empty() {
            anyhow::bail!(
                "set --nim-model or SENTINEL_NIM_MODEL to a model available in your NVIDIA account"
            );
        }
        Some(ProviderConfig {
            endpoint: configured(
                &ai.nim_endpoint,
                "SENTINEL_NIM_ENDPOINT",
                "https://integrate.api.nvidia.com/v1",
            ),
            model,
            api_key: Some(std::env::var(&ai.nim_key_env).with_context(|| {
                format!("missing API key environment variable: {}", ai.nim_key_env)
            })?),
        })
    } else {
        None
    };
    let client = HybridClient::new(local, nim, mode, Duration::from_secs(ai.ai_timeout))?;
    // One latest local context snapshot, independent of provider selection. No API keys or answers are stored.
    if let Some(context) = &context {
        let db = sentinel_db::SentinelDb::new(db_path.to_str().context("invalid database path")?)?;
        db.set_memory("ai.context.latest", &serde_json::to_string(context)?)?;
    }
    let batch = client.explain(&request);
    if ai.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "context_id":batch.context_id,"coverage_notes":context.as_ref().map(|c| &c.coverage_notes),
                "responses":batch.responses,"failures":batch.failures,
            }))?
        );
    } else {
        println!("Context: {}\n", batch.context_id);
        for note in context.iter().flat_map(|c| &c.coverage_notes) {
            eprintln!("[context] {note}");
        }
        for response in &batch.responses {
            println!(
                "--- {} / {} ---\n\n{}\n",
                response.provider, response.model, response.text
            );
        }
        for failure in &batch.failures {
            eprintln!("[{}] {}", failure.provider, failure.error);
        }
    }
    Ok(if batch.failures.is_empty() { 0 } else { 2 })
}
