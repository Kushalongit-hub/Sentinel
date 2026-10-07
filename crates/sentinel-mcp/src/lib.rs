//! Local stdio MCP server with repository-bound, deterministic security tools.
use anyhow::Result;
use rmcp::schemars;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerConfig},
    schemars::JsonSchema,
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use sentinel_core::security::TraceLimits;
use sentinel_graph::Engine;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndexInput {
    pub path: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileInput {
    pub path: String,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiffInput {
    pub repository: String,
    pub base: Option<String>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextInput {
    pub repository: String,
    pub target: String,
    #[serde(default = "default_items")]
    pub max_items: usize,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SymbolInput {
    pub repository: String,
    pub query: String,
    #[serde(default = "default_items")]
    pub max_items: usize,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TraceInput {
    pub repository: String,
    pub target: String,
    pub sink_type: Option<String>,
    #[serde(default = "default_depth")]
    pub max_call_depth: usize,
    #[serde(default = "default_paths")]
    pub max_paths: usize,
    #[serde(default = "default_nodes")]
    pub max_nodes_visited: usize,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingInput {
    pub finding_id: String,
}
fn default_items() -> usize {
    40
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryInput {
    #[serde(default = "default_history_limit")]
    pub limit: usize,
}
fn default_history_limit() -> usize {
    20
}
fn default_depth() -> usize {
    8
}
fn default_paths() -> usize {
    64
}
fn default_nodes() -> usize {
    10000
}

#[derive(Clone)]
pub struct SecurityServer {
    root: Arc<PathBuf>,
    tool_router: ToolRouter<Self>,
    gate: Arc<tokio::sync::Semaphore>,
}
impl SecurityServer {
    /// Bind this server to one existing repository. Requests cannot widen its filesystem scope.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().canonicalize()?;
        if !root.is_dir() {
            anyhow::bail!("MCP repository must be a directory");
        }
        Ok(Self {
            root: Arc::new(root),
            tool_router: Self::tool_router(),
            gate: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    async fn execute<T: serde::Serialize + Send + 'static>(
        &self,
        repository: Option<String>,
        operation: impl FnOnce(Engine) -> Result<T> + Send + 'static,
    ) -> CallToolResult {
        let permit = match self.gate.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                return CallToolResult::structured_error(
                    serde_json::json!({"error":"server is shutting down"}),
                )
            }
        };
        let root = self.root.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
            let _permit = permit;
            if let Some(repository) = repository {
                let path = Path::new(&repository);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    root.join(path)
                };
                if path.canonicalize()? != *root {
                    anyhow::bail!("repository differs from the server's configured root");
                }
            }
            serde_json::to_value(operation(Engine::open(&*root)?)?).map_err(Into::into)
        })
        .await;
        match result {
            Ok(Ok(value)) => {
                if serde_json::to_vec(&value).is_ok_and(|v| v.len() > 4 * 1024 * 1024) {
                    CallToolResult::structured_error(
                        serde_json::json!({"error":"result exceeds 4 MiB; narrow the target or reduce limits"}),
                    )
                } else {
                    CallToolResult::structured(value)
                }
            }
            Ok(Err(error)) => CallToolResult::structured_error(
                serde_json::json!({"error":error.to_string(),"complete":false}),
            ),
            Err(_) => CallToolResult::structured_error(
                serde_json::json!({"error":"security worker failed","complete":false}),
            ),
        }
    }
}
#[tool_router]
impl SecurityServer {
    #[tool(
        description = "Return the pinned Cloudflare/Sentinel audit adapter and validation contract. This is guidance, not permission to execute target code or contact cloud models."
    )]
    async fn sentinel_get_audit_workflow(&self) -> CallToolResult {
        CallToolResult::structured(sentinel_graph::audit_workflow::workflow())
    }
    #[tool(
        description = "Read the latest validated imported audit, coverage gaps, recorded review verdicts, and source freshness. Imported AI audit claims never change deterministic patch gates."
    )]
    async fn sentinel_get_audit_status(&self) -> CallToolResult {
        self.execute(None, |engine| engine.audit_status()).await
    }
    #[tool(
        description = "List up to 100 retained audit revision metadata records. Does not revalidate historical source freshness or expose SQL."
    )]
    async fn sentinel_get_audit_history(
        &self,
        Parameters(input): Parameters<HistoryInput>,
    ) -> CallToolResult {
        self.execute(None, move |engine| engine.audit_history(input.limit))
            .await
    }
    #[tool(
        description = "Incrementally index the configured repository into a local security graph. Does not execute repository code."
    )]
    async fn sentinel_index_project(
        &self,
        Parameters(input): Parameters<IndexInput>,
    ) -> CallToolResult {
        self.execute(Some(input.path), |engine| engine.index())
            .await
    }
    #[tool(
        description = "Scan an in-repository file with embedded deterministic rules and relevant cross-function taint evidence."
    )]
    async fn sentinel_scan_file(&self, Parameters(input): Parameters<FileInput>) -> CallToolResult {
        self.execute(None, move |engine| engine.scan_file(&input.path))
            .await
    }
    #[tool(
        description = "Compare Git working-tree changes, including untracked files, against HEAD or a base ref. Return new/resolved/unchanged findings and changed taint paths."
    )]
    async fn sentinel_scan_diff(&self, Parameters(input): Parameters<DiffInput>) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.scan_diff(input.base.as_deref())
        })
        .await
    }
    #[tool(
        description = "Verify the patch against a saved baseline or Git HEAD/ref. Return PASS/WARN/FAIL and NEW/RESOLVED/UNCHANGED/REGRESSED evidence; incomplete analysis never passes."
    )]
    async fn sentinel_verify_patch(
        &self,
        Parameters(input): Parameters<DiffInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.verify_patch(input.base.as_deref())
        })
        .await
    }
    #[tool(
        description = "Retrieve ranked security evidence around a symbol, file, file:line, or diff. Includes call relationships, sources/sinks, guards, applicable rules, findings, and bounded paths."
    )]
    async fn sentinel_get_security_context(
        &self,
        Parameters(input): Parameters<ContextInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.get_security_context(&input.target, input.max_items)
        })
        .await
    }
    #[tool(
        description = "Trace potential untrusted input to dangerous sinks across resolved local/imported functions. Reports confidence, sanitizers, guards, locations, and explicit traversal limits."
    )]
    async fn sentinel_trace_taint(
        &self,
        Parameters(input): Parameters<TraceInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.trace(
                &input.target,
                input.sink_type.as_deref(),
                TraceLimits {
                    max_call_depth: input.max_call_depth,
                    max_paths: input.max_paths,
                    max_nodes_visited: input.max_nodes_visited,
                },
            )
        })
        .await
    }
    #[tool(
        description = "Explain a persisted vulnerability using deterministic WHAT/WHERE/WHY/FLOW/EVIDENCE/FIX evidence. Never calls an LLM."
    )]
    async fn sentinel_explain_finding(
        &self,
        Parameters(input): Parameters<FindingInput>,
    ) -> CallToolResult {
        self.execute(None, move |engine| {
            engine.explain_finding(&input.finding_id)
        })
        .await
    }
    #[tool(
        description = "Find matching symbol names, qualified names, IDs, or file locations in the configured security graph."
    )]
    async fn sentinel_find_symbol(
        &self,
        Parameters(input): Parameters<SymbolInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.find_symbols(&input.query, input.max_items)
        })
        .await
    }
    #[tool(
        description = "Get incoming call relationships and callers for a symbol or file. Uncertainty remains explicit."
    )]
    async fn sentinel_get_callers(
        &self,
        Parameters(input): Parameters<ContextInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.relationships(&input.target, true, input.max_items)
        })
        .await
    }
    #[tool(
        description = "Get outgoing call relationships and callees for a symbol or file. Dynamic unresolved receivers are not fabricated as resolved edges."
    )]
    async fn sentinel_get_callees(
        &self,
        Parameters(input): Parameters<ContextInput>,
    ) -> CallToolResult {
        self.execute(Some(input.repository), move |engine| {
            engine.relationships(&input.target, false, input.max_items)
        })
        .await
    }
}
#[tool_handler(router = self.tool_router)]
impl ServerHandler for SecurityServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions("Deterministic security intelligence for humans and AI coding agents. Call index_project, get_security_context before editing, trace_taint during investigation, and verify_patch after edits. Conclusions are bounded and approximate; inspect confidence and coverage. This server is local and repository-bound; LLM calls are optional CLI functionality.")
    }
}
/// Serve MCP over newline-delimited stdio; stdout contains protocol messages only.
pub async fn serve(root: impl AsRef<Path>) -> Result<()> {
    let server = SecurityServer::new(root)?
        .serve(rmcp::transport::stdio())
        .await?;
    server.waiting().await?;
    Ok(())
}
