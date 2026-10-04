//! Portable, deterministic contracts for repository security intelligence.
use serde::{Deserialize, Serialize};

/// A project-relative source location; line numbers are one-based and inclusive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
}
/// An AST-derived symbol. Identity excludes line numbers and content hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRecord {
    pub id: String,
    pub name: String,
    pub qualified_name: String,
    pub kind: String,
    pub location: Location,
    pub language: String,
    pub content_hash: String,
    pub parameters: Vec<String>,
    pub body: Vec<FlowStmt>,
}
/// Compact executable expression IR. Literals deliberately contain no source text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowExpr {
    Literal,
    Variable {
        name: String,
    },
    Source {
        name: String,
        line: usize,
    },
    Join {
        values: Vec<FlowExpr>,
    },
    Call {
        name: String,
        args: Vec<FlowExpr>,
        line: usize,
        snippet: String,
        shell: bool,
    },
}
/// Structured statements used by bounded, conservative flow interpretation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowStmt {
    Assign {
        name: String,
        value: FlowExpr,
        local: bool,
        line: usize,
    },
    Evaluate {
        value: FlowExpr,
    },
    Return {
        value: FlowExpr,
    },
    Branch {
        yes: Vec<FlowStmt>,
        no: Vec<FlowStmt>,
    },
    Loop {
        body: Vec<FlowStmt>,
    },
    Scope {
        body: Vec<FlowStmt>,
    },
}
/// An import binding captured from syntax, before module resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    pub module: String,
    pub imported: String,
    pub local: String,
    pub line: usize,
}
/// An unresolved call site retained for incremental relationship resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub owner: String,
    pub name: String,
    pub line: usize,
    pub snippet: String,
}
/// A syntactic security annotation. Recognition does not prove runtime API identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub owner: String,
    pub kind: String,
    pub category: String,
    pub name: String,
    pub location: Location,
    pub snippet: String,
}
/// Cached AST-derived data for a file; the file hash determines whether reparsing is needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFile {
    pub path: String,
    pub language: String,
    pub content_hash: String,
    pub symbols: Vec<SymbolRecord>,
    pub imports: Vec<ImportRecord>,
    pub calls: Vec<CallSite>,
    pub annotations: Vec<Annotation>,
    pub notes: Vec<String>,
}
/// A typed graph relationship; `resolved=false` preserves uncertainty explicitly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub file: String,
    pub line: usize,
    pub name: String,
    pub resolved: bool,
}
/// Configurable limits shared by trace and context operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TraceLimits {
    pub max_call_depth: usize,
    pub max_paths: usize,
    pub max_nodes_visited: usize,
}
impl Default for TraceLimits {
    fn default() -> Self {
        Self {
            max_call_depth: 8,
            max_paths: 64,
            max_nodes_visited: 10000,
        }
    }
}
/// One location along a data-flow trace, including the source/call/sink operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub symbol: String,
    pub symbol_id: String,
    pub location: Location,
    pub operation: String,
}
/// A deterministic potential source-to-sink path, with explicit analysis confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub id: String,
    pub source: FlowStep,
    pub path: Vec<FlowStep>,
    pub sink: FlowStep,
    pub sink_type: String,
    pub sanitizers: Vec<FlowStep>,
    pub security_guards: Vec<FlowStep>,
    pub confidence: String,
    pub evidence: String,
    pub remediation_hint: String,
}
/// Bounded trace output; `complete` concerns traversal, not compiler-level soundness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReport {
    pub paths: Vec<TaintPath>,
    pub nodes_visited: usize,
    pub duration_ms: u128,
    pub complete: bool,
    pub coverage_notes: Vec<String>,
}

/// Stable SHA-256 identity for serialized deterministic keys.
pub fn identity(value: impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&value).expect("identity key is serializable"))
    )
}
/// Recognized dangerous call category and argument position. API recognition is syntactic.
pub fn sink_type(name: &str, shell: bool) -> Option<(&'static str, usize)> {
    let name = name.replace("::", ".");
    let tail = name.rsplit('.').next().unwrap_or(&name);
    if [
        "execute",
        "executemany",
        "query",
        "raw",
        "executeRaw",
        "queryRawUnsafe",
    ]
    .contains(&tail)
    {
        Some(("sql-injection", 0))
    } else if ["exec", "execSync", "system", "popen"].contains(&tail)
        || (shell && ["run", "call", "Popen", "spawn", "spawnSync"].contains(&tail))
    {
        Some(("command-injection", 0))
    } else if ["send", "write", "html", "innerHTML"].contains(&tail) {
        Some(("xss", 0))
    } else if [
        "open",
        "readFile",
        "readFileSync",
        "read_to_string",
        "sendFile",
        "read_text",
    ]
    .contains(&tail)
    {
        Some(("path-traversal", 0))
    } else {
        None
    }
}
/// Category-specific, explicitly recognized sanitizer call names.
pub fn sanitizer_type(name: &str) -> Option<&'static str> {
    match name.rsplit('.').next().unwrap_or(name) {
        "escapeHtml" | "escape_html" | "sanitizeHtml" | "sanitize_html" | "escape" => Some("xss"),
        "quote" => Some("command-injection"),
        "safe_path" | "validate_path" => Some("path-traversal"),
        "parameterize" | "parameterized_query" => Some("sql-injection"),
        _ => None,
    }
}
/// Syntactic guard annotations do not establish dominance or authorization correctness.
pub fn guard_type(name: &str) -> Option<&'static str> {
    match name.rsplit('.').next().unwrap_or(name) {
        "authenticate" | "require_auth" | "login_required" | "isAuthenticated" => {
            Some("authentication")
        }
        "authorize" | "check_permission" | "requires_permission" | "hasPermission" => {
            Some("authorization")
        }
        _ => None,
    }
}
