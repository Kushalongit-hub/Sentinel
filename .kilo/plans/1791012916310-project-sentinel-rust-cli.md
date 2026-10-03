# Project Sentinel — Rust CLI Implementation Plan

## Goal
Build Project Sentinel as a fast, offline-first AI code auditor CLI in Rust. MVP is a working `sentinel audit` and `sentinel diff` that produces structured diagnostic reports from AST parsing, static scanners, and an optional local/cloud LLM.

## Stack
- Rust 2021 edition, `cargo` workspace
- CLI: `clap` (derive) for subcommands
- AST: `tree-sitter` + language grammars
- Git diff: `gix`
- SQLite storage: `rusqlite`
- JSON/SARIF output: `serde`/`serde_json`
- HTTP/LLM: `reqwest` + `serde_json` for Ollama/cloud APIs
- Terminal output: `colored`
- Parallelism: `rayon`

## Prerequisites
- Rust toolchain installed (`rustup default stable`)
- Optional external scanners (`semgrep`, `bandit`, `trivy`, `gitleaks`) — Sentinel invokes them if present, skips if not

## Workspace Layout
```
crates/
  sentinel-cli/     # binary crate, clap commands
  sentinel-core/    # shared engine logic
  sentinel-ast/     # tree-sitter parsing + symbol extraction
  sentinel-scanner/ # static + security scanner wrappers
  sentinel-llm/     # ollama + cloud provider adapters
  sentinel-report/  # report models + renderers (text/json/sarif)
  sentinel-db/      # sqlite memory/rules persistence
```

## CLI Contract
```bash
sentinel audit <path>        # deep scan of path
sentinel diff                # scan unstaged/staged changes
sentinel explain <finding-id> # detail view for a finding
sentinel rules               # list/validate project rules
```

## Data Model
```rust
struct Finding {
    id: String,
    severity: Severity,
    confidence: f64,
    category: String,
    file: PathBuf,
    line: usize,
    title: String,
    description: String,
    execution_path: Vec<String>,
    affected_components: Vec<String>,
    evidence: Vec<String>,
    recommendation: String,
}

struct ScanReport {
    findings: Vec<Finding>,
    files_scanned: usize,
    symbols_indexed: usize,
    scanners_used: Vec<String>,
    duration_ms: u128,
}
```

## Implementation Order
1. Workspace + crates + `cargo check` green
2. `sentinel-cli`: clap scaffolding for `audit`, `diff`, `explain`, `rules`
3. `sentinel-core`: `Finding`, `Severity`, `ScanReport`, error types
4. `sentinel-ast`: file walker, supported extension filter, tree-sitter init for Python and TypeScript, symbol extraction stub
5. `sentinel-scanner`: PATH detection for external scanners, subprocess runner stub, finding normalization
6. `sentinel-llm`: Ollama client stub, provider config, prompt template stub
7. `sentinel-report`: terminal/json renderers wired to cli output
8. `sentinel-db`: SQLite init, schema for findings/rules/memory, query stubs

## Validation
- `cargo fmt --all && cargo clippy --all-targets --all-features -D warnings`
- `cargo test --workspace`
- Manual smoke test: `cargo run -- audit .` on a fixture repo

## Out of Scope for V0.1
- MCP server
- TUI
- Memory embeddings
- CI/CD integration
- Advanced blast-radius graph traversal
