# Sentinel — Competitive Gap Remediation Plan

## Current State
Sentinel is a rule-based AST scanner with 15 bundled YAML rules, tree-sitter symbol extraction, and optional external scanners. It lacks taint analysis, secret detection, supply-chain scanning, and LLM triage in the scan loop.

## Competitive Analysis
| Gap | Competitor | Sentinel Today |
|-----|-----------|----------------|
| Taint / dataflow | semgrep Pro, Qryon | None |
| Secrets + git history | gitleaks, PledgeRecon | None |
| Supply chain / advisories | cargo-audit, inkode | None |
| False-positive reduction | PledgeRecon LLM triage, inkode call graph | None |
| Unsafe / FFI auditing | rust-security-auditor, cargo-capsec | None |
| Rule-match precision | semgrep AST-aware patterns | Substring matching |

## Proposed Remediation (Priority Order)

### P1 — AST Taint Tracking for Rust
**Why**: This is the single biggest detection gap. semgrep Pro's Rust taint rules catch SQL injection, command injection, SSRF, and path traversal. Without taint, Sentinel misses entire vulnerability classes.

**Approach**:
- Add `sentinel-taint` crate with source/sink/sanitizer registry
- Use tree-sitter to find function arguments marked as sources (e.g., `web::Path`, `Request`, `Json<T>`)
- Track taint through assignments, method calls, and `format!`/`push_str`-style string operations
- Match tainted data reaching sinks (`diesel::sql_query`, `std::process::Command`, `reqwest::Client::get`, `std::fs::File::open`)
- Implement intra-procedural analysis first; inter-procedural later

**Files affected**: `crates/sentinel-ast/`, `crates/sentinel-scanner/`

### P2 — Secret Detection
**Why**: gitleaks-style detection is table stakes for a security scanner. Easy to implement, high user value.

**Approach**:
- Add `sentinel-secrets` crate
- Embed regex patterns for API keys, tokens, passwords, AWS keys, GitHub PATs
- Add Shannon-entropy check for high-entropy strings (> 4.5 bits/char)
- Scan all text files during `audit`
- Optional: scan git history via `git log -p` subprocess

**Files affected**: `crates/sentinel-scanner/`, `crates/sentinel-cli/src/audit.rs`

### P3 — Supply-Chain Scanning
**Why**: RUSTSEC advisories and yanked crates are a major Rust-specific risk. inkode and cargo-audit already do this; Sentinel doesn't.

**Approach**:
- Add `sentinel-supply` crate
- Parse `Cargo.lock` for crate names + versions
- Query OSV API (`https://api.osv.dev/v1/query`) for Rust ecosystem advisories
- Cache results in SQLite
- Fall back to wrapping `cargo audit` if installed

**Files affected**: `crates/sentinel-supply/` (new), `crates/sentinel-db/`

### P4 — LLM Triage in Scan Loop
**Why**: PledgeRecon's differentiator is local Ollama triage reducing false positives. Sentinel already has the `sentinel explain` path; this extends it to auto-triage.

**Approach**:
- After each scan, send low-confidence findings to Ollama
- Ask LLM to classify as true positive / false positive / needs review
- Downgrade false positives to `Info` severity
- Require `--with-llm-triage` flag (opt-in, not default)

**Files affected**: `crates/sentinel-llm/`, `crates/sentinel-cli/src/audit.rs`

### P5 — Unsafe / FFI Auditing
**Why**: rust-security-auditor and cargo-capsec fill this niche. Sentinel's current `unsafe-usage` rule is just a substring match.

**Approach**:
- Add tree-sitter queries to find `unsafe { ... }`, `extern "C"`, `transmute`, `MaybeUninit`, raw pointer ops
- Build call graph from AST to see if unsafe is reachable from public API
- Flag unsafe without `// SAFETY:` comment

**Files affected**: `crates/sentinel-ast/`, `crates/sentinel-scanner/rules/`

## Out of Scope (V0.2)
- MIR-based analysis (requires nightly + custom driver)
- Cross-file taint (P1 is intra-procedural only)
- WASM custom rules
- TUI / MCP server

## Validation
- `cargo check --workspace`
- `cargo test --workspace`
- Smoke test: `cargo run -- audit .` on a fixture repo with known vulnerabilities
- Benchmark: scan 50K-line repo, ensure < 30s
