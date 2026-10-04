# P1 — Intra-Procedural Taint Tracking Implementation Plan

## Goal
Add intra-procedural taint tracking to Sentinel so taint-mode rules (`mode: taint`) can fire. This should activate ~80% of the semgrep rules already bundled but currently inert, increasing active rule coverage from ~5 to ~25+.

## Scope
- New crate: `sentinel-taint`
- Modify: `sentinel-scanner/src/rules.rs` to support `mode: taint` rules
- Smoke test: `cargo run -- audit C:\projects\OpenConnect` must find ≥ 5 findings after P1 (currently 3 without taint)

## Out of Scope (P1)
- Cross-file taint (inter-procedural)
- Rust taint tracking (JS only in P1)
- MIR-based analysis
- Taint through complex dataflow (spread, destructuring)

## Design

### New Crate: `sentinel-taint`

**Dependencies**: `sentinel-core`, `tree-sitter`, `tree-sitter-javascript`, `thiserror`

**Core types**:
```rust
pub enum TaintLevel { Clean, Tainted, Sanitized }

pub struct TaintContext {
    pub variables: HashMap<String, TaintLevel>,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub sanitizers: Vec<String>,
}

pub struct TaintEngine {
    source_patterns: Vec<String>,
    sink_patterns: Vec<String>,
    sanitizer_patterns: Vec<String>,
}

pub fn analyze_function(
    engine: &TaintEngine,
    source: &str,
    function_body: &str,
) -> Vec<TaintFinding>;
```

**Algorithm** (intra-procedural, single pass):
1. Parse function body with tree-sitter-javascript
2. Walk AST top-to-bottom
3. For each assignment/variable declaration:
   - If RHS contains a source pattern → mark LHS variable as `Tainted`
   - If RHS contains a sanitizer pattern → mark LHS as `Clean`
   - If RHS is a tainted variable → mark LHS as `Tainted`
4. For each call expression:
   - If call matches a sink pattern AND any argument/variable in scope is `Tainted` → emit `TaintFinding`

### Rule Schema Extension

Add to `sentinel-scanner/src/rules.rs`:
```yaml
rules:
  - id: detect-child-process
    mode: taint
    message: "Detected subprocess with user-controlled input"
    languages: [javascript, typescript]
    severity: ERROR
    pattern-sources:
      - patterns:
        - pattern-inside: |
            function ... (...,$FUNC,...) { ... }
        - focus-metavariable: $FUNC
    pattern-sinks:
      - patterns:
        - pattern-either:
          - pattern: child_process.exec($CMD,...)
          - pattern: child_process.execSync($CMD,...)
        - focus-metavariable: $CMD
```

**Deserialization changes**:
- Add `mode: Option<String>` to `Rule` (default: `search`)
- Add `pattern_sources: Option<Vec<PatternEntry>>` to `Rule`
- Add `pattern_sinks: Option<Vec<PatternEntry>>` to `Rule`
- Add `pattern_sanitizers: Option<Vec<PatternEntry>>` to `Rule`

### Rule Engine Integration

In `RuleEngine::scan()`:
1. If `rule.mode == "taint"` → delegate to `TaintEngine::analyze_file()`
2. Otherwise → existing pattern matching

**New method**: `TaintEngine::analyze_file(source: &str, language: &str, rule: &Rule) -> Vec<Finding>`

Algorithm:
1. For each taint rule matching the language:
   a. Extract source patterns from `pattern-sources`
   b. Extract sink patterns from `pattern-sinks`
   c. Extract sanitizer patterns from `pattern-sanitizers`
   d. Parse file with tree-sitter
   e. For each function in file:
      - Call `analyze_function()` with the rule's patterns
      - Collect findings
2. Deduplicate by `(file, line, rule_id)`

### Pattern Extraction from YAML

For taint rules, extract concrete strings from `PatternEntry`:
- `pattern`: exact string match
- `pattern-regex`: regex to compile
- `pattern-inside`: context requirement (function must be inside this pattern)
- `focus-metavariable`: which variable to track (default: first metavariable)

**Helper**: `fn extract_string_patterns(entry: &PatternEntry) -> Vec<String>`

### Tree-Sitter Queries

Use tree-sitter's S-expression query language to find:
- Function declarations: `(function_declaration name: (identifier) body: (statement_block))`
- Variable declarations: `(variable_declarator name: (identifier) value: (_))`
- Call expressions: `(call_expression function: (member_expression) arguments: (_))`
- Member expressions: `(member_expression object: (_) property: (property_identifier))`

**Note**: We can start with manual AST walking instead of S-expression queries for P1, since tree-sitter-javascript provides `node.children()` and `node.kind()`.

## Implementation Steps

### Step 1: Add `tree-sitter-javascript` dependency
- Add to `sentinel-taint/Cargo.toml`:
  ```toml
  tree-sitter = "0.22"
  tree-sitter-javascript = "0.21"
  ```

### Step 2: Create `sentinel-taint/src/lib.rs`
- Define `TaintLevel`, `TaintContext`, `TaintEngine`, `TaintFinding`
- Implement `TaintEngine::new()` with default source/sink/sanitizer patterns for JS
- Implement `analyze_function()` using tree-sitter AST walking

### Step 3: Extend `sentinel-scanner/src/rules.rs`
- Add `mode`, `pattern_sources`, `pattern_sinks`, `pattern_sanitizers` to `Rule`
- Add `TaintEngine` import
- In `RuleEngine::scan()`, branch on `rule.mode == "taint"`
- Implement `analyze_taint_rule()` method

### Step 4: Wire into `sentinel-cli/src/audit.rs`
- No changes needed; `audit.rs` already calls `engine.scan(lang, source, path)` for all files

### Step 5: Update existing rules to declare `mode`
- For rules that need taint (`detect-child-process`, `dangerous-subprocess-use`), add `mode: taint` and `pattern-sources`/`pattern-sinks`
- For rules that work with static matching, leave `mode` absent (defaults to `search`)

### Step 6: Validation
1. `cargo check --workspace`
2. `cargo test --workspace`
3. `cargo run -- audit C:\projects\OpenConnect`
   - Expected: ≥ 5 findings (currently 3 without taint)
   - Specifically: `js-expose-process-env` should still fire, plus at least 2 new taint-based findings
4. If `detect-child-process` doesn't fire, add a debug print of taint state to verify the engine is tracking variables

## Risks
1. **False positives**: Intra-procedural taint will over-approximate. Any variable that touches a source will be marked tainted, even if it's later sanitized by a library function we don't recognize. Mitigation: start conservative, require explicit sanitizer patterns to clear taint.
2. **Performance**: Walking the AST for every function in every file could slow scans. Mitigation: benchmark on OpenConnect; if > 2s, add caching per file.
3. **Complexity**: Tree-sitter AST walking is verbose. Mitigation: use tree-sitter's built-in query language (`tree_sitter::Query`) instead of manual walking if the API is stable.

## Fallback
If P1 proves too complex, fall back to P2 (expand static rules) which is lower risk and still increases coverage.
