# Sentinel project review

Reviewed on 4 October 2026 against the working tree, including existing uncommitted changes. All eight crates, the bundled YAML rules, manifests, CLI paths, persistence, report formats, and README were inspected. Application source was not changed by this review.

## Assessment

The crate boundaries are a useful foundation, but the current implementation is not ready to be trusted as a security audit tool. Its largest risk is false reassurance: incomplete or failed scans can look like successful scans with no findings. Several advertised rules cannot detect their intended cases, and external scanner results are lost.

P1 means fix before relying on results or releasing the tool. P2 means a substantial correctness or operational defect. Examples below are derived from source inspection unless explicitly described as executed checks. This review does not claim an exhaustive proof of correctness.

## Findings

### 1. P1 — Bundled rules depend on the original build machine's source directory

Location: `crates/sentinel-cli/src/audit.rs:49`.

`env!("CARGO_MANIFEST_DIR")` embeds an absolute build-time directory, and audit loads YAML files from its sibling scanner crate. Moving the binary to another machine, or deleting the checkout, removes its rule coverage. The load error is silently ignored by `if let Ok(engine)`. A distributed executable can therefore report no findings without running its main scanner.

Embed bundled rules in the executable or package them in a resolved installation directory. Fail visibly when required rules cannot load. Verify a relocated binary against a vulnerable fixture outside the source checkout.

### 2. P1 — Scanner failures are presented as successful coverage

Locations: `crates/sentinel-cli/src/audit.rs:32`, `crates/sentinel-cli/src/diff.rs:32`, `crates/sentinel-scanner/src/lib.rs:57`.

Audit invokes every discovered scanner with only the target path; diff supplies only `--` and `.`. There are no scanner-specific subcommands, JSON options, rule configuration, or recursive options. The adapters nevertheless expect JSON. All execution and parsing errors are swallowed, and the scanner is added to `scanners_used` even when it failed. Every nonzero subprocess status is rejected without examining potentially useful output.

Implement an adapter contract for each supported scanner: invocation, structured output, exit-code interpretation, timeout, and errors. Report attempted, completed, and failed scanners separately, and propagate incomplete coverage to the command outcome.

### 3. P1 — External findings are truncated or replaced with placeholders

Locations: `crates/sentinel-scanner/src/lib.rs:74`, `:102`, `:153`.

Semgrep and Bandit parsers return only `results.first()`. Every other result is discarded. Their IDs contain only the scanner and rule ID, so separate occurrences of one rule overwrite each other in SQLite. Trivy and Gitleaks return a fabricated Info finding even when the output describes no vulnerabilities, rather than parsing real results.

Return a collection of findings, distinguish occurrence identity from rule identity, and implement real adapters or remove unsupported scanners from discovery. Test empty, multiple, malformed, and partial-result responses.

### 4. P1 — Diff does not scan the changed-file set

Location: `crates/sentinel-cli/src/diff.rs:8`.

The changed list is used only for display and a count. Every external scan targets `.`; bundled rules are never run. On a system without external scanners, any changed vulnerable file produces an empty report. Unchanged files can appear when an external scanner succeeds. Plain `git diff` also excludes staged-only changes and untracked files. Line-delimited Git output is unsuitable for quoted or newline-containing filenames.

Reuse the audit pipeline with explicit file inputs. Resolve repository paths, define working-tree/staged/untracked behavior, use NUL-delimited output, and test the command from a repository subdirectory.

### 5. P1 — Exclusion entries disable bundled rules

Locations: `crates/sentinel-scanner/src/rules.rs:35`, `:58`, `:260`, `:311`.

The YAML keys `pattern-not` and `pattern-not-inside` lack serde rename attributes, so those fields deserialize as absent. Independently, `matches_one` rejects every entry without a positive pattern. Such entries are normal exclusion constraints inside a positive `patterns` conjunction. Both `javascript-detect-insecure-websocket` and `python-insecure-hash-function` contain these entries and cannot satisfy the conjunction.

Deserialize all supported keys correctly and apply negative entries as constraints on positive match candidates. Retain protection against rules containing no positive selectors overall. Top-level context/exclusion fields also need evaluation; `matches` currently ignores them.

### 6. P1 — Two bundled taint rules have no surviving sink patterns

Location: `crates/sentinel-scanner/src/rules.rs:214`.

`extract_from_entry` discards patterns containing `$` and ignores source context/focus semantics. All sink expressions in `javascript-detect-child-process` and `javascript-detect-eval-with-expression` contain metavariables. Their sink collections become empty and `analyze_taint_rule` returns no findings unconditionally.

Either implement the required pattern semantics or rewrite the bundled rules into an explicitly supported dialect. Reject unsupported rules at load time rather than silently enabling inert rules.

### 7. P1 — Python call patterns use a nonexistent grammar node kind

Location: `crates/sentinel-ast/src/ast_query.rs:137`.

Python calls are represented by `call`, while `infer_node_kinds` selects `call_expression`. Consequently `ssl._create_unverified_context(...)` cannot match the ordinary Python call it is meant to detect. Rust coverage tests do not exercise this branch.

Use grammar-specific node kinds and add positive and negative fixtures for each supported language, including valid function bodies rather than relying only on parser recovery.

### 8. P1 — Metavariable patterns are compared as literal source text

Locations: `crates/sentinel-scanner/src/rules.rs:181`, `crates/sentinel-ast/src/ast_query.rs:84`.

Non-ellipsis patterns use `source.contains`, so `$BUILDER.set_verify(...)` requires the literal `$BUILDER` in Rust source. Ellipsis matching also retains metavariables literally in its prefix/suffix. The bundled OpenSSL rule and ordinary rustls receiver calls therefore miss their intended code. The reqwest patterns add dots on both sides of the ellipsis, which does not fit a direct single-dot builder chain.

Provide actual metavariable and call-chain matching, or constrain the bundled rules to the matcher capabilities. Validate every bundled rule with at least one intended triggering fixture.

### 9. P1 — Taint traversal skips calls in assignment right-hand sides

Location: `crates/sentinel-taint/src/lib.rs:198`.

The assignment branch updates the destination variable and returns without visiting its children. `let cmd = process.env.CMD; let result; result = spawn(cmd);` skips the sink call, while the equivalent `let result = spawn(cmd)` is traversed and can be detected. Calls and nested assignments on the right-hand side are not inspected.

Traverse assignment children with correct evaluation ordering and test sinks nested in assignments.

### 10. P1 — Branches and block scopes can erase real taint

Locations: `crates/sentinel-taint/src/lib.rs:150`, `:189`, `:215`.

All branches update the same function context sequentially, and blocks do not establish lexical scope. In `let cmd = process.env.CMD; if (flag) { cmd = "safe"; } spawn(cmd);`, the conditional assignment marks cmd clean even when the branch does not execute. In `let cmd = process.env.CMD; { let cmd = "safe"; } spawn(cmd);`, a block-local declaration incorrectly clears the outer variable. Nested functions also consult only their own context and miss captured tainted values.

Model lexical bindings and merge possible taint states conservatively across branches. Document any remaining limitations and avoid implying complete intra-procedural coverage.

### 11. P2 — Sanitization is based on substring presence

Locations: `crates/sentinel-taint/src/lib.rs:181`, `:268`, `:273`.

Any sanitizer name anywhere in an initializer clears all taint. For example, with `escapeHtml` registered, `let data = user_input + escapeHtml("safe"); exec(data);` is considered clean although raw input remains. Conversely, a direct `exec(escapeHtml(user_input))` does not apply sanitizer logic at the sink. Source and sink matching also inspect raw call text, including literals, rather than binding the relevant callee and value.

Evaluate sanitizer effects on the expression they actually transform, and apply the same evaluation at sinks and assignments. Add mixed sanitized/unsanitized expressions and source-like string literals to tests.

### 12. P2 — Non-taint matching loses occurrences and source locations

Locations: `crates/sentinel-scanner/src/rules.rs:132`, `:362`.

The matcher returns a file-level Boolean and emits only one finding per rule per file. Multiple vulnerable occurrences are lost. Location lookup tries to compile literal patterns as regexes, treats ellipsis/metavariable patterns as raw search strings, and uses the first alternative regardless of which alternative matched. The line counter also overcounts matches following text on their line. AST findings commonly fall back to line 1.

Return source spans from matching and emit an occurrence for each real match. Separate literal search from regex search and derive locations directly from byte offsets or AST positions.

### 13. P2 — Pattern conjunctions match unrelated code and comments

Locations: `crates/sentinel-scanner/src/rules.rs:186`, `:260`, `:332`.

All conditions are evaluated against the entire file. A WebSocket listener in one function and `JSON.parse` in an unrelated trusted function satisfy `js-unsafe-json-parse`. A string or comment containing a Rust pattern also counts as executable use. Context constraints similarly do not establish that the positive match is inside the required region.

Evaluate candidate spans and their containing AST scopes. Make text-only rules explicit so their lower precision is visible.

### 14. P2 — Finding storage has no scan lifecycle

Locations: `crates/sentinel-scanner/src/rules.rs:137`, `crates/sentinel-taint/src/lib.rs:71`, `crates/sentinel-db/src/lib.rs:68`.

Bundled findings receive fresh random IDs on each scan. Audit only inserts and never expires previous results. Repeated audits accumulate duplicate findings, and fixed or deleted vulnerabilities remain explainable as if still current. External rule-only IDs have the opposite problem: they overwrite distinct occurrences.

Store scan records and stable occurrence fingerprints, distinguish history from current results, and write the scan transactionally. Do not ignore insert failures in audit.

### 15. P2 — Audit and follow-up commands disagree about database location

Locations: `crates/sentinel-cli/src/audit.rs:67`, `crates/sentinel-cli/src/explain.rs:5`, `crates/sentinel-cli/src/rules.rs:4`.

Audit writes into the target directory, but explain and rules open `.sentinel.db` in the current working directory. `sentinel audit C:\other-project` followed by explain from the original directory accesses the wrong database. Opening creates a missing database, so the missing-database message is not a reliable check. Auditing an existing individual source file also tries to create `file.rs/.sentinel.db` and fails after scanning it.

Use an explicit shared project/database location, distinguish read-only opening from creation, and define file-target storage behavior.

### 16. P2 — The rules command cannot list the loaded rules

Locations: `crates/sentinel-cli/src/rules.rs:13`, `crates/sentinel-db/src/lib.rs:118`.

Rules lists the database rules table, but no production code calls `upsert_rule`. Audit loads rules only into memory. A new audit therefore leaves `sentinel rules` saying no rules found despite actively loading bundled rules.

List rules from the same RuleEngine used to scan, or persist the loaded catalog as part of the scan lifecycle.

### 17. P2 — Memory writes do not replace values by key

Locations: `crates/sentinel-db/src/lib.rs:58`, `:137`.

The memory table has a primary key on id, but `set_memory` does not supply id, and key has no uniqueness constraint. SQLite's ordinary rowid-table TEXT primary key permits null here. Repeated writes to one key create multiple rows; `get_memory` returns an arbitrary first row, potentially the obsolete value.

Make key the primary key or unique and upsert on that key. Test two writes and a read. This API is currently unused by the CLI, so its immediate user impact is lower than scan defects.

### 18. P2 — Advertised export options are unavailable

Locations: `crates/sentinel-cli/src/main.rs:25`, `README.md` output-format examples.

The CLI accepts only `Audit { path }`. `--format json` and `--format sarif` from the README are rejected; both renderers are unreachable through the CLI. SARIF also writes native Windows paths without URI conversion and accepts startLine 0 from external placeholders, producing invalid or unusable locations.

Expose and validate output format selection. Ensure machine output contains no terminal decoration, encode paths as URIs, and validate SARIF regions and stable rule IDs.

### 19. P2 — Symbol indexing omits members and nested definitions

Locations: `crates/sentinel-ast/src/lib.rs:147`, `:178`, `:220`.

The extractor records a recognized definition but does not recurse into it. Python and TypeScript class methods, nested functions, Rust impl methods, and module contents are skipped. Rust impl_item looks for a name field, and arrow functions usually have no name field, so those paths also fail to index their expected symbols. The displayed symbol count is therefore incomplete even for simple projects.

Traverse bodies after recording definitions and extract names through grammar-specific fields and parent bindings. Add class, impl, module, and arrow-function fixtures.

### 20. P2 — Scanner execution and file traversal are unbounded

Locations: `crates/sentinel-scanner/src/lib.rs:63`, `crates/sentinel-ast/src/lib.rs:55`, `crates/sentinel-cli/src/audit.rs:24`.

Subprocess output waits indefinitely and captures unlimited stdout/stderr. A hanging scanner blocks the audit. Skip-directory checks occur only after the walker reaches files, so excluded directories can still be traversed where ignore rules do not prune them. Audit reads files twice and the matcher reparses source/compiles regexes repeatedly; no file-size boundary is enforced.

Add scanner timeouts and output limits, prune directories at walk entry, reuse file contents and parsed trees, and compile rules once. Measure these changes on large fixtures rather than assuming a performance gain.

## Additional operational gaps

- The TUI does not check for EOF. Closed stdin repeatedly prints the menu and invalid-option message. Handle read_line returning zero and recover from individual command failures inside the menu loop.
- Audit returns success even when findings exist, and most follow-up errors become successful printed messages. Define documented exit codes for completed clean scans, findings over a threshold, and incomplete/failed scans before offering CI enforcement.
- The LLM client ignores api_key and prompt-template contents; a missing response field is treated as a successful empty explanation. Either support those public configuration fields or remove them until implemented. No live Ollama service was tested.
- Parsing errors, invalid regexes, unknown YAML keys, and unsupported semantics often silently yield no matches. Validate rules at load time with actionable diagnostics.
- Rule severity mappings differ between bundled and external adapters. An ERROR becomes Critical in one and High in another; WARNING becomes High versus Medium. Establish one documented mapping.
- The process.env regex rule flags any environment access while its message claims a flow into an untrusted child process. JSON.parse rules similarly overstate what parsing alone establishes. Align rule names, evidence, severity, and messages with the behavior actually proven.
- No tracked CI workflow or end-to-end CLI tests were found. The repository contains seven unit tests, mostly positive happy-path examples, and no tests in persistence, report, LLM, core, or CLI. Strong lint results cannot establish scanner correctness.
- The root-only database ignore rule does not exclude databases produced by auditing subdirectories; `crates/.sentinel.db` was already untracked when this review started.
- README descriptions of tests passing, compiled-in rules, export flags, matcher behavior, and current limitations need to be reconciled with the implementation.

## Executed validation

- Initial `cargo test --workspace` failed on three Vec-versus-slice borrow errors in ast_query.rs. Concurrent workspace edits corrected these during review; they are not listed as a remaining source defect.
- Latest `cargo check --workspace` passed.
- Latest `cargo clippy --workspace --all-targets -- -D warnings` passed.
- Tests for sentinel-ast passed (2 tests), and sentinel-taint passed (3 tests). Selected core, db, and report test targets passed but contain zero unit tests.
- Full workspace tests remained blocked by the Windows GNU linker: `ld: cannot find -lktmw32`. Another attempt also encountered unavailable dlltool. These are local toolchain limitations, not demonstrated application source defects.
- Formatting check failed. Its output was kept in the host temporary directory rather than modifying source.
- No live external scanner integration, release relocation, dependency vulnerability audit, SARIF schema validation, or Ollama integration was executed. Most behavior findings above are source-derived and require regression fixtures when repaired.

## Recommended repair order

1. Make scan completion and failure explicit; package bundled rules reliably and correct scanner adapters.
2. Repair rule loading/semantics and prove every bundled rule with positive and negative fixtures.
3. Fix taint assignment traversal, scope, branch joins, and sanitizer evaluation.
4. Share one audit pipeline with diff; add CLI integration tests and documented exit codes.
5. Fix occurrence identity, scan lifecycle, database selection, and persistence error handling.
6. Wire up exports, validate SARIF, repair symbol indexing, and add resource bounds.

The release gate should be behavior-based: a relocated executable must detect the intended vulnerable fixtures, reject or clearly label incomplete coverage, preserve all occurrences, and avoid flagging matched safe fixtures. A compiling workspace alone is insufficient.
