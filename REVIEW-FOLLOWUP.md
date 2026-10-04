# Sentinel remediation review

Reviewed 4 October 2026 at HEAD `9c83565`, including the current working tree. Application source was not changed. This follow-up assesses actual behavior against the earlier review and implementation plan.

## Verdict

Some foundational fixes work, but the seven remediation phases are not complete. Do not treat the phase commit titles as acceptance evidence. The core risk of false reassurance remains, and database upgrades introduce a new persistence regression.

Verified improvements: 19 bundled rules load from generated embedded data; Python SSL call detection works; taint sinks inside assignment right-hand sides are now visited. Diff uses the shared pipeline and NUL-delimited Git output. Empty external result arrays now produce no fabricated finding. Explicit outcome types and scan records exist. A CI workflow was added.

## Prioritized findings

### 1. P1 — File failures still produce Complete scans

`crates/sentinel-scanner/src/pipeline.rs:103`, `:185`, `:193`.

Read and UTF-8 failures append coverage notes without changing outcome. Missing explicit file inputs are silently filtered at line 93. A probe scanning a `.js` file containing byte 255 returned `Complete` with a UTF-8 failure note. The CLI can still exit successfully without analyzing the file. File counts represent selected inputs rather than successfully analyzed files.

Mark failures on intended source files incomplete, retain explicit missing-file errors, and distinguish attempted/analyzed/skipped counts. Report bundled scanner completion even when it returns zero findings. Structured ScanReport also needs outcome and coverage information.

### 2. P1 — Existing database migration silently fails

`crates/sentinel-db/src/lib.rs:99`, `:121`.

SQLite cannot add a column with a nonconstant CURRENT_TIMESTAMP default to the populated old findings table. The ALTER error is discarded. A probe with an old-schema row opened successfully, then insert_finding failed with `table findings has no column named created_at`.

Use versioned, transactional migrations with explicit schema checks and timestamp backfill. Never discard arbitrary migration errors. Migrate the old memory table as well; CREATE TABLE IF NOT EXISTS does not add key uniqueness to an existing table.

### 3. P1 — Persistence failures do not affect scan outcome

`crates/sentinel-scanner/src/pipeline.rs:256`, `:262`.

Failed finding inserts and scan-record writes print errors but leave outcome unchanged. This compounds the migration bug: audit can show findings that explain cannot retrieve and record a Complete scan despite lost data. Persistence remains nontransactional.

Persist the scan atomically and propagate failures into the command result. Do not record completion before persistence succeeds.

### 4. P1 — Scope and control-flow changes still lose taint

`crates/sentinel-taint/src/lib.rs:261`.

The new block handler looks for a body field and otherwise uses the same context. Ordinary statement blocks and if statements therefore still mutate shared bindings. Loop bodies use cloned contexts that are discarded instead of merged.

All three probes expected a tainted sink and returned zero findings:

```javascript
let data = user_input;
if (flag) { data = 'safe'; }
exec(data);
```

```javascript
let data = user_input;
{ let data = 'safe'; }
exec(data);
```

```javascript
let data = 'safe';
while (flag) { data = user_input; }
exec(data);
```

Implement lexical bindings separately from flow-state snapshots and conservatively merge possible branch/loop states. Also handle loop condition/update expressions rather than traversing only the body.

### 5. P1 — Exclusions and metavariable rules remain broken

`crates/sentinel-scanner/src/rules.rs:37`, `:62`, `:327`, `:339`, `:438`.

pattern-not and pattern-not-inside still lack serde renames. Exclusion-only entries inside conjunctions still return false. Dollar-containing taint patterns are still discarded, so child-process/eval rules retain empty sink sets. Validation does not reject this unsupported behavior.

Probes failed to detect both `new WebSocket('ws://example.com')` with the insecure-WebSocket rule and `eval(location.search)` with the eval rule. Python weak-hash patterns still include unsupported Semgrep string syntax.

Validate supported semantics and prove every bundled rule with triggering/nontriggering fixtures. None of the required per-rule fixture suite was added.

### 6. P1 — External scanner integration is still incomplete

`crates/sentinel-scanner/src/pipeline.rs:121`, `crates/sentinel-scanner/src/lib.rs:57`, `:91`, `:142`.

The pipeline still invokes scanners with no scanner-specific arguments. The normalizer returns Option<Finding> and only parses the first result. Nonzero statuses discard useful stdout, and subprocesses have no timeout/output limit. Trivy/Gitleaks remain discoverable although their normalization is now explicitly unsupported.

Implement real adapters and return collections. Removing fabricated findings and accepting empty arrays addresses only part of this phase. Live scanner integration was not executed in this review.

### 7. P2 — Reporting exits the entire application and masks incomplete status

`crates/sentinel-scanner/src/pipeline.rs:275`, `:290`.

persist_and_report calls process::exit(1) whenever any finding meets the default threshold. An incomplete scan with findings therefore exits 1 instead of the documented 2. An audit inside the TUI closes the entire application. ScanOptions.threshold is never used; the reporter always creates the default threshold.

Return outcome/report data to the caller. Choose exit codes once in main, prioritize incomplete/failed status, and keep the TUI running after audit.

### 8. P2 — Fingerprints do not deduplicate or resolve findings

`crates/sentinel-db/src/lib.rs:107`, `:121`, `crates/sentinel-scanner/src/rules.rs:246`.

The fingerprint index is nonunique, insert conflicts use random finding IDs, and no production code calls resolve_finding. Repeating one identical unsafe scan produced two unresolved rows in a probe. Fixed findings still remain current, and a repeated external rule ID can overwrite earlier history. Re-detection also preserves a prior resolved_at value.

Implement a scan-occurrence lifecycle with stable fingerprints, active/resolved status, history, and reactivation. Restrict resolution to successfully covered files, especially for diff/partial scans.

### 9. P2 — Rewritten rustls rule still misses normal receiver calls

`crates/sentinel-scanner/rules/rust/lang/security/rustls-dangerous.yml:6`, `crates/sentinel-ast/src/ast_query.rs:117`.

Removing $CLIENT leaves `dangerous().set_certificate_verifier(...)`, but matching still requires the node text to start with that prefix. A real call starts with `client.`. The probe `client.dangerous().set_certificate_verifier(verifier)` returned no rustls finding.

Match call-chain structure and receiver suffixes explicitly, rather than comparing only whole-node textual prefixes.

### 10. P2 — Diff selection remains incomplete

`crates/sentinel-cli/src/diff.rs:7`, `crates/sentinel-scanner/src/pipeline.rs:121`.

Only unstaged tracked changes are collected. Staged-only and untracked files remain excluded. Repository-relative names are interpreted relative to the current directory, causing missing or wrong file selection from subdirectories. External scanners still receive the whole target directory rather than explicit changed inputs.

Resolve repository root paths, define change-selection flags/defaults, and apply the selected set consistently to every scanner.

### 11. P2 — Database selection, rule listing, and exports remain unfinished

`crates/sentinel-scanner/src/pipeline.rs:247`, `crates/sentinel-cli/src/explain.rs:4`, `crates/sentinel-cli/src/rules.rs:3`, `crates/sentinel-cli/src/main.rs:25`.

Audit still writes into target/.sentinel.db while explain/rules open cwd/.sentinel.db. Individual-file targets still attempt file.rs/.sentinel.db. The rules table has no production writer. --format and threshold flags remain absent, while README still advertises JSON/SARIF flags. SARIF paths and occurrence IDs remain unchanged.

Finish shared database selection, catalog listing, export wiring, and valid SARIF output before calling the persistence/reporting phase complete.

### 12. P2 — CI gates currently fail and behavioral coverage is absent

`crates/sentinel-db/src/lib.rs:181`, `crates/sentinel-scanner/src/lib.rs:78`, `.github/workflows/ci.yml:14`.

Strict Clippy fails on record_scan's nine arguments. Formatting fails in the unsupported-scanner error arm. The seven repository unit tests are unchanged; no CLI, migration, scanner-adapter, or per-rule regression suite was added. CI runs --lib tests, so it does not exercise CLI behavior. No hosted CI result was inspected.

Fix the gates and add the behavioral acceptance tests from the plan. A phase should be considered complete only when those tests pass.

## Additional remaining issues

- Sanitizer detection remains substring-based and can clear a mixed raw/sanitized expression.
- Match results are still file-level Booleans: multiple occurrences are lost, locations remain guessed, and unrelated scopes/comments can satisfy patterns.
- severity validation accepts high/low/critical, but severity() maps them to Medium. compiled_regex is populated but matches() recompiles the regex instead of using it; nested regexes are not validated upfront.
- The symbol extractor still does not recurse into recognized classes, functions, impls, or modules; arrow-function names and impl fields remain unhandled. The Phase 7 commit did not implement the claimed extraction repairs.
- Directory pruning, file-size limits, source/tree reuse, and LLM configuration handling remain unfinished.
- TUI read_line checks is_err, but EOF is Ok(0), so empty stdin loops forever.
- Scanner crate now imports database and terminal-report crates, coupling analysis to storage/UI. Keep orchestration and exit handling in the CLI, or use a separate application layer.
- The build script silently skips unreadable rule files/directories. Packaging should fail if required bundled assets cannot be collected.

## Executed validation

| Check | Result |
|---|---|
| cargo check --workspace | Passed |
| Strict workspace Clippy | Failed: record_scan has too many arguments |
| Formatting check | Failed: scanner error arm |
| Selected AST/taint/core/db/report tests | Passed; only 5 actual unit tests in these targets |
| Full workspace and scanner tests | Blocked by local GNU linker missing ktmw32 |
| Isolated behavioral probes | 3 passed, 9 failed |

The probes compile the actual current rule/pipeline source by path, use its generated embedded rules, and depend on current AST/taint/database crates. External discovery is stubbed to return no scanners, allowing deterministic bundled-pipeline checks without the scanner crate's Windows linker dependency. They do not establish end-to-end CLI behavior.

Probe source: `C:/Users/kusha/AppData/Local/Temp/sentinel-review-7ea05223da454e4d83e8447a9af6fe26/src/lib.rs`.

Passed probes: embedded rules load and match; Python SSL call fix; assignment-right-hand-side traversal. Failed probes: conditional taint, block shadowing, loop propagation, insecure WebSocket rule, eval rule, rustls receiver rule, invalid UTF-8 outcome, populated old-schema migration, repeated-scan deduplication.

## Next implementation pass

1. Fix outcome propagation, migration, and persistence-error handling first.
2. Repair rule constraints and unsupported-pattern handling with per-rule fixtures.
3. Replace the taint scope workaround with tested binding and flow-state handling.
4. Complete external adapters and exit-code handling without process exits in library code.
5. Finish lifecycle, diff path selection, database selection, and exports.
6. Require the regression suite and CI gates to pass before marking phases complete.
