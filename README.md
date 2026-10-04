# Sentinel

An offline-first static code auditor for Rust, Python, JavaScript, and TypeScript.
The default scan uses 19 embedded rules and requires no external scanner or network.
Optional Semgrep/Bandit scans and AI explanations must be requested explicitly.
Explain findings or the codebase with local Ollama, NVIDIA NIM, or both models
concurrently using the same context snapshot.

Sentinel is currently suitable for evaluation and controlled pilots. Its rule
coverage and approximate taint analysis have not been independently benchmarked;
a successful scan is not a guarantee that a project has no vulnerabilities.

## Contents

- [Build and run](#build-and-run)
- [Changed-file scans](#changed-file-scans)
- [Optional external scanners](#optional-external-scanners)
- [Persistence and explanations](#persistence-and-explanations)
- [Hybrid AI and codebase explanations](#hybrid-ai-and-codebase-explanations)
- [Rule dialect](#rule-dialect)
- [Architecture](#architecture)
- [Scan execution](#scan-execution)
- [Rule execution](#rule-execution)
- [Database model](#database-model)
- [Finding lifecycle](#finding-lifecycle)
- [Verification](#verification)

## Build and run

```sh
cargo build --release --bin sentinel
sentinel audit /path/to/project
sentinel audit /path/to/project --format json
sentinel audit /path/to/project --format sarif --threshold high
sentinel audit /path/to/file.rs
sentinel rules
sentinel tui
```

`--format` accepts terminal, json, or sarif. JSON and SARIF go to stdout without
terminal decoration. Reports expose completion status and coverage notes.

Exit codes:

- 0: complete scan with no findings at or above the threshold.
- 1: complete scan with findings at or above the threshold.
- 2: failed or incomplete scan, including persistence failure.

The default threshold is info. `--threshold` accepts info, low, medium, high,
or critical. A higher threshold changes the exit code, not the findings returned.
An incomplete scan takes precedence over findings when choosing the exit code.

## Changed-file scans

```sh
sentinel diff
sentinel diff --staged --format json
sentinel diff --unstaged --format sarif
sentinel diff --tracked-only
```

Default diff selects staged changes, unstaged changes, and untracked files.
`--staged` and `--unstaged` select only that tracked change category.
`--tracked-only` excludes untracked files from the default selection.
Paths resolve from the repository root, including when invoked in a subdirectory.
Deleted tracked files are not read; complete diff coverage can resolve their
previous findings. External scanners receive the selected files, not the whole project.

## Optional external scanners

```sh
sentinel audit . --external-scanners
sentinel audit . --external-scanners --semgrep-config ./my-semgrep-rules.yml
sentinel diff --external-scanners --semgrep-config ./my-semgrep-rules.yml
```

Only Semgrep and Bandit are supported. Semgrep requires a local configuration
file or directory written in Semgrep's dialect. Sentinel's bundled rule files
are not a full Semgrep-compatible configuration. Semgrep metrics and version
checks are disabled. Bandit runs only on selected Python files.

Each available scanner has a separate completion result. Missing optional
scanners are recorded as unavailable; requesting external scans with no
applicable available scanner marks the scan incomplete. Malformed or partial
scanner output also marks the scan incomplete while retaining valid findings.

The subprocess timeout defaults to 60 seconds and is configurable with
`--scanner-timeout`. Stdout is limited to 8 MiB and stderr to 64 KiB.
A source file larger than 10 MiB is reported as incomplete coverage.
Syntax errors and excessive syntax nesting are reported rather than treated as
clean source. Unsupported languages and binary files are identified as skipped.

## Persistence and explanations

Each project stores `.sentinel.db` in its audited directory. A single-file
audit stores it beside the file. `--db` overrides the database used by audit,
diff, or either explanation command.

```sh
sentinel explain FINDING_ID --project /path/to/project
sentinel explain FINDING_ID --db /path/to/.sentinel.db
```

Finding explanation requires an existing database and finding. Its default
provider is Ollama at localhost:11434 with model llama2; the model and endpoint
are configurable. Before calling AI, the shared project context is stored in the
database's `memory` table. Codebase explanation can create a database without a
prior scan. `--context-only` previews the payload without provider requests or
database writes. A failed provider returns exit `2`; successful responses from
other requested providers are preserved.

Schema upgrades, findings, and scan records are transactional. SHA-256
fingerprints identify occurrences by normalized file path, line, category,
rule title, and evidence (including columns when available). Repeated scans
update the same current occurrence. Scan
snapshots preserve history. Complete coverage resolves missing occurrences;
incomplete scans never resolve old findings, and diff resolves only selected files.
Full scans preserve findings in existing files that were skipped or not analyzed;
they can resolve findings in analyzed files and files deleted from the target.
Reappearing occurrences become active again. Moving an occurrence to another
line or column gives it a new identity.

## Hybrid AI and codebase explanations

Use `explain` for a persisted security finding, or `explain-codebase` to understand
a project without first auditing it. Both commands support a custom question.

```sh
# Local model only
sentinel explain-codebase . --provider local --local-model llama2

# Inspect the exact shared context and messages without calling AI
sentinel explain-codebase . --context-only

# Ask about a specific part of the project
sentinel explain-codebase . --question "How do findings reach the database?"

# Cloud only, or both providers concurrently
sentinel explain-codebase . --provider nim --nim-model YOUR_NIM_MODEL_ID
sentinel explain-codebase . --provider both --nim-model YOUR_NIM_MODEL_ID --json

# The same provider choices apply to finding explanations
sentinel explain FINDING_ID --project . --provider both --nim-model YOUR_NIM_MODEL_ID
```

Choose a model ID available in your NVIDIA account. Sentinel uses NVIDIA's
[chat-completions API](https://docs.api.nvidia.com/nim/reference/llm-apis) with
base URL `https://integrate.api.nvidia.com/v1` and bearer authentication.
Set the key in the process environment, rather than passing it on the command line:

```powershell
# PowerShell: enter the key without putting it in shell history
$nimCredential = Get-Credential -UserName NVIDIA -Message "Enter your NVIDIA API key as the password"
$env:NVIDIA_API_KEY = $nimCredential.GetNetworkCredential().Password
$env:SENTINEL_NIM_MODEL = "YOUR_NIM_MODEL_ID"
sentinel explain-codebase . --provider both --json
```

| Option | Environment variable | Default |
| --- | --- | --- |
| `--provider` | — | `local`; accepts `local`, `nim`, `both` |
| `--local-model` | `SENTINEL_LOCAL_MODEL` | `llama2` |
| `--local-endpoint` | `SENTINEL_LOCAL_ENDPOINT` | `http://localhost:11434` |
| `--nim-model` | `SENTINEL_NIM_MODEL` | Required for `nim` or `both` |
| `--nim-endpoint` | `SENTINEL_NIM_ENDPOINT` | `https://integrate.api.nvidia.com/v1` |
| `--nim-key-env` | Names the key variable | `NVIDIA_API_KEY` |
| `--ai-timeout` | — | `60` seconds per provider |
| `--context-bytes` | — | `12000`; range `1024`–`65536` |
| `--context-only` | — | Preview only; no model or key required |
| `--question` | — | Architecture overview or finding explanation |
| `--json` | — | Structured responses and failures |

CLI values take precedence over environment configuration. There is **no
automatic fallback**: `local` calls only Ollama, `nim` calls only NVIDIA NIM,
and `both` calls both concurrently. Each answer is labeled with provider, model,
and context ID. If one fails, the other answer remains available and the command
returns exit `2`. No model arbitrates or silently merges the answers.

### Shared context architecture

One request builds one immutable context bundle and one system/user message
sequence. Both providers receive identical messages, including the same source
evidence and question. The providers still have independent native token windows
and inference state; Sentinel shares the input evidence rather than model memory.

```mermaid
flowchart TB
    Command["explain / explain-codebase<br/>question and optional finding"]
    Project["Local project<br/>sources, manifests, documentation"]
    Index["Shared context builder<br/>file inventory and AST symbols"]
    Retrieve["Lexical retrieval<br/>relevant snippets and finding-line focus"]
    Snapshot["Immutable context snapshot<br/>SHA-256 ID and coverage notes"]
    Memory[("SQLite memory<br/>latest local context")]
    Preview["--context-only<br/>inspect exact payload"]
    Request["Common system and user messages"]
    Route{"User-selected provider"}
    Local["Ollama /api/chat<br/>local or both"]
    Cloud["NVIDIA NIM /v1/chat/completions<br/>nim or both"]
    Results["Separate labeled answers<br/>shared context ID and per-provider errors"]

    Project --> Index --> Retrieve --> Snapshot
    Command --> Retrieve
    Snapshot --> Preview
    Snapshot -->|"normal execution only"| Memory
    Snapshot --> Request --> Route
    Route --> Local
    Route --> Cloud
    Local --> Results
    Cloud --> Results

    classDef shared fill:#dbeafe,stroke:#2563eb,color:#172554;
    classDef cloud fill:#fef3c7,stroke:#d97706,color:#78350f;
    class Index,Retrieve,Snapshot,Request shared;
    class Cloud cloud;
```

The context includes project-relative paths, content hashes, symbol locations,
and numbered source excerpts. Finding explanations prioritize the affected file
and line. Context is rebuilt from current files for each request; its ID changes
when the included evidence changes. `memory["ai.context.latest"]` stores the
latest bundle locally, independent of provider choice. This is evidence sharing,
not a persistent multi-turn chat session or a vector database.

Retrieval considers at most 256 eligible files, reads files up to 256 KiB, and
uses a bounded source-read budget of roughly 4 MiB. It selects up to 20 excerpts,
each capped at 40 lines and 2500 bytes, then fits them and the inventory into
the configured context-byte budget. Large repositories can have partial context;
coverage notes describe truncation and indexing failures. Increase the byte
budget only within the selected models' context limits: byte budgets are not
token budgets. Ollama requests an 8192-token context window and up to 2048 output
tokens; NIM requests up to 2048 output tokens.

The builder honors the project walker exclusions, omits hidden and known
credential/key filenames, and rejects paths resolving outside the project root.
It does **not** guarantee secret redaction inside ordinary source or documentation.
`nim` and `both` send the included context and finding to the configured cloud
endpoint. Use the preview to inspect that evidence. API key configuration is not
stored in SQLite, included in prompts, or printed in provider diagnostics.

AI answers are advisory. The prompt requests source citations and separates
evidence from inference, but citations and claims still need review. AI output
does not modify code, create scan findings, change finding resolution, or execute
repository instructions. HTTP requests have timeouts, response bodies are capped
at 2 MiB, redirects are disabled, and incomplete model responses are reported as
provider failures.

## Rule dialect

Rules are validated and compiled when loaded. Supported selectors are:

- `pattern`: literal code or a call/block pattern with `...` wildcards.
- `pattern-regex`: regex against executable AST nodes for code-language rules.
- `languages: [regex]`: explicit text matching, including strings and comments.
- `patterns` and `pattern-either`: conjunction and alternatives over candidates.
- `pattern-not`, `pattern-not-regex`, `pattern-inside`, and
  `pattern-not-inside`: exclusions and AST context constraints.
- `mode: taint`: JavaScript/TypeScript source-to-sink analysis with simple
  structural source, sink, and sanitizer names.

Conjunctions must match overlapping candidates. They do not associate unrelated
expressions elsewhere in a file. Plain code selectors ignore comments and
string-only matches. Regex-language rules intentionally search text.

The dialect does not implement Semgrep metavariable binding, focus-metavariable,
metavariable-pattern, or Semgrep string-regex syntax. Unsupported keys and
patterns, invalid regexes, duplicate IDs, and missing positive selectors are
rejected with diagnostics. Taint rules require nonempty supported sources/sinks;
they are never silently discarded.

Taint analysis handles identifier assignments, lexical shadowing, captured
bindings, conservative branch joins, and loop fixed points. Sanitizers affect
only the expression they transform. Function-parameter audit rules use the
explicit `@parameter` source. Analysis is approximate: it does not resolve module
imports, compute general interprocedural summaries, or precisely distinguish
object fields and dynamic aliases. Generic execution calls and environment
reads are audit signals, not proof of exploitability. Remaining unsupported
language features and complex control flow require manual review.

Bundled rules are generated at build time; collecting unreadable or missing
assets fails the build. Add or edit YAML under crates/sentinel-scanner/rules,
then rebuild. `sentinel rules` lists the loaded catalog without requiring a scan.

## Architecture

The CLI owns command routing, persistence, output, and process exit codes. The
scanner returns a result rather than exiting the process, so the same pipeline
can serve audit, diff, and the interactive TUI. The diagram shows runtime data
flow; arrows do not represent the complete Cargo dependency graph.

```mermaid
flowchart TB
    User["Developer or CI"] --> CLI["sentinel-cli<br/>commands and file selection"]

    subgraph Local["Local scan boundary - default execution"]
        Pipeline["sentinel-scanner<br/>scan orchestration and coverage"]
        AST["sentinel-ast<br/>parsing, spans, and symbols"]
        Rules["RuleEngine<br/>embedded selectors and constraints"]
        Taint["sentinel-taint<br/>JS / TS flow approximation"]
        Result["ScanPipelineResult<br/>sentinel-core findings and outcomes"]
        Finish["CLI finish<br/>persist, render, choose exit code"]
        DB[("sentinel-db<br/>.sentinel.db history")]
        Report["sentinel-report<br/>terminal / JSON / SARIF"]

        Pipeline --> AST
        Pipeline --> Rules --> Taint
        Pipeline -->|"aggregate results"| Result
        Result --> Finish
        Finish --> DB
        Finish --> Report
    end

    CLI -->|"audit / diff / tui"| Pipeline
    CLI -->|"rules catalog"| Rules

    subgraph Optional["Explicit integrations"]
        Adapters["Semgrep / Bandit adapters<br/>bounded execution and normalization"]
        LLM["sentinel-llm<br/>shared context and local / NIM explanations"]
    end

    Pipeline -.->|"--external-scanners"| Adapters
    Adapters -.->|"findings and diagnostics"| Result
    CLI -.->|"explain / explain-codebase"| LLM

    classDef entry fill:#dbeafe,stroke:#2563eb,color:#172554;
    classDef storage fill:#dcfce7,stroke:#16a34a,color:#14532d;
    classDef optional fill:#fef3c7,stroke:#d97706,color:#78350f;
    class CLI,Finish,Result entry;
    class DB storage;
    class Adapters,LLM optional;
```

Solid arrows show local scan orchestration. Dashed arrows show
explicit integration paths. External scanners are local processes; their own
configuration determines any additional behavior. AI providers are contacted
only by explanation commands, using the explicitly selected provider mode.

| Crate | Responsibility | Main implementation |
| --- | --- | --- |
| `sentinel-cli` | Commands, file selection, persistence, rendering, exit codes | [main.rs](crates/sentinel-cli/src/main.rs), [scan.rs](crates/sentinel-cli/src/scan.rs), [diff.rs](crates/sentinel-cli/src/diff.rs) |
| `sentinel-core` | Shared findings, severity, fingerprints, and completion models | [models.rs](crates/sentinel-core/src/models.rs) |
| `sentinel-ast` | Walking, language detection, parsing, spans, and symbols | [lib.rs](crates/sentinel-ast/src/lib.rs), [ast_query.rs](crates/sentinel-ast/src/ast_query.rs) |
| `sentinel-taint` | Lexical environments and approximate source-to-sink tracking | [lib.rs](crates/sentinel-taint/src/lib.rs) |
| `sentinel-scanner` | Embedded rule execution, adapters, and coverage aggregation | [pipeline.rs](crates/sentinel-scanner/src/pipeline.rs), [rules.rs](crates/sentinel-scanner/src/rules.rs) |
| `sentinel-db` | Versioned SQLite migration, current findings, and snapshots | [lib.rs](crates/sentinel-db/src/lib.rs) |
| `sentinel-report` | Terminal, JSON, and SARIF serializers | [lib.rs](crates/sentinel-report/src/lib.rs) |
| `sentinel-llm` | Shared project evidence and concurrent Ollama/NIM explanation requests | [lib.rs](crates/sentinel-llm/src/lib.rs), [context.rs](crates/sentinel-llm/src/context.rs) |

## Scan execution

Audit walks a target; diff constructs an explicit file set from Git. Both enter
the same pipeline. An empty diff stays empty rather than falling back to a full
project scan. Source failures accumulate coverage notes while other files can
still produce findings.

```mermaid
sequenceDiagram
    autonumber
    actor Developer
    participant CLI as CLI command
    participant Selection as Walker / Git selection
    participant Pipeline as Scan pipeline
    participant Analysis as AST / rule / taint engines
    participant External as Optional adapters
    participant DB as SQLite persistence
    participant Report as Report renderer

    Developer->>CLI: audit or diff with options
    CLI->>Selection: Resolve target and selected paths
    Selection-->>CLI: Canonical target and scan scope
    CLI->>Pipeline: run_scan(ScanOptions)
    Pipeline->>Analysis: Load and validate embedded rules
    loop Each selected source file
        Pipeline->>Pipeline: Bounded read and UTF-8 validation
        alt Supported source or text input
            Pipeline->>Analysis: Extract symbols and evaluate rules
            Analysis-->>Pipeline: Findings or analysis error
        else Unsupported language or binary input
            Pipeline->>Pipeline: Record skipped-file coverage note
        end
        Note over Pipeline: Read, decode, size, or syntax failures mark Incomplete
    end
    opt External scanning requested and analyzed inputs exist
        Pipeline->>External: Run available tools on selected inputs
        External-->>Pipeline: Valid findings and completion diagnostics
        Note over Pipeline,External: Timeout, output limits, and partial JSON are handled
    end
    Pipeline-->>CLI: Findings, scope, outcomes, and coverage notes
    opt Pipeline outcome is not Failed
        CLI->>DB: Migrate and persist scan transactionally
        alt Persistence succeeds
            DB-->>CLI: Commit scan, current findings, and snapshots
        else Persistence fails
            DB-->>CLI: Roll back and return error
            CLI->>CLI: Mark report Incomplete
        end
    end
    CLI->>Report: Render final report
    Report-->>Developer: Terminal, JSON, or SARIF
    CLI-->>Developer: Exit 0, 1, or 2
```

| Final condition | Exit | Meaning |
| --- | --- | --- |
| Complete, no finding meets the threshold | `0` | Scan completed within its reported scope |
| Complete, at least one finding meets the threshold | `1` | Findings need review |
| Incomplete or Failed | `2` | Coverage or execution failed; inspect diagnostics |

Skipped-file notes must still be reviewed: `Complete` describes the implemented
scan scope, not universal language coverage. Findings remain in the report even
when they fall below the exit threshold or another scanner fails.

## Rule execution

Embedding makes the executable portable; semantic validation happens when the
rule engine loads. Invalid rules produce diagnostics instead of silently
disabling detection. This is Sentinel's own limited dialect, not a replacement
for the full Semgrep engine.

```mermaid
flowchart TB
    YAML["YAML assets"] --> Embed["Build-time embedding<br/>deterministic ordering"]
    Embed --> Validate["Load-time validation<br/>IDs, languages, severity, selectors"]
    Validate -->|"unsupported or invalid"| Error["Rule diagnostic<br/>scan becomes Incomplete"]
    Validate -->|"valid"| Mode{"Rule kind"}

    Mode -->|"code selectors"| Parse["Parse and validate syntax"]
    Parse --> Candidates["Executable AST candidates<br/>source spans and enclosing contexts"]
    Candidates --> Constraints["All / any / exclusions<br/>overlap and context checks"]

    Mode -->|"regex language"| Text["Explicit raw-text regex matching"]
    Mode -->|"JS / TS taint"| Flow["Lexical environments<br/>assignments and captured bindings"]
    Flow --> Join["Branch joins and loop fixed points<br/>expression-local sanitizers"]
    Join --> Sink["Check source-to-sink flow"]

    Constraints --> Finding["Occurrence findings<br/>actual locations and stable IDs"]
    Text --> Finding
    Sink --> Finding

    classDef failure fill:#fee2e2,stroke:#dc2626,color:#7f1d1d;
    classDef success fill:#dcfce7,stroke:#16a34a,color:#14532d;
    class Error failure;
    class Finding success;
```

AST selectors avoid comment and string-only matches. Raw-text regex rules
deliberately include them. Taint tracking uses conservative joins, but it has no
general interprocedural summaries or precise dynamic alias model; its findings
are review signals rather than proof of exploitation.

## Database model

SQLite separates the current occurrence view from historical scan snapshots.
The schema below shows logical associations; these are not declared SQL foreign
key constraints. `findings.scan_id` identifies the last scan that observed an
occurrence and can contain a legacy identifier after migration.

```mermaid
erDiagram
    scans ||--o{ scan_findings : "contains snapshots"
    findings ||--o{ scan_findings : "identified by fingerprint"

    scans {
        TEXT id PK
        TEXT target
        TEXT outcome
        TEXT coverage_notes "JSON"
        INTEGER files_scanned
        INTEGER symbols_indexed
        TEXT scanners_used "JSON scanner results"
        INTEGER duration_ms
        TEXT created_at
    }
    findings {
        TEXT id PK
        TEXT fingerprint UK "SHA-256 occurrence identity"
        TEXT scan_id "last observed scan"
        TEXT file
        INTEGER line
        TEXT severity
        TEXT category
        TEXT title
        TEXT evidence "JSON"
        TEXT created_at
        TEXT resolved_at "NULL while active"
    }
    scan_findings {
        TEXT scan_id PK "composite key part"
        TEXT fingerprint PK "composite key part"
        TEXT snapshot "JSON finding at scan time"
    }
    memory {
        TEXT key PK
        TEXT value
    }
```

The findings table also stores confidence, description, execution path, affected
components, and recommendation; they are omitted from the diagram for clarity.
Migration preserves legacy lifecycle metadata when present. A failed scan write
rolls back its scan record, finding updates, snapshots, and resolution changes.

## Finding lifecycle

Resolution requires both a complete scan and the appropriate file scope. An
existing file omitted from a full scan does not lose its active findings. A
reappearing fingerprint reactivates the current row while scan snapshots retain
the earlier observations.

```mermaid
stateDiagram-v2
    [*] --> Active: First observed occurrence
    Active --> Active: Same fingerprint observed again
    Active --> Active: Incomplete scan or file outside covered scope
    Active --> Resolved: Complete scan and occurrence absent in eligible scope
    Resolved --> Resolved: Occurrence remains absent
    Resolved --> Active: Same fingerprint observed again

    note right of Active
        Current finding is upserted by fingerprint.
        Each observation has a per-scan snapshot.
    end note
    note right of Resolved
        Eligible scope means analyzed files,
        selected deletions in diff, or deleted
        files within a full-scan target.
    end note
```

A changed path, line, category, rule title, or evidence creates a different
fingerprint. Resolution does not delete the current finding row or historical
snapshots. The threshold controls the CLI exit code, not persistence or lifecycle.

## Verification

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The suite includes positive/negative fixtures for every bundled rule, taint
regressions, database upgrades, subprocess limits, and real CLI integration
checks for relocation, diff selection, persistence failures, lifecycle,
structured output, thresholds, and TUI EOF. CI runs the full workspace suite.
AI tests use local mock HTTP servers to verify identical messages, concurrent
dual-provider requests, explicit routing, partial failures, bearer authentication,
response validation, key redaction in diagnostics, and bounded context retrieval.
CLI checks verify side-effect-free context previews and finding-line excerpts.
These checks do not substitute for a live account/model integration test.

On Windows GNU toolchains, ensure the MinGW bin directory is on PATH so Cargo
can find gcc/dlltool and their libraries. The installed MinGW directory used
for local verification was C:\msys64\mingw64\bin. No machine-specific compiler
path is committed to the project.
