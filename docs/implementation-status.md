# Implementation status

Updated 2026-10-07. This is a work ledger, not a release certification.
Continue against [the roadmap](competitive-roadmap.md); preserve existing changes.
Use the [competitive gap backlog](competitive-gap-backlog.md) for current priorities.

| Phase | Status | Implemented | Still required before exit |
|---|---|---|---|
| 0: scoreboard | Started | CLI rules/graph runner, 26 development cases (12 graph cases), confidence intervals, hashes, incomplete-scan reporting, CI execution | 300 independently adjudicated cases, family-disjoint holdout, larger realistic multi-file corpus, patched pairs, graph queries, pinned competitor runs, cost/memory/cold-warm measurements |
| 1: durable evidence | Started | Typed patch-assessment evidence/manifests, embedded rule identity, source disagreement handling, baseline compatibility, transactional normalized audit import revisions, bounded CLI/MCP history, resumable static jobs and persistent budgets, semantics-aware cache invalidation | Artifact descriptors, history browsing UI, legacy import migration workflow, hard-deadline/native audit workers, reverse dependency refresh, reconciliation/watcher, large-corpus latency proof |
| 2: semantics/backends | Started | Existing approximate graph and category-specific sanitizers; measured request.body/query_params source fixes | Framework contracts/fixtures, measured analysis improvements, evaluate optional Joern under isolation |
| 3: breadth | Planned | Existing application rules | Secrets, dependency inventory/advisories, IaC and AI/agent suites with measured precision |
| 4: native audit | Planned | Existing provider transport and external Cloudflare audit workflow | Native bounded scheduling, structured responses, isolated discovery/review sessions, cancellation and resumption, provider accounting |
| 5: verification | Planned | Deterministic patch comparison | Reviewed OS containment, observed reproduction, isolated patch/test loop, hostile worker/artifact tests |
| 6: evidence UX | Planned | Existing CLI/TUI/MCP, latest audit status | Structured audit workspace, navigable traces, editor/LSP, policy/export integration, usability evidence |
| 7: release proof | Planned | Existing Windows CI/build checks | Independent security audits, competitor evaluation, multi-platform packaging, signed releases, provenance and workflow studies |

Current Phase 1 checks cover snapshot identity changes, candidates remaining
unconfirmed, stale graph/rule source disagreement, legacy baselines without
manufactured provenance, preserved legacy audit memory, idempotent import,
revision retention and transactional rollback under an induced SQLite failure.

Next priorities: expand realistic reviewed development families and graph-query
benchmarks; add structured history/jobs UI and graph-query benchmarks; extend the static job foundation with native audit worker contracts
before native audit orchestration. The hourly continuation task is attached to this
thread. It must update this ledger after each verified milestone.

Independent review, blind holdout adjudication, human workflow studies and external
containment review cannot be substituted with self-generated labels or passing
unit tests. Report the missing evidence while continuing independent implementation.

Latest milestone adds static jobs with restart, budget, cancellation and stale-source tests; MCP revision history; eight multi-file flow cases and four request-shape cases. Both missed request-shape flows are now detected with both safe counterparts clean. Full framework routing, aliasing and middleware semantics remain unsupported. Before/after development reports retain their exact corpus/binary hashes.

Verification: workspace tests and strict Clippy passed after semantics revision 2; four Python harness checks passed. The updated global release CLI was exercised through job create, resume across separate processes, completion, cancellation and graph scanning. The eight multi-file cases were also rerun against the installed release binary successfully. Phase exit gates remain open.

2026-10-07 continuation: benchmark fixtures now reject portable-path aliases, scanner-state overlap, file/directory conflicts and source-budget overflow. Scoring rejects exit-2/Complete contradictions, malformed evidence and incomplete scanner/graph records. Six harness tests and all 26 development cases passed against the installed release. Competitive gap backlog now defines measurable deliverables against both comparators; secrets with redaction is the next breadth priority after measurement/job contracts.
