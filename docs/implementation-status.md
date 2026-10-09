# Implementation status

Updated 2026-10-07. This is a work ledger, not a release certification.
Continue against [the roadmap](competitive-roadmap.md); preserve existing changes.
Use the [competitive gap backlog](competitive-gap-backlog.md) for current priorities.

| Phase | Status | Implemented | Still required before exit |
|---|---|---|---|
| 0: scoreboard | Started | CLI rules/graph runner, 68 development cases (54 graph cases), confidence intervals, hashes, incomplete-scan reporting, CI execution | 300 independently adjudicated cases, family-disjoint holdout, larger realistic multi-file corpus, patched pairs, graph queries, pinned competitor runs, cost/memory/cold-warm measurements |
| 1: durable evidence | Started | Typed patch-assessment evidence/manifests, embedded rule identity, source disagreement handling, baseline compatibility, transactional normalized audit import revisions, bounded CLI/MCP/TUI history, normalized JSON artifact descriptors, resumable static jobs, bounded CLI/TUI job browsing and persistent budgets, semantics-aware cache invalidation | General reproduction artifact intake, revision detail browsing, TUI job controls, historical per-run legacy migration, hard-deadline/native audit workers, reverse dependency refresh, reconciliation/watcher, large-corpus latency proof |
| 2: semantics/backends | Started | Native lexical/import aliases, Flask/FastAPI string entry points, literal property/branch precision, async returns, source-bound trace provenance; Flask HTTP shortcuts and unsupported-route coverage and keyword rules and module-scoped framework namespace constructors in source order; bounded Express/Fastify ESM/CommonJS registrations, Router handler aliases and local Fastify plugin callbacks (semantics revision 11) | Reviewed broader framework/type/exception contracts, held-out graph/flow improvement, isolated Joern benefit evaluation |
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

2026-10-07 continuation (15:57 UTC): added bounded audit revision browsing to the
Investigation TUI (`h`, newest 20 imports). The existing repository-bound history
API supplies run/revision identity, import time, status and source snapshot. The
workspace explicitly labels historical source freshness unchecked and distinguishes
"latest imported" from a current-source or security verdict; `u` retains the latest
coverage/freshness check. Empty history and additional retained revisions are visible.
No provider calls or target execution are involved. README controls updated.

Validation: 21 CLI/TUI tests passed, including revision identity/freshness rendering,
empty CLI history and rejected limits outside 1–100; strict CLI all-target Clippy
passed. The preceding chatbot changes remain preserved. Global replacement remains
blocked by the open `C:\Users\kusha\.cargo\bin\sentinel.exe` process. No phase exit
is claimed; independent labels/reviews, containment review and workflow studies
remain external gates. Next Phase 1 priorities are artifact descriptors and structured
job browsing before native audit workers.

2026-10-07 next milestone: SQLite schema v7 and revision-scoped normalized JSON
artifact descriptors. New imports retain four descriptor records transactionally;
version-6 databases preserve their revisions and describe older records from retained
payloads. The CLI exposes bounded metadata via `audit-workflow artifacts <revision>`.
Hashes/sizes refer to normalized serialization, never fabricated original bytes;
import attestations are explicitly not observed execution. General external
reproduction artifact intake remains unimplemented. This does not close Phase 1.

Validation for this milestone: full workspace tests passed before the final CLI
integration addition; all 54 affected CLI/database/graph tests passed afterward
(one manual latency measurement remains ignored). A targeted corruption check also
passed, and strict workspace Clippy and formatting passed. The CLI integration
confirms repository-bound descriptor retrieval and rejects path-like revision IDs.
Global installation is still blocked by the open Sentinel process; the release
build contains the new command. Structured static-job browsing is the next bounded
Phase 1 milestone. Independent phase exit gates remain open.

2026-10-07 continuation (22:30 IST): added `sentinel job list [project] --limit N`
and the TUI Investigation job browser (`o`). Metadata summaries show newest
persisted states, recorded units, reserved attempts, time budgets, active files
and snapshot identity. Limits are 1–100 with explicit `has_more`; the TUI requests
20. Database reads share a transaction, validate each displayed stored job contract,
and omit large source manifests and per-finding payloads. Source freshness stays
unchecked, and Completed is explicitly not a clean security verdict. Browse does
not index, resume, execute targets or call AI. Resume/cancel remain explicit CLI
actions; interactive job controls remain outstanding.

Validation: 24 CLI/TUI tests passed, including bounded ordering, project isolation,
unchanged pending state after a source edit, malformed stored record rejection and
empty-state rendering. Existing graph tests passed (one manual latency test ignored),
strict workspace all-target Clippy passed, and release build/formatting checks passed.
Global executable replacement remains blocked by the open Sentinel process. No
phase exit is claimed. Next priorities are legacy audit migration and scalable
refresh/dependency invalidation; independent corpus/review gates remain external.

2026-10-07 continuation: implemented explicit latest compatibility-record recovery
with `audit-workflow export-legacy`. Export preserves metadata/evidence and memory,
requires bounded records and a new out-of-target directory, and never promotes a
record. Existing validate/import commands remain the schema, provenance and source
freshness gates. Historical per-run compatibility keys still require future work.
The new regression checks preservation, no automatic history promotion, existing
and in-target output rejection, and stale-source import rejection.

Validation: 11 audit workflow tests and 24 CLI/TUI tests passed; strict workspace Clippy and formatting passed. The release build is ready. Global installation remains blocked by the open Sentinel process. Phase exit gates remain open.

2026-10-07 Phase 2 continuation: added conventional `req.headers`, `req.cookies`,
`request.headers` and `request.cookies` source shapes. Semantics revision 3 forces
unchanged-source cache reparsing and invalidates incompatible baseline/job detector
identities. Added eight paired development cases, a graph regression, source-contract
documentation and CI benchmark execution. Before/after release reports retain binary
and corpus identities: four missed unsafe SQL flows become four detected flows;
all four separate-parameter counterparts stay clean. Existing 26 development cases
also passed with the new release (34 total, 17 TP/17 TN on their declared scope).

Full workspace tests passed before the final targeted graph regression; that new
regression, strict workspace Clippy, formatting and release build also passed.
These author-labelled cases establish regression behavior only, not independently
measured competitive accuracy or full framework support. Phase 1 stays Started:
reverse dependency refresh, watcher reconciliation, external artifact intake and
large-repository latency evidence remain outstanding. Phase 2 is actively underway;
import/type/alias resolution, route reachability and isolated Joern evaluation remain
future work. Global installation remains blocked by the open Sentinel process.

2026-10-07 Phase 2 autonomous native pass: implemented lexical parent-scope call
resolution, namespace/named aliases, conservative ambiguous-module/default export
handling, supported Flask/FastAPI string route inputs, literal object-field
precision and branch/reassignment invalidation. Unsupported FastAPI dependencies
produce incomplete coverage notes. Trace reports now carry backend/revision and
source snapshot identity; missing legacy provenance stays unknown. Semantics
revision 4 invalidates incompatible caches and detector identities.

Validation: full workspace tests, strict all-target Clippy, formatting and offline
release build passed. The additional unsupported-parameter regression was run
separately afterward. The new 14-case development corpus improved from 5 TP/2 FN
and 5 TN/2 FP in the installed baseline to 7 TP/7 TN in the new release. Existing
34 cases also passed: 48 total, 24 TP/24 TN, zero mapped FP/FN or failed cases.
These are author-labelled regressions, not blind holdout or competitor proof.

Joern is absent and the installed Docker engine is unavailable. No isolated
backend measurement or containment proof was manufactured; inclusion is deferred.
See [backend evaluation](phase2-backend-evaluation.md). Phase 2 remains Started
pending reviewed framework/type/exception coverage, independent held-out results
and isolated backend evaluation. Global installation is still blocked by the open
Sentinel executable; `target/release/sentinel.exe` contains this implementation.

2026-10-07 heartbeat (18:05 UTC): extended the existing Flask contract to HTTP
method shortcuts (`get`, `post`, `put`, `patch`, `delete`). Recognized dynamic
paths and unsupported converters now explicitly mark route analysis incomplete
instead of allowing an unsupported clean trace to imply complete coverage.
Semantics revision 5 reparses cached source and invalidates incompatible detector
identities. A regression exercises all five shortcuts and dynamic/custom routes;
the existing FastAPI incomplete-coverage regression follows the shared note.

Validation: all 25 graph integration tests passed (one manual latency check
ignored), strict workspace all-target Clippy passed. Documentation records the
exact support boundary. Independent Phase 2 labels and isolated Joern evaluation
remain open; no target code was executed and no phase exit is claimed.

The revision-5 offline release build passed; all five development corpora were
rerun successfully (48 cases, 24 TP/24 TN, zero mapped FP/FN or failures).

2026-10-09 heartbeat: Flask source extraction now recognizes keyword `rule=`
literal paths using the existing AST helper. Interpolated strings remain dynamic
and explicitly mark coverage incomplete. Semantics revision 6 invalidates old
parse/detector identities. Regression tests cover positional and keyword dynamic
paths plus keyword route/get sources. All 26 graph integration tests passed
(one manual latency check ignored); strict workspace all-target Clippy passed.
Supported-contract documentation updated. Independent labels and isolated Joern
benefit/containment evidence remain outstanding; no phase exit is claimed.

Revision-6 release build, formatting and six harness tests passed. All 48
development cases passed again (24 TP/24 TN, zero mapped FP/FN or failures).

2026-10-09 Phase 2 continuation: the existing framework source helper now handles
Python namespace imports (`api.FastAPI`, `api.APIRouter`, `web.Flask`) alongside
direct aliases. Direct assignments to a constructor or namespace invalidate its
subsequent constructor evidence. Semantics revision 7 refreshes incompatible
parse/detector identities. Tests cover namespace/direct constructor recognition
and rebinding, without executing inspected source. Framework identity remains
lexical, not runtime dependency proof; conditional rebinding and factories remain
outside the contract.

The test run exposed timestamp collisions in parallel graph fixture directories;
a process-local atomic counter now distinguishes them. All 27 graph integration
tests passed after that fix (one manual latency measurement ignored). Independent
Phase 2 graph labels and isolated Joern evaluation remain outstanding.

Revision-7 strict all-target Clippy, formatting and offline release build passed.
All 48 development cases passed again (24 TP/24 TN, zero mapped FP/FN or failures).

2026-10-09 heartbeat (15:16 UTC): restricted framework constructor discovery to
module-level imports before the decorated function. Imports within unrelated
functions no longer leak framework identity into module routes; later imports
also supply no route evidence. Reuses the existing import parser and source
helper. Semantics revision 8 invalidates incompatible parse/detector identities.
A regression covers nested named/namespace imports, later imports, and a valid
module import. All 28 graph integration tests passed (one manual latency check
ignored), and strict workspace all-target Clippy passed. Supported contracts and
roadmap status updated. No independent gate or phase completion is claimed.

Revision-8 formatting and offline release build passed; all 48 development cases
passed again (24 TP/24 TN, zero mapped FP/FN or failures).

2026-10-09 LM Studio integration: local endpoints ending in /v1 use the shared
OpenAI-compatible chat transport, without requiring cloud credentials. Existing
Ollama transport is retained for other endpoints. Seven AI tests and strict
workspace Clippy passed. Bionic model discovery returned qwen/qwen3.5-9b; CLI/TUI
defaults now point to localhost:1234/v1 and that model, with existing overrides.
The first live local request timed out at 60 seconds; a longer retry is pending.
Global replacement remains blocked by the open global Sentinel process.

Bionic live verification: model discovery succeeds and generation requests reach
the server. Qwen returned finish_reason=length with empty final content and
reasoning-only output, including when asked to disable thinking. Sentinel rejects
this as incomplete. Model-level thinking/template configuration needs adjustment;
successful inference is not yet verified. AI timeout increased to 180 seconds
with a 210-second TUI worker limit. Updated global executable installed after
the user closed the previous TUI.

2026-10-09 NIM configuration: exact user-provided model identifier z-ai/glm-5.3
is the CLI/TUI cloud default. GLM requests specify low reasoning effort and
8192 output tokens, preserving shared messages and existing provider isolation.
Eight AI tests and strict workspace Clippy passed. No pasted credential was
stored or used for a live request; replacement key required after chat exposure.

2026-10-09 live NVIDIA test: user authorized temporary use of the supplied key.
Installed Sentinel cloud-only generic chat successfully returned a complete
response from z-ai/glm-5.3 with no provider failures. Only a connection-test
prompt was sent, no repository context. Credential existed only in the child
PowerShell environment and was removed in finally; not persisted in files.
This verifies transport, not security-analysis accuracy or latency guarantees.

2026-10-09 configuration: added git-ignored .env and tracked .env_example with
blank key and current local/NIM settings. CLI loads only the current-directory
file, bounded to 64 KiB, admitting five AI keys without overriding process
variables. dotenvy handles syntax; malformed input is rejected before mutation
with fixed secret-safe errors. Two configuration tests, strict workspace Clippy
and release build passed; global executable updated. No key persisted by agent.

2026-10-09 configuration refresh fix: TUI AI actions reread the launch-directory
.env before spawning children; empty template values are not imported into the
process environment. Existing non-empty process overrides still win. Empty child
stdout now surfaces the command error without a misleading JSON EOF suffix.
Nine CLI unit/TUI tests, strict workspace Clippy and release build passed.
Global executable replaced after user exited; file hashes match. The source-order
framework milestone considered during this heartbeat remains pending.

2026-10-09 AI usability fix: generic chat receives JSON-escaped working/selected
directory metadata, explicitly separated from source evidence and instructions.
Source context remains opt-in. Environment loading falls back to user-level
~/.sentinel/.env after launch-directory settings; process values retain priority.
Existing project configuration was copied to the user file only when absent,
without displaying credentials. All 26 CLI/TUI tests, strict Clippy and release
build passed; an added chat regression checks directory metadata and exclusion
of source contents. Global install awaits closure of the currently open TUI.

2026-10-09 autonomous AI verification: installed latest directory/global-config
build once the global executable was unlocked. Backed up Qwen's model.yaml to
model.yaml.sentinel-backup, set enableThinking's default false, and reloaded
Qwen with 16K context and one prediction slot. Native Bionic reasoning=off probe
first isolated the thinking issue; no alternate backend was added to Sentinel.
Existing OpenAI-compatible transport then returned a complete local answer in
about five seconds. Local synthetic history recall returned Ada, and directory
query returned C:\projects\Sentinal. NIM succeeded from outside the repository
using the user-level config. Both mode returned matching complete synthetic
answers from local-openai/qwen and nvidia-nim/GLM, with no failures. No repository
source was sent in these live probes; absolute directory metadata is included
in generic chat by the user's request. No target code was executed.

Added regression for user configuration supplying credentials outside a project,
with a fake key and loopback-only failed request; no secret output or database
side effect. Accepted timeout/refusal transport outcomes rather than assuming
one OS error. Fixed another timestamp collision in AI test fixture names with a
process-local counter. README now reflects both local protocols, current model
and timeout defaults, user configuration, and Qwen thinking setup. These are
transport/usability checks, not competitive security accuracy or phase exits.

Final autonomous verification: full locked/offline workspace tests and strict
all-target Clippy passed (one manual latency test remains ignored). Release/global
executable hashes match. Both provider answers, local history, directory awareness
and global NIM configuration are verified through the installed CLI. This closes
the requested AI connection milestone, not any roadmap release/phase gate.

2026-10-09 heartbeat (17:21 UTC): framework imports/assignments now share one
source-order pass. A later import cannot justify an earlier constructor call;
reimport restores constructor identity after reassignment; unrelated imports
invalidate same-name constructors and route receivers. Added five regression
shapes covering these cases. Semantics revision 9 invalidates incompatible parse
and detector identities. All 29 graph integration tests and strict workspace
all-target Clippy passed (one manual latency measurement ignored). Documentation
states the bounded lexical contract. Independent held-out labels and isolated
Joern evaluation remain open; no phase exit or competitive win is claimed.

Revision-9 offline release build passed; all 48 development cases passed again
(24 TP/24 TN, zero mapped FP/FN or failures).

2026-10-09 Express/Fastify initial registration contract: module-level ESM
factory/Router aliases, direct constructed receivers and literal-path HTTP method
calls identify inline and direct local named handlers. Independently taints the
first request parameter's query/body/params/headers/cookies fields regardless of
its name, preserving clean parameterized SQL. Existing helper summaries handle
resolved cross-file flows. Imports/assignments invalidate receiver/handler
bindings in order; function declarations are hoisted. Recognized middleware,
options, plugin/chained or opaque handler forms mark analysis incomplete instead
of implying authorization or complete route coverage. CommonJS, indirect aliases,
nested plugins and middleware lifecycle remain further work. Semantics revision
10 refreshes cached parses and detector identities.

Validation: all 31 graph integration tests passed (one manual latency test
ignored); strict all-target workspace Clippy and offline release build passed.
New eight-case before/after reports retain binary/corpus hashes: four baseline
misses become four detected flows, with all four safe cases clean. Existing 48
cases also pass (56 total; 28 TP/28 TN, zero mapped FP/FN or failed cases).
These are author-labelled development regressions, not held-out accuracy proof.
CI executes the new corpus. No target code was executed; no phase exit is claimed.

Final formatting/diff checks passed. The release artifact is ready; global install
is attempted only while the user executable is not open.

2026-10-09 CommonJS and bounded local plugin contracts: literal unshadowed
require('express'/'fastify') factories, immediate require factory calls, Express
Router() and simple local handler aliases now identify renamed request inputs.
Inline/local named Fastify callbacks are traversed up to eight nesting levels
and 256 expansions per inspection; nested plugin receivers and require shadowing
are carried into each scope. Imported/opaque plugins, options, Fastify addHook,
Express mounts and exhausted recursion remain explicitly incomplete; middleware
ordering and guard dominance are not inferred. Root inspection records opaque
registration coverage even when the file contains no function body. Semantics
revision 11 invalidates earlier cached parses and detector identities.

Validation: workspace tests passed; the final graph integration suite passed
35 tests with one manual latency test ignored. Strict all-target workspace Clippy,
offline release build and formatting passed. The twelve-case development corpus
improves from 0 TP/5 FN/5 TN plus two incomplete cases to 6 TP/6 TN with zero
mapped FP/FN or incomplete cases. All previous 56 cases pass again: 68 total,
34 TP/34 TN, zero mapped errors. Before/after reports retain binary/corpus hashes;
CI includes the new corpus. These are author-labelled development regressions,
not independent competitor or held-out accuracy evidence. No phase exit claimed.

Global sentinel.exe replaced while no Sentinel process was running; installed
and release SHA-256 hashes match. Existing user configuration is preserved.
