# Implementation status

Updated 2026-11-04. This is a work ledger, not a release certification.
Continue against [the roadmap](competitive-roadmap.md); preserve existing changes.
Use the [competitive gap backlog](competitive-gap-backlog.md) for current priorities.

| Phase | Status | Implemented | Still required before exit |
|---|---|---|---|
| 0: scoreboard | Started | CLI rules/graph runner, 68 development detection cases (54 graph cases), twenty-six author-labelled graph/trace queries across five development families with separate exact-result scoring, confidence intervals, hashes, incomplete-scan reporting, CI configuration | 300 independently adjudicated cases, family-disjoint holdout, larger realistic multi-file corpus, patched pairs, deeper graph query scoring, pinned competitor runs, cost/memory/cold-warm measurements |
| 1: durable evidence | Started | Typed patch-assessment evidence/manifests, embedded rule identity, source disagreement handling, baseline compatibility, transactional normalized audit import revisions, bounded CLI/MCP/TUI history and historical revision details, normalized JSON artifact descriptors, resumable static jobs, bounded CLI/TUI job browsing, explicit TUI status/resume/concurrent cancellation and persistent budgets, semantics-aware cache invalidation, transitive Git diff dependency scope, finding-row read/write payload and numeric validation, scoped context history retrieval, scan metadata/snapshot admission budgets, batched lifecycle resolution and bounded index statistics | General reproduction artifact intake, historical per-run legacy migration, hard-deadline/native audit workers, reverse dependency refresh, reconciliation/watcher, large-corpus latency proof |
| 2: semantics/backends | Started | Native lexical/import aliases, Flask/FastAPI string entry points, literal property/branch precision, async returns, source-bound trace provenance; Flask HTTP shortcuts and unsupported-route coverage and keyword rules and module-scoped framework namespace constructors in source order; bounded Express/Fastify ESM/CommonJS registrations, Router handler aliases and local Fastify plugin callbacks; module-scoped Python named/namespace imports and conservative import/receiver boundaries and Python class lexical-scope exclusion and scoped import collision checks and lexical import statement visibility and distinct-target resolution (semantics revision 18) | Reviewed broader framework/type/exception contracts, held-out graph/flow improvement, isolated Joern benefit evaluation |
| 3: breadth | Started | Existing application rules, five provider-token candidate checks with redacted evidence, and bounded offline npm package-lock v2/v3 inventory | Broader secret formats/history scanning, advisory inventory/refresh and version evaluation, other ecosystems/SBOM, IaC and AI/agent suites with measured precision |
| 4: native audit | Planned | Existing provider transport and external Cloudflare audit workflow | Native bounded scheduling, structured responses, isolated discovery/review sessions, cancellation and resumption, provider accounting |
| 5: verification | Planned | Deterministic patch comparison | Reviewed OS containment, observed reproduction, isolated patch/test loop, hostile worker/artifact tests |
| 6: evidence UX | Planned | Existing CLI/TUI/MCP, latest audit status | Structured audit workspace, navigable traces, editor/LSP, policy/export integration, usability evidence |
| 7: release proof | Planned | Existing Windows CI/build checks | Independent security audits, competitor evaluation, multi-platform packaging, signed releases, provenance and workflow studies |

Current Phase 1 checks cover snapshot identity changes, candidates remaining
unconfirmed, stale graph/rule source disagreement, legacy baselines without
manufactured provenance, preserved legacy audit memory, idempotent import,
revision retention and transactional rollback under an induced SQLite failure.

Next priorities: expand realistic reviewed development families and graph-query
benchmarks; harden worker lifetimes, hard deadlines and scalable refresh;
extend the static job foundation with native audit worker contracts
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

2026-10-09 CI verification and development regression gate: GitHub run
37968684941 for df901e00a5ad6792ee13a9f5b852e08eb76dda28 completed successfully.
The screenshot's failure could not be matched to that run; no failure root cause
is inferred from the email image. The benchmark harness previously returned zero
for completed measurements with mapped FP/FN, so CI could pass a detection
regression. Added explicit --fail-on-regression and enabled it on all seven CI
corpora; default historical measurement semantics remain unchanged. Reports are
retained before nonzero exits; incomplete/failed cases take exit-2 precedence.
Seven Python tests pass, including CLI exit/report checks for misses, false
positives, incomplete execution and clean results. All 68 development cases pass
with the gate enabled. These changes are local and have not been pushed; hosted
CI verification of the new gate remains pending. Phase exit gates remain open.

2026-10-10 stored static job consistency: shared status/list/resume/cancel loading
now rejects duplicate/out-of-manifest results, results exceeding reserved attempts,
invalid active-file reservations, inconsistent finding counts (including overflow),
and completed jobs without complete results for every admitted file. Cancelled
records may retain a valid outstanding active file; cooperative elapsed-time
overshoot remains recorded. These are contract consistency checks, not database
authentication or evidence of present source freshness. No schema migration or
new dependency is needed. A regression mutates stored records and verifies every
read/action path rejects contradictions while valid cancelled reservations remain
terminal. All 36 graph integration tests pass (one manual latency test ignored);
strict all-target workspace Clippy and formatting/diff checks pass. No target
code was executed. Changes remain local; independent exit gates remain open.

The repository-scoped CLI job-list integration test also passes.

Offline release build passed. The release artifact is ready; this heartbeat did
not replace the global executable, commit, push or publish changes.

2026-10-10 static job cancellation boundary: added a deterministic SQLite
second-writer simulation immediately after active-unit reservation. The late
worker compare-and-swap is rejected, cancelled state and its consumed attempt
remain intact, no unit result enters the cancelled job, and a fresh engine cannot
admit more work. Also tightened active-file validation so cancelled records cannot
claim an active file without an outstanding reservation. This is a bounded
transaction/state regression, not exhaustive concurrency or OS containment proof.
All 38 graph integration tests pass (one manual latency test ignored); strict
all-target workspace Clippy, formatting and diff checks pass. Existing resumable,
stale-source and interrupted-budget regressions remain green. Changes remain
local; this slice has not rebuilt or replaced the release/global executable.
No target code execution or phase exit claim. Hard worker deadlines, broader
concurrent schedules and independent release evidence remain outstanding.

2026-10-10 historical audit content retrieval: added the repository-bound
Engine::audit_revision and `audit-workflow revision ID --project PATH` command.
It returns the retained normalized run with explicit unchecked-source and
unobserved-execution flags. Reads do not reconcile source, open original artifact
paths, reimport or promote a historical revision to latest. A shared bounded
loader enforces retained content identity; artifact descriptor reads now reject
payload/identity disagreement too. No schema migration or new dependency.
Tests cover two distinct retained revisions, changed source, removed original
run files, cross-repository lookup rejection, malformed identities, corrupted and
oversized retained content, and unchanged latest pointers. All 12 audit-workflow
integration tests and the new CLI integration test pass; strict all-target
workspace Clippy, formatting and diff checks pass. README and workflow contracts
are updated. Changes remain local; this slice has not rebuilt/replaced the global
release. TUI detail navigation, generalized artifacts and independent phase exit
evidence remain open.

2026-10-10 MCP historical evidence parity: added
`sentinel_get_audit_revision` and `sentinel_get_audit_artifacts` using the existing
repository-bound worker gate and shared historical content loader. Inputs accept
only a revision identity; unknown repository overrides are rejected. Reads do not
refresh source, open original artifacts, contact providers, import or promote
history. The MCP stdio integration test now checks both tools, removed original
run files, freshness/execution flags, invalid/unknown identities, rejected scope
widening and unchanged latest pointers; existing index/trace/navigation/scope
checks remain green. The server exposes 15 tools. Strict all-target workspace
Clippy, formatting and diff checks pass. README/workflow contracts are updated.
Changes remain local; release/global executable unchanged. These are deterministic
historical evidence queries, not independent provenance authentication or phase
exit evidence.

2026-10-10 TUI historical revision browsing: history now shows one selected entry
within the latest 20 imports. Arrows/j/k select entries, Home selects the newest,
and Enter invokes the repository-bound historical revision CLI worker. Detail
output remains explicitly historical, freshness unchecked and execution unobserved;
h reloads history and u checks latest freshness. Other investigation results leave
history selection mode, and project changes clear cached history and displayed
investigation evidence. The footer reflects history controls; Page Up/Down scroll
long content. No new dependency or synchronous database/model work in the UI.
All 10 CLI/TUI unit tests pass, covering selection bounds, empty-history rejection,
detail labels, project reset, keyboard focus and drawing/resizing. Strict all-target
workspace Clippy passes. README and workflow documentation updated. Changes remain
local; release/global binary unchanged. Broader evidence navigation, TUI job
management, worker deadlines, human usability evidence and phase exit gates remain
open.

2026-10-10 explicit TUI static job controls: o loads up to 20 job summaries;
arrows/j/k select, Enter reads stored details, r invokes a one-unit resume with
existing budgets, and uppercase C cancels the selected persisted job. Detail
scrolling cannot switch the selected job; o reloads metadata. Resume exit 2 with
valid pending JSON is rendered as recorded workflow progress, not a protocol
failure or clean verdict. Source/detector checks and reservation accounting remain
in the existing CLI/engine. Project changes clear cached job selection. One UI
worker is retained; Esc stops it before a separate cancellation request, and
interrupted recovery remains explicit CLI-only. No auto-resume, budget growth,
provider calls or target execution.
Validation: all 11 CLI/TUI unit tests pass; a CLI integration exercises a pending
one-unit batch and cancellation across processes, preserving attempts/results and
budgets. Strict all-target workspace Clippy, formatting and diff checks pass.
README, keyboard guide and static job contracts updated. Changes remain local;
release/global executable unchanged. Concurrent cancellation, hard deadlines,
large-corpus performance and independent phase exit evidence remain open.

2026-10-10 TUI job action consistency and integrated verification: found that
arrows/Home could change the selected job while a resume/status worker was active.
A returned record could then describe one job while the next action targeted
another. Selection now remains frozen until the worker finishes, and typed job
responses must match the selected identity before replacing displayed evidence.
A regression uses an owned harmless OS child (no target code) to exercise busy
keyboard selection, then rejects a mismatched response without changing evidence
or selection. Static job contracts document the binding.
Full offline workspace tests pass across CLI/TUI, graph, audit persistence, MCP,
AI transport, scanner, database and taint components. Strict all-target workspace
Clippy and all seven Python harness tests pass. All 68 development cases pass with
--fail-on-regression against the current debug binary (34 TP/34 TN, zero mapped
FP/FN or failures). Formatting and diff checks pass. This validates the accumulated
local milestones together; it is not release certification or a competitor
measurement. No phase exit claimed, target code executed, changes pushed or global
executable replaced. Concurrent cancellation and hard worker deadlines remain
outstanding.

2026-10-10 pending TUI evidence identity: extended the busy-worker selection
protection to audit history. Up/Down/j/k/Home cannot change the selected revision
while a worker runs, and historical detail responses must match the selected
revision before replacing displayed evidence. Mismatched responses preserve the
history, selection and prior text. Also found that codebase/finding explanation
shortcuts could change the question while an AI answer was pending, attributing
that answer to a different user message. Those context shortcuts now wait for the
worker to finish; typing the next draft remains available.
Regression coverage exercises busy history navigation, mismatched revision
responses, pending-question stability and final conversation attribution using
only harmless owned OS children. All 11 CLI/TUI unit tests and strict all-target
workspace Clippy pass; formatting and diff checks pass. Workflow contracts are
updated. Changes remain local; no release installation, provider calls, target
execution or phase exit claim. Concurrent cancellation and hard worker deadlines
remain outstanding.

2026-10-10 concurrent TUI static-job cancellation: the existing primary worker
now admits one additional cancellation worker only while a static resume is
active. Uppercase C in Investigation uses the selected, frozen job identity
without first killing the resume worker. All settings, history/job selection and
new operations remain locked while either worker is pending. A validated matching
cancelled response stops the owned resume worker after persistence acknowledgement;
malformed/mismatched responses leave it running. If completion wins, its actual
terminal state is displayed. Esc/quit drop both workers; interrupted reservations
still require explicit CLI recovery and no budget is refunded or increased.
The footer and README/static-job contracts explain the distinction between
persisted cancellation and stopping UI workers. Three regression tests cover
second-worker admission, duplicate/new-operation rejection, primary completion
with cancellation still pending, settings lock, stopping both, response identity,
malformed responses, cancellation acknowledgement, completion races and conserved
budget fields. All 14 CLI/TUI unit tests pass. The CLI pending-batch/cancellation
integration and graph late-result CAS regression pass; strict all-target workspace
Clippy, formatting and diff checks pass. This bounded cancellation milestone is
local, with no deployment, cloud requests or target execution. OS containment,
hard deadlines, concurrent schedule stress tests, scalable refresh and external
phase exit evidence remain open.

2026-10-10 TUI worker output failure handling: polling now distinguishes a
pending pipe reader from a disconnected reader and immediately reports lost
reader results. Read errors carry an explicit worker-output diagnostic. Pipe
collection happens once before output-limit and completion checks, removing the
redundant post-exit collection branch. Existing output limits, original exit
status, timeout and missing-EOF errors remain enforced.
Four regression tests cover empty/exact-limit/overflow reader output, injected
read failure, stdout/stderr disconnection, each stream's output ceiling, elapsed
deadlines and real nonzero exit with both pipes retained. All 18 CLI/TUI unit
tests and strict all-target workspace Clippy pass; formatting and diff checks
pass. Tests execute only owned harmless OS helpers, with no inspected target
execution or provider calls. Static-job contracts now state the worker output
limits and polling limitations. Changes remain local. Descendant lifetime
handling after parent exit, hard deadlines, scalable refresh and independent
containment/phase exit evidence remain outstanding.

2026-10-10 transitive diff dependency scope: replaced the order-sensitive single
call-neighbor pass with a dependency closure over both working and immutable Git
base graphs. Resolved calls retain the existing bidirectional neighbor policy;
resolved imports propagate changes to importers without pulling in every uncalled
dependency. Each admitted file is visited once, including cycles. Deleted source
still propagates through baseline imports. Unresolved edges remain excluded and
existing incomplete-coverage handling remains authoritative.
A Git integration tests a three-hop importer chain, cycles, deletion, removed
imports, unrelated/opaque modules and importer-only changes. A focused graph test
checks alternating call edges across both snapshots, reversed snapshot order,
cycles, reverse call traversal and opaque-edge exclusion. All 39 graph integration
tests pass (one manual latency test remains ignored), both graph unit tests pass,
strict all-target workspace Clippy and the MCP stdio index/trace/context/diff
integration pass. Formatting and diff checks pass. README and agent contracts
updated. This broadens conservative assessment scope; it does not establish guard
correctness, exploitability, scalable incremental refresh or independent accuracy.
Full reconciliation, persistent invalidation/watcher work and external phase exit
evidence remain outstanding. Changes remain local; no target execution or release
installation.

2026-10-10 benchmark split and availability reporting: reports now retain
separate development/holdout summaries when all cases are selected, preventing a
combined score from silently standing in for holdout results. Failed cases are
broken down by positive/negative truth label. Completion rate and observed
positive detection rate expose availability alongside completed-case precision
and recall; failed positives remain failures, not reclassified false negatives.
The report additions apply to each existing summary group without changing exit
gates, corpus labels, report overwrite protection or historical reports.
All nine harness tests pass, including deliberately divergent mocked development
and holdout results, positive/negative scan failures, empty groups and undefined
completed-case rates. The real 14-case static development seed passes against the
current debug binary (7 TP/7 TN, no failures) with split/availability fields checked.
Benchmark instructions updated; diff checks pass. No genuine holdout was created,
independent labels obtained or competitor evaluated. This is a Phase 0 reporting
milestone; phase exit gates remain open and all changes remain local.

2026-10-10 benchmark binary consistency: the harness previously hashed the
scanner only after cases ran, allowing a replaced binary to be reported as if it
had produced earlier results. It now records the initial hash and checks again
after scanning. Replacement or disappearance saves an explicitly invalid report
and exits 2, even when all mocked cases report complete detection. Failed cases
also populate measurement errors; accuracy errors remain separate from execution
validity and retain the existing optional regression gate.
All ten harness tests pass, covering stable/replaced/removed binaries, preserved
initial identity, report retention and error precedence. The actual 14-case
static development seed passes against the current debug binary with identical
before/after hashes (7 TP/7 TN, zero failures). Benchmark instructions and diff
checks are updated. Endpoint hashes do not authenticate the process or rule out
replacement/restoration between checks, library changes or environment drift.
Changes remain local; no target execution, provider calls, independent holdout
labels, competitor measurement or phase exit claim.

2026-10-11 bounded stored evidence reads and latest-status consistency: job,
retained audit revision, artifact descriptor and legacy status queries now select
at most 2 MiB plus one overflow byte before Rust deserialization. SQL slices
bytes, not UTF-8 characters; oversized records fail before parsing/action. Artifact
reads fetch one extra row to reject undeclared descriptors beyond the fixed four
instead of silently truncating them. Latest audit status resolves its pointer via
the shared revision identity validator and fails on corrupted retained content;
legacy content is loaded only when the latest pointer is absent. These are payload
transfer/deserialization limits, not SQLite-wide resource containment.
Regression coverage includes ASCII/multibyte oversized data across all job actions,
historical/latest audit reads, oversized/extra descriptors, corrupt latest revision
identity, and modern-status independence from oversized legacy memory. Fixed an
observed parallel audit-fixture directory collision with the existing atomic
counter pattern used by graph fixtures; timestamps alone can repeat on Windows.
Full locked offline workspace tests pass: 18 CLI/TUI units, 20 CLI integrations,
13 audit workflow integrations, 40 graph integrations (one manual latency test
ignored), graph units, AI transport, scanner, database, AST, taint and doc tests.
Strict all-target workspace Clippy, formatting and diff checks pass. Workflow/job
contracts updated. All changes remain local; global executable unchanged. No
provider calls, target execution, deployment or phase exit claim. General artifact
intake, hard deadlines, scalable refresh and independent phase evidence remain open.

2026-10-11 legacy audit recovery boundary: status fallback and explicit legacy
export now share one bounded SQLite reader. This closes the remaining export
path that fetched an entire legacy payload before applying its size limit and
also applies export's existing repository/target binding to legacy status.
Oversized, malformed or cross-project legacy evidence fails before directory
creation or source freshness assessment. Valid export still preserves memory,
creates no audit revision and requires explicit validate/import; legacy data is
not silently promoted or authenticated.
All 14 audit workflow integration tests and strict all-target workspace Clippy
pass. New coverage checks ASCII/multibyte oversized records, cross-project
rejection in both paths, no output directory, unchanged legacy memory and no
revision creation. Existing migration/recovery/revalidation tests remain green.
Formatting and diff checks pass; workflow contracts updated. Changes remain
local and the global executable is unchanged. General artifact intake, historical
per-run migration, scalable refresh, hard deadlines and external phase exit
requirements remain outstanding. No target execution, provider calls or deployment.

2026-10-11 graph navigation completeness: symbol lookup and caller/callee
responses now carry the refreshed graph's index_complete flag and coverage notes.
Previously, these query paths discarded index warnings, so a partial graph could
return apparently ordinary empty or bounded results. Output omissions remain
separate: a complete index can still yield a truncated response, and unresolved
calls remain approximate. Older typed query JSON defaults missing completeness
metadata to false instead of manufacturing a complete history.
A graph regression checks valid symbols alongside an unrelated malformed file,
both caller/callee directions, bounded target/symbol omissions, correction of the
malformed source and conservative old-response deserialization. The MCP stdio
integration confirms all three navigation tools transmit both new fields; scope,
trace, diff and verification checks remain green. Targeted graph/MCP tests, strict
all-target workspace Clippy, formatting and diff checks pass. README and agent
contracts updated. Changes remain local, with no target execution, providers or
release installation. Source identity propagation, scalable refresh, hard deadlines
and independent phase exit evidence still require further work.

2026-10-11 graph navigation provenance: symbol and caller/callee results now
include the existing native backend identity contract and sorted indexed-source
manifest hash used by taint traces. Consumers can distinguish retained answers
from different source views or semantics revisions instead of relying on matching
symbol names. Missing provenance in old typed responses remains unknown/null.
The existing graph regression now verifies backend semantics, stable identity
across target/output-limit changes, equality with trace identity, identity changes
when another indexed file changes, and conservative old-response decoding. The
MCP integration checks provenance on all three navigation tools against the
corresponding trace. Targeted graph/MCP tests, strict all-target workspace Clippy,
formatting and diff checks pass. README and agent contracts updated.
Identity covers the admitted indexed manifest; it does not prove complete scope,
atomic filesystem observation, independently authenticated evidence or soundness.
Concurrent database-read consistency, scalable refresh, hard deadlines and
external phase evidence remain open. Changes remain local; no target execution,
provider calls, deployment or global executable replacement.

2026-10-11 coherent stored graph reads: snapshot() now pins one SQLite read
transaction across indexed files, relationship edges and index statistics.
Previously, independent table reads could cross another connection's refresh
commit and combine source identities with mismatched edges or coverage metadata.
If a caller already owns a transaction, snapshot joins it without committing or
rolling it back. Owned read transactions are released on success and parse errors.
No new dependency or separate cache was added.
A regression checks caller transaction ownership and failure cleanup. A bounded
two-connection test alternates static source refreshes while reading 200 snapshots
and verifies definition targets/file counts/symbol counts belong to one committed
view. This is limited concurrency regression evidence, not exhaustive scheduling
or filesystem snapshot proof. All 43 graph integrations pass (one manual latency
measurement ignored), 14 audit integrations and both graph units pass. The MCP
stdio integration and strict all-target workspace Clippy pass. Formatting/diff
checks and agent contracts updated. Changes remain local; global binary unchanged.
Live filesystem races, scalable reconciliation, worker deadlines, general artifact
intake and independent phase evidence remain open. No target code execution,
provider calls, deployment or phase exit claim.


2026-10-11 serialized graph refresh: index() now reserves the SQLite writer
before loading reusable IR, using one immediate transaction through reconciliation
and commit. Previously, two connections could calculate updates from the same
old graph, then sequentially commit incompatible file deltas and freshly rebuilt
edges/statistics. Snapshot read consistency alone cannot prevent that writer race.
The shared indexing entry point now serializes those database views without a
new dependency, lock table or schema change; all errors release the reservation.
A deterministic regression holds a competing writer while stored IR is malformed
and verifies writer acquisition fails with SQLite Busy before JSON parsing. It
then checks parse failure cleanup, injects an insert failure after deletion, proves
files/edges/statistics roll back together, and verifies a successful retry.
All workspace tests pass, including 44 graph integrations (one manual latency
measurement ignored), 14 audit integrations, 20 CLI integrations, 18 CLI/TUI
units and eight mock-provider tests. Strict all-target workspace Clippy, formatting
and diff checks pass. Agent integration contracts updated; changes remain local.
The writer reservation spans static parsing, so competing database writes can
wait up to the existing five-second busy timeout or fail. This correctness tradeoff
needs large-corpus measurement and a scalable reconciliation design before a
responsiveness claim. Source files are not frozen, hard worker deadlines and
independent phase gates remain open. No target execution, live provider calls,
deployment, publication or global executable replacement occurred.


2026-10-11 source-bound static job admission: job_manifest() now validates
completeness from the same coherent stored snapshot that supplies its file hashes.
Previously, it checked the statistics returned by index() and then loaded a
separate snapshot; another committed refresh could replace the graph with a
partial scope between those operations. The shared creation/resume path now
rejects that partial manifest instead of admitting work from mismatched coverage.
A deterministic SQLite trigger regression replaces persisted completeness while
refresh returns complete statistics. Creation fails without inserting another job;
resume marks the existing job stale without reserving an attempt, setting an active
file or recording a result. Removing the injected replacement permits a fresh job
to complete under its original budgets. This emulates the database-view boundary;
it does not establish atomic live filesystem observation or authenticate storage.
All three static-job graph regressions, both CLI job integrations and strict
all-target workspace Clippy pass. Formatting and diff checks pass; static job
contracts updated. Changes remain local. Scalable refresh, hard deadlines, general
artifact intake and independent phase exit evidence remain open. No target execution,
live provider calls, deployment or publication occurred.


2026-10-11 complete selected-scope audit planning: run initialization now seeds
one planned coverage unit per selected text manifest entry instead of using only
successfully indexed native code. Explicit hidden configuration, lockfiles,
unsupported text types and malformed source previously received snapshot hashes
but no initial review unit. Planning now uses the retained manifest directly,
also avoiding a separate graph-file read for this coverage inventory.
The static index summary remains separate and can be incomplete with zero indexed
files; planned units carry no attempts or reviewed paths and never imply native
parser/detector support. Non-UTF8 omissions remain explicit snapshot notes.
A regression initializes, validates and imports a five-surface run with malformed
Python, documentation, unsupported text, a hidden agent configuration and a lockfile,
plus an omitted binary. It checks exactly one planned unit per admitted path,
unchanged partial-coverage semantics and incomplete static index evidence. Existing
hidden-file regression now includes its policy file as an explicit planned unit.
All 15 audit integrations and four CLI audit integrations pass; strict all-target
workspace Clippy, formatting and diff checks pass. Audit workflow documentation
updated. Changes remain local. Reconnaissance must still refine generic boundaries
and attack classes and identify excluded surfaces. General artifact intake,
scalable refresh, hard deadlines and external phase exit evidence remain open.
No target execution, live provider calls, deployment or publication occurred.


2026-10-11 selected-scope coverage accounting: a complete imported audit must
now account for every selected source manifest path in its starting/reviewed
coverage paths. Previously, deleting a planned unit and marking remaining units
covered could shrink the ledger without changing the frozen source scope.
Status additionally stays partial unless every selected path appears in the
reviewed paths of a covered unit. This also applies to retained legacy records;
merely listing a path as a starting point does not establish reviewed coverage.
Merged units remain supported and blocked/candidate units remain partial.
A regression rejects a complete run with a missing unit before import and checks
no revision was created, keeps a matching legacy attestation partial, accepts a
merged scope unit while keeping its unreviewed path partial, and clears partial
only after covered review attestations account for both paths. This is structural
accounting, not verification of reviewer claims or observed target execution.
All 16 audit integrations, four CLI audit integrations and strict all-target
workspace Clippy pass. Formatting/diff checks and audit contracts updated. Changes
remain local. External evidence, scalable refresh, hard deadlines and general
artifact intake remain open; no phase exit, deployment, publication, live provider
calls or target execution occurred.


2026-10-11 retained source identity consistency: audit status now checks the
stored manifest hash against its declared source snapshot before reconciling live
files. Previously, a legacy record could carry a missing or contradictory source
identity while matching current file hashes and be reported fresh with nonpartial
covered attestations. Inconsistent identity now makes status stale and partial,
with an explicit stored-snapshot diagnostic; current-source reads are skipped
when that internal check already fails. The general stale notice distinguishes
changed source or inconsistent identity instead of claiming only filesystem change.
A regression checks a valid covered legacy record, empty and contradictory
identities, unchanged memory, explicit recovery export without promotion, failed
revalidation of the recovered record, and restoration of consistent freshness.
Recovery export remains available for correction; this is a consistency check,
not storage authentication or validation of reviewer claims.
All 17 audit integration tests and strict all-target workspace Clippy pass.
Formatting/diff checks and audit documentation updated. Changes remain local.
External phase evidence, scalable reconciliation, hard worker deadlines and general
artifact intake remain open. No target execution, live providers, publication,
deployment or phase exit claim occurred.


2026-10-12 bounded native source reads: indexing, baseline assessment, current
Git diff evidence and finding excerpts now reuse one byte-capped reader. Baseline,
diff and excerpt paths previously checked filesystem metadata then used unbounded
read_to_string, allowing file growth after that check to exceed the intended 1 MiB
read budget. The shared reader takes at most 1 MiB plus one overflow byte, rejects
oversized content before decoding, and preserves existing UTF-8 and error behavior.
No new dependency or schema change was needed. Required analysis failures remain
incomplete; finding excerpts retain their existing empty-result behavior on errors.
A regression checks valid multibyte text exactly at the byte limit, a source just
over it, invalid UTF-8 and repaired source. Baseline creation fails and verification
cannot PASS for the oversized/invalid sources, while exact-limit and repaired
sources retain their expected behavior. All 46 graph integrations pass (one manual
latency measurement ignored), along with 17 audit integrations, two graph units,
and strict all-target workspace Clippy. Formatting/diff checks and agent contracts
updated. This bounds source bytes transferred into these native paths, not all
process memory, filesystem races or blocking read time. Hard deadlines, scalable
refresh, general artifact intake and independent phase evidence remain open.
Changes remain local; no target execution, live provider calls, deployment,
publication or global binary replacement occurred.


2026-10-12 saved baseline bounds and consistency: baseline JSON now has a
16 MiB UTF-8 byte limit on creation and stored reads. Creation checks the serialized
record before opening the debt-replacement transaction. Reads use a SQLite BLOB
slice capped at limit+1 before JSON parsing, and oversized saved evidence fails
without implicit Git fallback, current-source reassessment or lifecycle updates.
Stored contracts also require matching finding/key counts, internally consistent
supplied source manifests, and matching finding/snapshot/detector identities for
modern evidence records. Missing legacy typed provenance retains conservative
WARN compatibility instead of fabricating historical evidence.
Two regressions cover ASCII and multibyte oversized records, exact-limit JSON,
restored valid records, missing finding keys, contradictory snapshot IDs and
mismatched modern finding/detector provenance. Invalid evidence leaves index
metadata and existing debt status unchanged. These checks detect inconsistency;
they do not authenticate deliberate database edits or bound total SQLite/JSON
serialization memory. The new creation cap is an explicit compatibility ceiling
for unusually large baselines; split scope or improve evidence storage rather
than silently truncating accepted debt.
The full offline locked workspace suite passes: 146 tests, with one manual graph
latency measurement ignored. This includes 48 graph integrations, 17 audit
integrations, 20 CLI integrations, 18 CLI/TUI units and eight mock-provider tests.
Strict all-target workspace Clippy, formatting and diff checks pass. README and
agent contracts updated. All changes remain local, preserving earlier edits.
Scalable refresh, worker deadlines, artifact intake, independently labelled
holdout/comparator measurements, external audits and reviewed containment remain
open. No target execution, live provider call, deployment or publication occurred.


2026-10-12 finding explanation provenance: deterministic finding explanations
now carry native backend identity, the indexed source snapshot, index completeness,
a separately hashed current source excerpt and an excerpt_matches_graph flag.
Previously, source excerpts and refreshed symbol/flow evidence had no machine-
readable identity connecting their views. Missing/unindexed/different excerpts
now add an explicit coverage note that graph evidence describes the indexed view.
Historical occurrence validity still requires scanning or verification; matching
current hashes does not confirm a historical finding. Missing fields in old typed
responses default to unknown/null identities and false completeness/match flags.
A targeted graph regression checks fresh identity agreement, an injected differing
indexed hash, repaired source with preserved historical warning, missing source
and old-response decoding. The MCP stdio integration verifies all new metadata
crosses the protocol and agrees with trace identity, while scope-escape rejection
and existing retrieval/diff/verification behavior remain intact. Both tests and
strict all-target workspace Clippy pass; formatting/diff checks and agent contracts
updated. This is view-disagreement metadata, not atomic filesystem observation,
full-scope proof, storage authentication or independent review.
Changes remain local; scalability, hard deadlines, artifact intake and external
phase evidence remain open. No target execution, live providers, publication,
deployment or global executable replacement occurred.


2026-10-12 ranked context graph provenance: security context now carries the
existing trace backend and indexed source snapshot identity. Investigation
consumers can compare context, graph navigation, traces and finding explanations
without treating matching symbol names as source equivalence. Identity remains
stable across target selection/output limits and changes with admitted source;
completeness and omissions retain their separate meanings. Old typed responses
keep unknown/null provenance.
A graph regression checks target/limit stability, trace equality, unrelated source
changes, incomplete indexing and legacy response decoding. The MCP integration
asserts context and trace metadata agree across stdio and preserves existing scope,
retrieval, explanation, diff and verification checks. Both targeted tests and
strict all-target workspace Clippy pass; formatting/diff checks and agent contracts
updated. The identity covers the indexed graph manifest, not historic findings,
separate Git observations, excluded paths, storage authentication or atomic live
filesystem reads. Historical finding selection retains its existing scan warning.
Changes remain local. Scalable refresh, hard deadlines, general artifact intake
and independent phase exit evidence remain open; no target execution, live
provider calls, deployment or publication occurred.


2026-10-12 refresh measurement foundation: added a stdlib-only native refresh
harness with deterministic independent Python modules, a fresh-database sample,
repeated unchanged refreshes and repeated one-file edits. It retains wall times,
index counters, completeness/coverage notes, scope failures, timeout errors,
platform/Python version, initial fixture identity and before/after binary hashes.
Nearest-rank p50/p95 use complete samples only and retain sample counts; partial
scope and counter/exit inconsistencies invalidate the measurement and return 2.
Reports are created exclusively and never overwrite historical measurements.
All 13 Python benchmark harness regressions pass, including timeout/partial/counter
rejection, percentile filtering, edit sequence, preserved partial reports,
no-overwrite behavior and invalidation on binary drift.
Local debug native measurements are retained under benchmarks: 1000 files with
three repeated samples completed, with a 13.31s fresh database index, 161.44ms warm
p95 and 174.88ms one-file-change p95. These three-sample synthetic figures are
only descriptive and include process/SQLite time. The 10000-file run indexed only
2000 files and explicitly reported the existing file cap in all three stages;
its measurement is invalid and complete-scope percentiles are null. This is
concrete gate failure evidence, not 10000-file performance or a competitive win.
The workload has no dependency graph/framework complexity, and measurements do
not include peak memory, cancellation, release builds, OS cache flushing,
independent labels or pinned competitors. Endpoint binary hashes do not prove
absence of replacement/restoration between checks. Benchmark documentation
updated; source compilation and diff checks pass. Changes and evidence remain
local. The next scalability work must address admitted scope and cold cost with
resource bounds before raising the cap; phase exit evidence remains outstanding.
No fixture/target execution, providers, deployment or publication occurred.


2026-10-12 indexed graph cleanup: project/file indexes now cover symbol and
security-annotation deletion in new and existing schema-v7 databases. Previously,
symbol cleanup could use a project/name index with residual file filtering,
while annotation cleanup lacked a matching index. The additive indexes preserve
all payload formats, schema version and semantic revision; older readers remain
compatible. New files also skip deletion of nonexistent prior records. Changed
and removed files retain their transactional cleanup and edge rebuild behavior.
A regression removes the indexes from an existing v7 fixture, reopens it, verifies
retained graph payloads/version, checks SQLite's DELETE query plans use both new
indexes and exercises new/changed/deleted-file symbol cleanup. All 149 locked
offline workspace tests pass, including 51 graph integrations and 17 audit
integrations; one manual latency test remains ignored. Strict all-target workspace
Clippy, formatting and diff checks pass. Agent/benchmark contracts updated.
The follow-up 1000-file debug refresh report retains a 14.96s fresh-database sample,
164.01ms warm p95 and 182.22ms one-file-change p95 across three samples. These do
not demonstrate an end-to-end improvement over the first run; the cold sample was
higher. Query-plan evidence establishes removal of a database lookup gap, not
representative latency or causal timing benefit. Profiling/repeated controlled
measurements are still needed. Full hashing/edge rebuilding, writer reservations,
the 2000-file cap, resource measurements, hard deadlines and external phase gates
remain open. All changes/evidence remain local; no target execution, provider
calls, deployment, publication or global binary replacement occurred.


2026-10-12 index stage diagnostics: IndexStats now retains optional millisecond
source-refresh, relationship-analysis and graph-persistence timings. Source refresh
includes writer reservation, prior IR load, enumeration, bounded reads and parsing;
analysis includes resolution/tracing/counting. Persistence ends before metadata
writing and commit. duration_ms previously ended before any graph writes; it now
includes those writes while still excluding metadata/commit. CLI wall time remains
the end-to-end measure. Legacy stats decode missing stage timings as null.
A regression checks timing bounds, exact returned/stored stats, unchanged refresh,
legacy status/snapshot decoding and timing restoration after refresh. All 52 graph
integrations pass (one manual latency test ignored), along with 17 audit
integrations, two graph units and strict all-target workspace Clippy. The local
CLI build succeeds; formatting and diff checks and agent/benchmark docs updated.
The first instrumented 1000-file debug report is retained. Its cold internal stages
were 13314ms source refresh, 72ms analysis and 998ms graph persistence, versus
19666ms CLI wall time. Source refresh dominates these measured internal stages;
the wall-time gap cannot be attributed to one operation from these coarse timers.
Warm/one-file-change wall p95 were roughly 544/550ms across three samples, higher
than earlier runs. These observations do not establish a speed improvement,
representative performance or a causal regression; controlled repetition and finer
profiling remain required. Index parsing/read/loading and redundant write costs
now have observable stage boundaries instead of speculative prioritization.
Full reconciliation, edge rebuilding, writer reservations, the 2000-file cap,
peak memory/cancellation measurement, hard deadlines and external phase gates
remain open. Changes/reports stay local; no target execution, live providers,
deployment, publication or global executable replacement occurred.


2026-10-12 source refresh bottleneck discrimination: stage diagnostics now
separate checked-path/open/bounded-read work from changed-file AST/security
extraction. Durations accumulate before millisecond conversion so repeated small
operations are not individually rounded away; hashing/loading/enumeration and
bookkeeping remain residual source-refresh work. Optional counters preserve
unknown/null decoding for the first stage-timing format. No parser cache or
concurrency layer was added on an unverified bottleneck assumption.
The existing timing regression now checks subset bounds, unchanged extraction
and intermediate legacy-field decoding. It passes, as do strict all-target
workspace Clippy and the local CLI build; formatting/diff checks and contracts
updated. The complete 1000-file/three-repeat debug benchmark is retained with
valid counter/scope/binary checks. Cold measured 13922ms in checked-path/open/read
versus 159ms extraction within 14119ms source refresh. This local result directs
next optimization toward filesystem latency rather than parser construction.
CLI wall time was 18721ms; warm/changed wall p95 were 197.48/217.97ms. Three-sample
synthetic timings do not establish representative performance, statistical gain,
OS cache state or a causal comparison with earlier runs. A zero millisecond
counter can represent sub-millisecond work. Peak memory, finer read-path profiling,
bounded prefetch/resource review, full reconciliation/edge rebuilding, the file
cap, hard deadlines and independent phase evidence remain open. All changes and
reports stay local; no target execution, providers, publication or deployment.


2026-10-12 bounded source read batches: native indexing now uses at most four
scoped readers at a time to address the measured filesystem-latency stage. Readers
share only canonical root/path data; SQLite access, byte admission, parsing, IR
reuse, notes and persistence remain serial. Results retain lexical order and
errors remain partial coverage. Single-file batches read directly; near the
16 MiB admitted-source quota, batches shrink to one file to preserve the existing
single-file overflow ceiling. All workers are joined; launch errors fail the
refresh transaction and reader panics are reported after joining the batch.
The per-file byte and project-scope checks remain shared with direct callers.
All 52 existing graph integrations and 17 audit integrations passed before the
new quota regression; that regression then passed with invalid UTF-8 among twenty
1 MiB files, exact admitted scope, ordered notes and repeat-cache consistency.
The MCP integration and strict all-target workspace Clippy pass. Formatting/diff
checks and agent/benchmark contracts updated. The local CLI builds and the valid
1000-file/three-repeat benchmark is retained: cold CLI wall time was 4.12s versus
18.72s in the previous run; warm/changed p95 were 216.43/221.65ms, not an improvement
in those warm observations. A single cold comparison is descriptive and cannot
establish controlled statistical benefit, general workloads or a release gate.
Read timing measures batch wall time including worker launch/join. The bound
covers concurrent source lengths, not allocator capacity, worker stacks or total
RSS. Blocked reads still delay joining/cancellation, and concurrent index calls
each have their own four-reader bound. Full reconciliation, edge rebuilding,
writer reservations, the 2000-file cap, resource studies, hard deadlines and
external phase evidence remain open. Changes/reports remain local; no target
execution, live providers, deployment, publication or global binary replacement.


2026-10-12 reused edge insertion: graph persistence now prepares its fixed SQL
insert once per refresh instead of once per edge. Binding, normalized payloads,
deduplication, full replacement and transactional semantics remain unchanged.
The statement ends before metadata/commit. No new dependency, cache, schema or
semantics revision was introduced. This addresses measured persistence work while
preserving the full reconciliation boundary rather than bypassing source reads.
A regression injects edge insertion failure after file updates/edge deletion,
checks files/edges/statistics all roll back and the connection returns to
autocommit, then retries and checks definition targets belong to refreshed symbols.
All 54 graph integrations and 17 audit integrations pass, along with two graph
units, strict all-target workspace Clippy and the local CLI build; one manual
latency test remains ignored. Formatting/diff checks and contracts updated.
The valid local 1000-file debug report is retained: warm persistence was 32..40ms
versus 47..48ms in the prior report; three-sample wall p95 was 211.33ms warm and
223.56ms changed. Cold wall time was higher at 7.02s. This does not establish a
controlled causal or overall speed improvement; the removed repeated preparation
is structural evidence, while comparative latency needs controlled repetition.
Incremental refresh, full edge rebuilding, writer/read delays, the 2000-file cap,
peak memory/cancellation studies, hard deadlines and external phase evidence
remain open. Changes/reports stay local; no target execution, live providers,
deployment, publication or global executable replacement occurred.


2026-10-12 strict Git subprocess completion: ScannerProcess now exposes its
actual optional exit code, and the Git read wrapper requires exit zero before
accepting stdout. Previously, it relied on the generic runner's scanner-specific
rule accepting exit one for findings, so a Git read could accept nonzero partial
output under the wrong protocol. Scanner exit-one finding behavior remains intact;
other runner errors/output/deadline limits retain their existing handling.
A real owned-file Git diff regression checks successful empty output versus
exit-one nonempty output and rejects the latter without echoing its contents.
Existing owned scanner subprocess regressions now check raw exit one/two codes
alongside their preserved findings/partial-error handling. All 17 scanner tests,
54 graph integrations, 17 audit integrations, two graph units and both CLI Git
diff integrations pass; one manual graph latency test remains ignored. Strict
all-target workspace Clippy, formatting and diff checks pass; agent contracts
updated. This closes a command-protocol consistency gap, not a detector accuracy
or competitive superiority gate. Scalability/file cap, resource measurement,
hard deadlines, artifact intake and external phase evidence remain open.
Changes stay local; no target execution, live providers, deployment, publication
or global executable replacement occurred.


2026-10-12 diff-context scope accounting: ranked context targeting diff now
keeps unavailable Git selection distinct from a known empty diff. Unavailable
selection, unindexed changed paths or deleted paths with no current graph symbols
make the response partial, instead of returning apparently complete empty context.
Deleted and unindexed paths remain visible as change metadata; notes direct
historical questions to scan_diff. Metadata candidates are capped at 200 and
omitted_count includes unadmitted changes plus response truncation. Indexed-path
membership uses a set rather than per-change full graph searches. Named symbol/
file context retains optional Git metadata, and graph identity remains graph-only.
A regression checks non-Git partial diff versus complete named context, clean
known-empty Git scope, complete indexed change, retained deleted metadata and
201 unsupported untracked paths with bounded selection/explicit omissions.
Higher-ranked applicable rules can displace change metadata, so omission checks
account for both layers. The targeted regression, MCP integration and strict
all-target workspace Clippy pass; formatting/diff checks and agent docs updated.
This is query-scope honesty, not baseline reconstruction, detection quality or
proof that excluded surfaces are safe. The cap/scalability, resource studies,
hard deadlines, artifact intake and external phase gates remain open. Changes
stay local; no target execution, live providers, deployment or publication occurred.


2026-10-12 repeated cold refresh observations: the existing refresh harness now
supports 1..10 fresh-database cold samples via --cold-repeats, default one. Each
sample generates identical initial modules in its own source root/database;
warm/edit observations use the final root. Temporary roots remain owned by the
harness and are cleaned together. Reports retain cold_repeats, actual counts,
per-sample outcomes/counters, hashes and complete-only nearest-rank summaries.
No OS cache flushing or independence/statistical confidence is implied.
A regression checks distinct cold roots, final-root reuse, source/edit counters,
three-sample p50/p95, retained counts and cleanup. All 14 Python benchmark tests
pass; Python compilation and diff checks pass. Benchmark docs updated. The actual
1000-file debug run completed all nine observations and retained its report:
cold p50/p95 2.67/4.58s, warm p95 205.72ms and one-file-change p95 239.38ms. This
spread confirms that prior single cold observations cannot establish a general
speedup; three samples remain descriptive. No earlier report was overwritten.
Controlled comparative/release-build runs, representative graph workloads,
peak-memory/cancellation evidence, scalable refresh/the 2000-file cap, hard
deadlines, artifact intake and independent phase gates remain open. Changes and
measurements stay local; no target execution, live providers, deployment,
publication or global binary replacement occurred.


2026-10-13 indexed context candidate accumulation: ranked retrieval now uses the
existing stdlib BTreeMap for keyed candidate merging instead of a linear vector
search on each insertion. This removes quadratic candidate lookup growth while
preserving first evidence, maximum score, distinct reason order and final
score/key sorting. No dependency, new public contract, schema or semantics
revision was introduced; output caps and omissions retain their meanings.
A 500-function file regression checks complete-but-truncated retrieval, bounded
target/items arrays, evidence uniqueness, reason uniqueness, descending scores,
repeat-stable selected evidence, unchanged omissions and source identity. All
56 graph integrations and 17 audit integrations pass, along with two graph units,
the MCP stdio integration and strict all-target workspace Clippy. One manual
latency test remains ignored. Formatting/diff checks and agent contracts updated.
This is structural lookup complexity improvement; no before/after end-to-end
latency or memory benefit is claimed. Full graph scans/IR allocation, ranking,
source reconciliation, edge rebuilding, the 2000-file cap, resource/cancellation
studies, hard deadlines, artifact intake and external phase gates remain open.
Changes stay local; no target execution, live providers, deployment, publication
or global executable replacement occurred.


2026-10-13 explicit context target omissions: security context now reports an
optional omitted_target_symbols counter for the independently bounded target array.
Previously, omitted_count described ranked evidence/changed metadata but did not
state how many matching targets were left out. Current responses carry a number;
old typed responses decode missing values as null rather than claiming zero.
Analysis/scope completeness remains separate from response exhaustiveness.
The existing 500-function regression now checks 301 omitted targets at limit 200,
500 at limit one, stable graph identity across limits and unknown legacy decoding.
The MCP integration checks an untruncated target's counter crosses stdio as zero.
Both targeted tests and strict all-target workspace Clippy pass; formatting/diff
checks and agent contracts updated. No full-scope/performance or phase completion
claim is implied. Scalable refresh/file cap, resource and cancellation studies,
hard deadlines, artifact intake and independent gates remain open. Changes remain
local; no target execution, providers, deployment or publication occurred.


2026-10-13 bounded audit history metadata: history queries now transfer bounded
BLOB slices as text for revision/run/source/status/time fields instead of loading
arbitrary-length stored metadata. Fields then require consistent bounded hash/run/
status shapes and nonempty, control-free bounded import timestamps. UTF-8 errors
and oversized values fail before returning summaries; pagination lookahead rows
receive the same checks. No payload reads, source refresh or promotion was added.
A regression injects large ASCII/multibyte strings and terminal controls across
retained metadata fields, verifies rejection, restores metadata and checks latest
selection, freshness-unchecked history and retained revision retrieval. All 18
audit integrations, the CLI history integration and strict all-target workspace
Clippy pass. Formatting/diff checks and audit docs updated. These limits bound
metadata transferred/decoded by Rust, not all SQLite/process memory, and shape
checks do not authenticate metadata against retained content or reviewer claims.
Scalable refresh/file cap, resource/cancellation studies, hard deadlines, general
artifact intake and independent phase gates remain open. Changes remain local;
no target execution, live providers, deployment or publication occurred.

2026-10-13 bounded job-list metadata: repository job listing now selects bounded
65-byte BLOB slices for stored identities and timestamps before Rust decoding.
Identity and nonempty, control-free timestamp checks cover the pagination
lookahead as well as returned rows. A corrupt record fails the listing without
partial summaries or job mutation. A regression corrupts an older lookahead row
with oversized ASCII/multibyte values, invalid hash characters, empty timestamps
and terminal controls; errors release the transaction and retained jobs remain
readable after restoration. The exact 64-byte timestamp boundary is accepted.
All 57 graph integrations passed (one manual latency test ignored), the CLI job
listing integration passed, and strict all-target workspace Clippy passed.
Formatting/diff checks and static-job docs updated. Limits bound Rust metadata
transfer, not all SQLite/process memory; shape checks do not authenticate metadata
or establish source freshness. No phase exit gate is closed. Hard deadlines,
scalable refresh, general artifact intake and external review remain open.
Changes remain local; no target execution, deployment or publication occurred.

2026-10-13 focused static context CLI and measurement: added `sentinel context
TARGET --project PATH --max-items N` using the existing graph context engine.
JSON retains backend/source identity, reasons, omissions and scope notes. Complete
scope exits 0; partial scope exits 2, separately from output truncation. No provider
calls or target execution were added. The regression covers bounded complete
output, invalid-source partial JSON, provenance and rejected output limits.
Invalid files change completeness independently of the valid indexed-source hash.
The native refresh harness now optionally measures warm and directly edited
focused context via --context, validating target presence, bounds, provenance,
omission counters and exit/completeness; partial samples never enter percentiles.
Two harness regressions cover malformed/partial/timeout responses and retained
partial reports with separate context edits. All 21 CLI integrations, all 16
Python benchmark tests and strict all-target workspace Clippy pass.
A local 1000-file debug run had complete context p95 239.47ms warm and 256.67ms
edited (three samples each). A separate 10000-file run retained partial results
under the 2000-file cap and null complete-scope percentiles. New reports, README
and agent/benchmark instructions are retained; prior reports remain unchanged.
This advances measurement access, not independent graph-query accuracy scoring
or the 10000-file latency gate. No phase exit is claimed. Scalable refresh, hard
deadlines, artifact intake and independent evidence remain outstanding. Changes
remain local and the global executable was not replaced or published.

2026-10-13 context benchmark source reconciliation: complete focused-context
responses must now match the exact generated full-source manifest identity,
including every current edit, rather than only carrying a well-formed hash.
The expected identity is recorded with each sample. Contradictory complete source
scope fails measurement and cannot enter latency percentiles; legitimate partial
indexed-subset identities remain partial. A regression feeds apparently complete
but stale JSON and verifies retained report failure, mismatched expected/returned
identities and null context percentiles. Warm/edit mocks also verify expected
hashes against actual fixture bytes, not newline-normalized reads.
Live validation exposed Windows newline translation in the harness's generated
fixture writes. Writes now explicitly use LF and reports disclose fixture_newlines.
The first failed expectation run is preserved, alongside a corrected LF report
with six complete context identities matching the current fixture and descriptive
warm/edited p95 281.75/295.42ms (three samples each). This was a harness contract
mismatch, not evidence of a Sentinel stale-source defect or speed regression.
All 17 Python benchmark tests pass. Benchmark documentation and diff checks are
updated; no Rust implementation changed this milestone. Earlier reports remain
unchanged, and changed fixture bytes prevent a controlled performance comparison.
No phase exit is claimed; the 2000-file cap, independent graph labels, scalable
refresh, hard deadlines and general artifact intake remain outstanding. Changes
remain local; no target execution, live provider calls, deployment or publication.

2026-10-13 indexed flow-edge endpoint lookup: graph refresh now constructs a
borrowed BTreeMap of source/sink annotations keyed by kind, owner and start line,
rather than linearly scanning all project annotations for both ends of every
taint path. First-match collision behavior and symbol fallback remain unchanged;
no schema, detector or semantics revision changed. Endpoint lookup is logarithmic
in key count after map construction; overall speed and memory are unmeasured.
A regression checks 24 independent request-to-SQL paths bind persisted source/sink
annotation identities to the correct owner and sink line, survive warm refresh
unchanged, and remove only the repaired path after parameterizing one query.
All 58 graph integrations, 18 audit integrations and two graph unit tests pass
(one manual latency test remains ignored); strict all-target workspace Clippy,
formatting and diff checks pass. Agent contracts updated. Full hashing/analysis,
the 2000-file cap, hard deadlines, artifact intake and independent exit-gate
evidence remain open. Changes remain local; no target code, providers, deployment
or publication were invoked.

2026-10-13 named graph query CLI: added `symbols`, `callers` and `callees` JSON
commands backed by the existing repository-bound static query engine. Shared
argument handling retains the existing context CLI's project/limit interface;
limits remain 1..200. Results preserve target/neighbor direction, direct call
edges, unresolved flags, backend/source identity, index coverage and omissions.
Partial indexes exit 2 independently of bounded output omissions. No new analysis
semantics, MCP tools, schema or executable query surface were introduced.
The integration regression checks a cross-file helper's two callers,
one-edge truncation, outgoing direction and shared provenance, unresolved opaque
calls without fabricated neighbor symbols, symbol locations, invalid-source
partial JSON and invalid limits for all three commands. All 22 CLI integrations,
including context and MCP stdio, pass; strict all-target workspace Clippy,
formatting/diff checks pass. README and agent contracts updated. This prepares
fixed shell query-corpus measurement; independently labelled graph-query scoring
remains the next measurement slice, not an achieved exit gate. Full reconciliation,
the 2000-file cap, hard deadlines, artifact intake and external evidence remain
open. Changes remain local; the global executable was not replaced, and no target
execution, providers, deployment or publication occurred.

2026-10-13 fixed graph-query scoreboard: added a separate stdlib query runner with
explicit symbol/edge expectations instead of reusing detection-positive labels.
Only symbols/callers/callees commands are admitted. Exact multisets retain duplicate
call names/resolution flags and file/name symbols. Complete responses require
untruncated bounded output, consistent exit/coverage and a full fixture source
identity; partial/malformed/stale/timeout responses cannot receive correctness.
Reports retain expectations, full query output, scored projection, hashes and
separate complete-accuracy/all-attempt correct-response Wilson intervals, including
per-class/split summaries. Binary drift and failures take exit-2 precedence; the
optional regression gate returns 1 for incorrect complete responses. Outputs do
not overwrite retained reports. Existing fixture safety/budget validation was
extracted and reused without weakening the detection runner's contracts.
Four author-labelled queries from one development family passed locally. These
are separate from the 68 detection cases; no independent/held-out claim follows.
All 21 Python benchmark tests pass, including stale/truncated/partial output,
multiset/unresolved distinctions, malformed fixtures, split leakage, timeout,
binary drift and retained-report gates. CI configuration now runs all benchmark
unit tests and the query seed, but hosted execution/publication was not performed.
Benchmark docs and diff checks updated. Endpoint, type, taint/guard query scoring,
realistic independently labelled families and pinned comparator evaluation remain
open, alongside scalable refresh, hard deadlines and artifact intake. No phase
exit is claimed. No target code, providers, deployment or publication was invoked.

2026-10-13 directed endpoint query scoring: fixed query cases may now opt into
expected.endpoint_edges labels binding returned call from/to IDs to declared
file/name owner/callee symbols. Name/resolution-only labels remain compatible;
the original seed and reports were preserved. Resolved calls require both known
endpoints, each call requires its owner, and inconsistent symbol identities fail
measurement. Unresolved destinations remain null rather than invented symbols.
Endpoint labels must agree with the existing name/resolution multiset.
The regression distinguishes correct and reversed calls with identical names and
neighbor lists, rejects dangling resolved identities, preserves opaque unresolved
calls and rejects contradictory labels. All 22 Python benchmark tests pass.
The endpoint extension of the same four author-labelled questions passed locally,
as did the original projection rerun. This does not add four independent cases
or meet a held-out/reviewer gate. New hashed reports and endpoint corpus retained;
benchmark docs, CI configuration and diff checks updated. Hosted CI was not run.
File/name endpoints still lack qualified method/type and runtime-dispatch proof;
flow/guard query scoring, independent labels, comparative runs, scalable refresh,
hard deadlines and artifact intake remain open. No phase exit is claimed. No
Rust implementation changed; no target code, provider, deployment or publication
was invoked.

2026-10-14 unique import-target reuse: relationship refresh computes each import's
unique indexed module once and shares the result between IMPORTS edges and every
matching call. The search stops after the second match because ambiguity already
requires unresolved output. Calls no longer repeat a file-wide module count;
existing symbol/lexical lookup and ambiguous-import behavior remain unchanged.
No schema or semantics revision changed; cache lifetime is one source refresh,
not a persistent assumption about subsequent filesystem changes.
The new regression verifies twenty calls and their import edge all resolve,
become unresolved when a competing package module appears, and resolve again
when that competing module is removed. The existing 58 graph integrations,
18 audit integrations and two graph units passed; the added regression, named
CLI graph-query integration and strict all-target workspace Clippy passed too.
All four directed development query projections passed against the rebuilt local
CLI and are retained in query-local-2026-10-14-import-targets.json. Formatting/diff
checks and agent contracts updated. This removes repeated module search work,
not full reconciliation or global symbol searches, and does not establish an
overall performance/resource improvement. The 2000-file cap, hard deadlines,
artifact intake, independent labels/reviews and other phase gates remain open.
Changes remain local; no target code, live providers, deployment or publication
were invoked.

2026-10-14 keyed resolver symbol lookups and workspace verification: relationship
refresh now groups imported candidates by short name and indexes owner lookup by
symbol ID. Candidate groups preserve all duplicates in prior traversal order;
ID lookup preserves the first match. Module filtering, lexical scope, instance
method handling and ambiguity remain unchanged. No schema, detector identity or
semantics revision changed. The maps borrow current IR; they do not persist a
cache across refreshes or establish new source/runtime guarantees.
Full workspace verification passed: 161 Rust tests, with one manual latency test
ignored, including 59 graph integrations, 18 audit integrations, 22 CLI integrations
and local/fake-provider transport contracts. All 22 Python benchmark tests and
strict all-target workspace Clippy pass. Four directed development query checks
also pass against the rebuilt local binary; their hashed report is retained in
query-local-2026-10-14-symbol-lookups.json. Formatting/diff checks and agent docs
updated. This removes repeated project-wide symbol-name/owner searches, while
same-file lexical scans, full reconciliation, file admission limits and broader
analysis cost remain. No measured overall speed/memory or competitive improvement
is claimed. Hard deadlines, scalable refresh, artifact intake, independent labels,
review/containment/workflow studies and all related phase gates remain open.
Changes remain local; no target code, live providers, deployment or publication
were invoked.

2026-10-14 imported context evidence repair: security context previously looked
up an IMPORTS file endpoint as a module-symbol ID, so uncalled imported modules
never contributed their intended dependency symbols. The same file/symbol key
mismatch also omitted import relationships from target-file evidence. Context
now joins imports through a keyed indexed-file lookup and explicitly admits
imports originating from target files. Unique imports contribute their dependency
symbols at the existing score/reason; ambiguous imports expose unresolved edges
without guessing symbols. Output limits/omissions and source identity remain
separate from analysis completeness. This fixes retrieval, not extraction or
flow semantics; no schema/detector revision or provider behavior changed.
A regression checks uncalled dependencies, bounded omission reporting and stable
identity across limits, new ambiguity without guessed modules, visible unresolved
import evidence, and recovery after removing the ambiguous module. It caught the
second omitted-relationship path before the shared selection condition was fixed.
All 60 graph integrations, 18 audit integrations, two graph unit tests and 22 CLI
integrations (including context and MCP stdio) pass; one manual latency test remains
ignored. Strict all-target workspace Clippy, formatting/diff checks pass. README
and agent contracts updated. Changes remain local and the global CLI was not
replaced. Full reconciliation, the file cap, hard deadlines, artifact intake and
external labels/reviews remain open; no phase exit or comparative win is claimed.
No target code, live providers, deployment or publication were invoked.

2026-10-15 qualified symbol query scoring: query cases can opt into qualified-name
symbol and endpoint labels, while legacy short-name cases remain compatible.
Results retain the selected mode. Qualified mode fails missing qualified fields
rather than falling back to short names; otherwise same-named methods in different
classes could look correct despite a wrong lexical callee. The regression checks
correct and wrong class qualification, missing fields and rejected mode values.
All 23 Python benchmark tests pass. Two new author-labelled questions from one
lexical-method family pass against the local CLI, and the original four directed
endpoint questions pass again. Hashed reports and the qualified corpus are
retained; old corpora/reports remain unchanged. This brings distinct query questions
to six across two development families, with alternate projections not counted as
new cases, separately from the 68 detection cases. Benchmark docs, status table,
CI configuration and diff checks updated. Hosted CI was not run or published.
No Rust analysis semantics changed. Inheritance, type/runtime dispatch, overloads,
flow/guard scoring, independent labels and comparative evidence remain open, as
do scalable refresh, deadlines and artifact intake. No phase exit is claimed.
No target code, live provider, deployment or publication was invoked.

2026-10-16 bounded trace CLI: added `sentinel trace TARGET --project PATH` using
the existing native trace engine. Optional exact sink filtering and explicit
call-depth/path/node budgets retain engine limits/defaults. JSON includes static
paths, confidence, coverage and backend/source identity; partial/budget-exhausted
traversal exits 2. Completeness remains traversal coverage, not a verification
PASS, confirmed exploit or clean verdict. The budgets apply before target/sink
filtering, and request errors may return exit 2 without JSON.
The integration regression checks a cross-file request-to-SQL path, source/sink
locations and provenance, sink filtering, a node-budget partial response with
stable source identity, a parameterized repair with changed identity and no path,
invalid budget flags and a missing target. All 23 CLI integrations, including
context and MCP stdio, and strict all-target workspace Clippy pass. Formatting/
diff checks, README and agent instructions updated. No native extraction/flow
semantics, schema or provider behavior changed. The command prepares shell-based
flow-query measurement; independent trace/guard labels, comparative runs, scalable
refresh, hard deadlines and artifact intake remain open. No phase exit is claimed.
Changes remain local; the global executable was not replaced. No target code,
live providers, deployment or publication were invoked.

2026-10-16 static trace endpoint scoreboard: the existing fixed query harness now
accepts trace cases with exact sink-category and directed source/sink file/line/
qualified-symbol endpoint labels. Shared source identity, backend, coverage,
exit-status, failure accounting and retained-report gates apply to traces too.
Traversal budgets are fixed and recorded (depth 8, paths 200, nodes 10000);
partial/exhausted analysis never counts as correct. Complete empty path output
can satisfy an explicitly labelled safe counterpart, not a general clean verdict.
Two regressions cover correct/reversed locations, wrong categories, missing paths,
invalid/oversized/stale output, contradictory complete/exit responses, partial
analysis, malformed labels and the emitted CLI budget arguments. All 25 Python
benchmark tests pass. A three-file request-to-SQL endpoint question and its
parameterized counterpart pass locally, as do the earlier qualified method
questions. New source/binary/corpus-hashed reports and trace corpus retained;
old evidence unchanged. CI, benchmark docs, status table and diff checks updated;
hosted CI was not run. There are eight authored query questions across three
related development families, separately from the 68 detection cases; none are
independently adjudicated or held out. Intermediate trace steps, confidence,
guards/sanitizers and runtime verification remain unscored. No Rust semantics
changed, no phase exit is claimed, and scalable refresh, hard deadlines, artifact
intake and external review remain open. No target code, live provider, deployment
or publication was invoked.

2026-10-16 ordered trace-step scoring: fixed trace questions can opt into exact
ordered file/line/qualified-symbol steps in addition to category and endpoints.
Only the outer path collection is unordered; intermediate step order and duplicates
remain significant. Missing/malformed lists, over-1000-step output and inconsistent
source/sink boundaries fail measurement. Valid-boundary paths with skipped or
reordered intermediates count as incorrect rather than silently passing endpoint
checks. Endpoint-only trace questions and existing call/symbol questions remain
compatible. Reports retain each trace question's selected scoring mode.
Two regressions cover correct, reordered, skipped, reversed-boundary, missing and
oversized paths plus invalid label/mode contracts. All 27 Python benchmark tests
pass. The same unsafe/safe trace pair passes both ordered and endpoint-only live
modes against the local CLI; new hashed reports and ordered corpus are retained.
The eight distinct development question count is unchanged. CI configuration,
benchmark docs and diff checks updated; hosted CI was not run. Native call steps
use callee entry lines and do not prove runtime dispatch. Operation text, columns,
confidence and guard/sanitizer validity remain unscored; labels are still authored,
not independently adjudicated or held out. No Rust semantics changed, no phase
exit is claimed, and scalable refresh, hard deadlines, artifact intake and external
review remain open. No target code, provider, deployment or publication was invoked.

2026-10-17 Python named-import scope repair (semantics revision 12): the query
corpus reproduced two errors before implementation: a same-named class method made
a valid module-level imported helper spuriously ambiguous, and a method without
any module export incorrectly resolved a plain named import. Named-import plain
calls in Python now require the candidate's qualified name to match the module
binding. Class methods/nested functions are excluded while duplicate module-level
definitions remain unresolved. Namespace chains, dynamic exports and rebinding
retain their existing limitations. Semantics revision 12 invalidates old cached IR
and baseline/job detector identities; source identity is not retroactively changed.
A regression covers valid aliased imports alongside class/nested collisions,
missing module exports and duplicate top-level definitions. Full workspace tests
pass (164 Rust tests; one manual latency test ignored), all 27 Python benchmark
tests and strict all-target workspace Clippy pass. The two reproduced questions
improve from 0/2 to 2/2 correct on identical fixture identities. All 68 detection
development cases and ten distinct graph/trace questions pass after the change;
new hashed before/after and revision-12 reports are retained. These corpus groups
ran concurrently for correctness, not controlled performance comparison.
README, framework contracts, roadmap/status, benchmark instructions and CI
configuration updated; hosted CI was not run. This adds two authored questions
from one import-scope family, making ten questions/four development families
separate from detection counts; no independent/held-out improvement, competitive
win or phase exit is claimed. Scalable refresh, deadlines, artifact intake and
external reviews remain open. Changes remain local and the global executable was
not replaced. No target code, live provider, deployment or publication was invoked.

2026-10-17 Python namespace/attribute boundary repair (semantics revision 13):
follow-up queries reproduced four remaining import errors under revision 12.
Direct namespace calls suffered the same method/name collision as plain imports;
method-only candidates could impersonate module exports, named-import attributes
were resolved as calls to their base binding, and deeper namespace/class chains
were guessed from a matching short name. Python imported calls now require their
supported syntactic shape (plain named binding or direct namespace member), and
both forms require module-level candidates. Unsupported chains and bare module
calls remain unresolved; supported aliased direct calls still work. Revision 13
invalidates old IR and baseline/job detector identity rather than promoting prior
interpretation as current proof. Runtime rebinding/class dispatch remain unsupported.
A regression checks all four boundary forms plus a module-object call. Full workspace
tests pass (165 Rust tests; one manual latency test ignored), all 27 Python benchmark
tests and strict all-target workspace Clippy pass. The four reproduced questions
improve from 0/4 to 4/4 correct on identical fixture identities. All 68 detection
cases and fourteen distinct graph/trace questions pass under revision 13; new hashed
before/after and revision-13 reports are retained. Corpus groups ran concurrently
for correctness, not controlled performance comparison. New questions stay in the
same import-scope family, so the four development-family count is unchanged.
README, framework contracts, roadmap/status, benchmark docs and CI configuration
updated; formatting/diff checks pass. Hosted CI was not run and the global binary
was not replaced. No phase exit, independent/held-out improvement or competitor
win is claimed. Scalable refresh, deadlines, artifact intake and external reviews
remain open. No target code, live provider, deployment or publication was invoked.

2026-10-17 direct receiver boundary repair (semantics revision 14): two authored
Python/JavaScript questions reproduced deeper self/this attribute calls incorrectly
resolving to the current class's same-named helper. Lexical receiver resolution now
requires exactly a direct member; different receivers behind attribute chains
remain unresolved instead of inheriting the current class's method identity.
Direct self.helper/this.helper calls retain their targets. Revision 14 invalidates
old IR and baseline/job detector identities; no new type/runtime dispatch support
or schema change is implied.
The regression checks direct and deeper calls for Python and JavaScript, selecting
the explicit Worker.run owner rather than unrelated auxiliary module-scope edges.
Full workspace verification passes (166 Rust tests, one manual latency test ignored),
all 27 Python benchmark tests and strict all-target workspace Clippy pass. Both
reproduced questions improve from 0/2 to 2/2 on identical fixture identities. All
68 detection cases and sixteen distinct graph/trace questions pass under revision
14; new hashed reports retained, preceding evidence unchanged. Corpus groups ran
concurrently for correctness, not controlled performance comparison. Two questions
add one related development family, for five families total, without independent
labels/holdout or comparative proof. README, framework contracts, roadmap/status,
benchmark docs and CI configuration updated; formatting/diff checks pass. Hosted
CI was not run, and the global executable remains unchanged. Phase exit gates,
scalable refresh, hard deadlines, artifact intake and external reviews stay open.
No target code, live provider, deployment or publication was invoked.

2026-10-17 Python method lexical-scope repair (semantics revision 15): two authored
queries reproduced bare calls inside a method resolving to the enclosing class's
helper instead of a module helper, or falsely resolving when no lexical helper
existed. Python bare-call lookup now skips enclosing class namespaces while
retaining the current scope and enclosing function/module bindings. Nearest
function-local helpers still take precedence. Direct receiver and other-language
resolution retain their existing contracts; runtime binding/descriptor behavior
and compiler-level scope proof remain unsupported. Revision 15 invalidates cached
IR and baseline/job detector identities rather than retaining prior interpretation.
The regression checks module-helper selection, a method-only unresolved case and
nested-function priority from the explicit Worker.run owner. Full workspace tests
pass (167 Rust tests; one manual latency test ignored), all 27 Python benchmark
tests and strict all-target workspace Clippy pass. Both reproduced questions improve
from 0/2 to 2/2 on identical fixture identities. All 68 detection cases and eighteen
distinct graph/trace questions pass under revision 15; new hashed reports retained.
Corpus groups ran concurrently for correctness, not controlled timing comparison.
New questions stay within the existing lexical-method family, so five development
families remain; labels are authored, not independent or held out. README, contracts,
roadmap/status, benchmark docs and CI configuration updated; formatting/diff checks
pass. Hosted CI was not run, global executable unchanged, and no phase exit or
comparative win is claimed. Scalable refresh, hard deadlines, artifact intake and
external reviews stay open. No target code, provider, deployment or publication
was invoked.

2026-10-19 Python import collision repair (semantics revision 16): two recorded
questions reproduced valid module imports being suppressed by unrelated nested
functions or same-named class methods in the importing file. Collision checks now
consider only module definitions and enclosing lexical scopes, excluding enclosing
class namespaces from method closures. Conflicting module/local/enclosing function
definitions stay conservatively unresolved. The shared resolver is reused across
CLI/MCP/context/flow consumers; no separate command-specific workaround was added.
Revision 16 invalidates cached IR and prior baseline/job detector identity. Import
statement scope, assignment/parameter rebinding and global/nonlocal remain unsupported.

Both questions improve from 0/2 to 2/2 with identical corpus/source identities;
before/after reports are retained. A native regression covers those two cases plus
module, current-function and outer-function conflicts. Full workspace tests pass
(168 Rust tests, one manual latency test ignored), all 27 Python harness tests and
strict all-target workspace Clippy pass. All 68 detection cases and twenty distinct
authored graph/trace questions pass under revision 16. The new questions stay in
the existing Python import family, leaving five correlated development families.
Fifteen revision16-*-2026-10-19.json reports record one stable binary identity;
parallel corpus runs establish correctness, not controlled latency performance.
README, contracts, benchmark instructions, CI configuration and roadmap/status
are updated. Hosted CI remains unverified and the global executable is unchanged.
No target execution, live providers, publication or deployment occurred. Phases
remain Started; independent labels, comparative runs, scalable refresh, hard worker
deadlines and externally reviewed containment remain outstanding.

2026-10-19 Python import statement scope (semantics revision 17): four authored
questions exposed function imports leaking into sibling functions, class imports
leaking into method closures, and a nearer function import failing to override a
module import. The existing nested-function closure case was already correct.
ImportRecord now carries a serde-defaulted lexical scope, populated during Python
AST traversal. The shared call resolver admits visible module/function imports,
excludes enclosing class namespaces, and selects the nearest binding scope before
module lookup. A missing nearer import remains unresolved rather than borrowing an
outer target. File-level import dependency edges still retain all syntactic imports.
Other languages retain their previous import resolution behavior. Revision 17 forces
cached IR reparsing and changes baseline/job detector identity; no SQLite migration
is needed. Legacy import records deserialize with empty scope. Assignment/parameter
rebinding, conditional/source-order execution and global/nonlocal remain unsupported.

The four-query corpus improves from 1/4 to 4/4 on identical corpus/source hashes.
The native regression also checks direct local imports, function closures around
classes, namespace-import isolation, missing nearer modules and legacy deserialization.
Full workspace tests pass (169 Rust tests; one manual latency test ignored), all
27 Python harness tests pass, and strict workspace all-target Clippy, formatting
and diff checks pass. All 68 detection cases and twenty-four distinct authored
graph/trace questions pass. These remain five correlated development families;
no independent adjudication, holdout or competitor improvement is claimed. Sixteen
revision17-*-2026-10-19.json reports retain one stable binary identity; parallel
runs are correctness checks, not controlled latency evidence. README, contracts,
benchmark instructions, roadmap/status and local CI configuration are updated.
Hosted CI and external phase gates remain open. The global executable was not
replaced; no target code, live providers, deployment or publication was invoked.

2026-10-23 finding-row read boundary: individual lookup, active/historical listing
and legacy migration now share a bounded SQLite projection. Each of the ten text
columns returns at most 1 MiB plus one overflow byte; aggregate text above 1 MiB
is rejected before owned finding strings or JSON payloads are decoded. Numeric
columns reject nonnumeric storage in SQL. Empty text remains empty rather than
becoming NULL; invalid NULL records still fail. Oversized payloads produce a
size-only error instead of truncated evidence, and retained records are unchanged.
Context and explanation propagate errors instead of returning success from incomplete
history. Legacy migration rejects before history replacement and rolls back cleanly.
No schema or analysis-semantics revision change is needed (schema 7, semantics 17).

The database regression checks every text column, numeric-column corruption,
exact aggregate boundary, multibyte overflow, combined individually-small fields,
error redaction and migration rollback. A graph regression checks context and
explanation failure, untouched stored payload, and recovery after explicit repair.
Full workspace tests pass (171 Rust tests; one manual latency measurement ignored),
all 27 Python harness tests pass, and strict all-target workspace Clippy, formatting
and diff checks pass. README, agent contracts and roadmap/status are updated.
Existing 68-case detection and 24-question authored query reports remain historical;
those corpora were not rerun for this read-boundary-only change. No new accuracy,
latency, resource containment or competitive claim is made. Finding row counts,
write admission and extra legacy lifecycle metadata remain unbounded; ranked context
still reads active history before filtering. Scoped/paginated retrieval remains a
next Phase 1 task alongside worker deadlines and scalable refresh. External audits,
independent labels/holdout and containment review remain open phase gates. Hosted
CI was not run, the global executable remains unchanged, and no target code, live
provider, publication or deployment was invoked.

2026-10-23 scoped context history: ranked context now selects active stored findings
in SQLite from the files already present in its scored graph neighborhood, instead
of loading all active history and filtering it in Rust. This preserves imported
module and caller/callee neighborhood evidence. Exact file matching normalizes
slash separators, binds path parameters and excludes resolved records. A shared
API accepts at most 2000 paths and a row limit of 1–200; empty file scope returns
no records. Context requests up to 200 stored findings independently of max_items.
A lookahead row causes an explicit request error before decoding its payload;
no silent truncation, guessed omitted count or Complete response is manufactured.
Unrelated malformed/oversized records no longer break another neighborhood's
context, while matching corrupt records retain the preceding fail-closed behavior.
A file/active-state expression index is added on normal writable schema-v7 opens;
existing payloads, lifecycle state and analysis semantics (revision 17) are unchanged.

The database regression covers stable ordering, active filtering, both separator
forms, empty/injection-shaped paths, exact/invalid parameter budgets including
2000 paths, row overflow and malformed lookahead. The graph regression preserves
related/imported historical findings, excludes resolved/unrelated history, rejects
matching oversized payloads and fails row overflow at both output limits 1 and 200
without changing stored row counts. The schema-v7 reopen regression verifies index
recreation and SQLite query-plan selection while preserving graph payloads. Full
workspace tests pass (173 Rust tests; one manual latency test ignored), all 27
Python harness tests and strict all-target workspace Clippy pass; formatting and
diff checks pass. README, agent contracts and roadmap/status are updated. Historical
68-case detection and 24-question query reports were not rerun for this retrieval
change, and no comparative or latency claim is made. General history pagination,
write admission, query-work/total-memory limits, scalable refresh and hard worker
deadlines remain open. External audits, independent labels/holdout, human studies
and containment review remain phase gates. Hosted CI was not run and the global
executable is unchanged. No target execution, live provider, publication or deployment
was invoked; no user decision is required for continued bounded work.

2026-10-23 finding write admission: the shared insert/upsert path now enforces the
same combined 1 MiB text budget as finding reads, so new writes cannot create rows
that the reader rejects solely for payload size. Scalar text is charged before
serialization, then the three JSON array columns consume one shared remaining
budget. Standard-library slice writers stop JSON encoding when capacity runs out;
UTF-8 bytes, JSON escaping and delimiters all count. No custom writer or dependency
was added. All validation occurs before fingerprint computation or INSERT/UPDATE.
An oversized upsert leaves an existing resolved finding resolved. A failed later
finding in persist_scan rolls back earlier findings, scan metadata and snapshots
through the existing transaction, preserving old occurrence lifecycle state.

The new regression accepts an exact-limit write/read round trip; rejects scalar,
array, multibyte, escape-expansion and combined-array overflow without leaking
payloads; preserves existing upsert state; accepts subsequent valid writes; and
checks complete-scan rollback after a first valid and second oversized finding.
Full workspace tests pass (174 Rust tests; one manual latency measurement ignored),
all 27 Python harness tests and strict workspace all-target Clippy pass; formatting
and diff checks pass. README, agent contracts and roadmap/status are updated.
Schema 7 and analysis semantics 17 remain unchanged. Historical detection/query
benchmark reports were not rerun for this persistence change; no competitive,
latency or process-resource claim is made. Already allocated caller inputs,
full-report metadata/snapshot serialization, general history pagination, scalable
refresh and hard worker containment remain outside this admission bound. External
audits, independent labels/holdout, human studies and containment review remain
open phase gates. Hosted CI was not run, the global executable is unchanged, and
no target code, live provider, publication or deployment was invoked. No user
input is needed for continued bounded implementation.

2026-10-23 finding numeric contract: a regression reproduced acceptance of positive
infinity as persisted confidence. Shared read/write validation now requires finite
confidence in [0, 1] and a positive source line representable by SQLite i64 and the
host usize. Writes validate before JSON encoding, fingerprint computation or SQL;
reads validate before finding JSON decoding. Zero/negative stored lines are rejected
instead of silently rewritten to line 1. Invalid history remains untouched, and
legacy migration rolls back on rejection. A later invalid finding also rolls back
scan persistence, preserving earlier history and lifecycle state. This enforces
representation/range integrity; it does not calibrate confidence, establish current
source identity or confirm security findings. No schema/analysis revision change is
needed (schema 7, semantics 17).

The new regression checks infinities, NaN, out-of-range confidence, zero/overflowing
write lines, negative stored lines, valid confidence endpoints, the maximum supported
line, resolved-record upsert preservation, a failed second finding's transaction
rollback, scoped history rejection and legacy migration rollback without clamping.
Full workspace tests pass (175 Rust tests; one manual latency measurement ignored),
all 27 Python harness tests and strict workspace all-target Clippy pass; formatting
and diff checks pass. README, agent contracts and roadmap/status are updated.
Historical detection/query benchmark reports were not rerun for this storage
validation change. No comparative, latency or containment claim is made. General
history pagination, report-level metadata/snapshot budgets, scalable refresh and
hard worker limits remain outstanding alongside external audit, independent labels/
holdout, human studies and containment review gates. Hosted CI was not run, the
global executable is unchanged, and no target code, live provider, publication or
deployment was invoked. No user decision is needed for continued bounded work.

2026-10-23 scan persistence budgets: new scan writes now admit identifiers up to
128 UTF-8 bytes and a combined 1 MiB metadata budget for id, target, outcome,
encoded coverage notes and scanner results. Counters use checked SQLite i64
conversion instead of wrapping file/symbol counts or elapsed milliseconds.
Metadata is validated and encoded before opening the transaction. The existing
bounded slice encoder is reused for full finding snapshots with an 8 MiB individual
and 16 MiB aggregate encoded-byte budget. Escaping and delimiters count; the
aggregate is independent of each finding row's 1 MiB budget. Overflow rolls back
all earlier rows/snapshots and scan metadata before occurrence resolution. Errors
omit payload data. Serde is now a direct dependency of sentinel-db to reuse the
typed serializer; it was already pinned in the workspace. Offline lockfile update
added only that dependency edge and changed no package versions. Schema 7 and
analysis semantics 17 remain unchanged.

The new regression covers exact metadata and identifier boundaries, multibyte and
escape expansion, oversized target and scanner errors, redacted failures, checked
counter overflow, maximum supported duration, and aggregate snapshot exhaustion
after valid earlier inserts. It verifies complete rollback and retention of old
active findings and previously accepted scan metadata. Full workspace tests pass
(176 Rust tests; one manual latency measurement ignored), all 27 Python harness
tests and strict all-target workspace Clippy pass; formatting/diff checks pass.
README, agent contracts and roadmap/status are updated. Historical detection/query
reports were not rerun for this write-boundary change. These are application-byte
admission limits, not retrospective scan-history validation, physical SQLite/WAL
limits, caller-input limits or independent containment/latency proof. General history
pagination, scalable refresh and hard worker limits remain outstanding alongside
external audits, independent labels/holdout, human studies and containment review.
Hosted CI was not run, the global executable is unchanged, and no target code,
live provider, publication or deployment was invoked. No user input is required.

2026-10-23 batched occurrence resolution: complete scans now retrieve prior active
id/file metadata in 64-row keyset batches, replacing the unbounded candidate Vec.
Each read closes before lifecycle updates, and the next query seeks beyond the
last observed rowid. Updating resolved_at cannot cause OFFSET-style skips. The
initial query has no sentinel lower bound and handles minimum/negative/zero rowids;
new current-scan findings stay excluded. Id/file transfer and aggregate text reuse
the existing 1 MiB finding read boundary. Invalid later metadata aborts and rolls
back earlier resolution batches together with new scan metadata/findings/snapshots.
Existing admitted-file/deleted-in-target rules remain unchanged, including keeping
unselected existing and outside-target paths active. No schema or analysis revision
change is needed (schema 7, semantics 17), and no new dependency was introduced.

The regression spans multiple batches with reverse-ordered identifiers, minimum/
negative/zero rowids, selected and unselected files, deleted in-target and missing
outside-target paths, and a current-scan finding. It then introduces oversized
metadata late in a subsequent scan and verifies redacted failure, restored lifecycle
counts and retained prior scan/snapshot records. Full workspace tests pass
(177 Rust tests; one manual latency measurement ignored), all 27 Python harness
tests and strict all-target workspace Clippy pass; formatting/diff checks pass.
README, agent contracts and roadmap/status are updated. Historical detection/query
reports were not rerun for this persistence change. The bound applies to retained
candidate batches; total work, filesystem-stat latency, transaction journals and
worker deadlines remain outside it. General history pagination, scalable graph
refresh and hard worker limits remain open, as do external audits, independent
labels/holdout, human studies and containment review. No comparative or latency
claim is made. Hosted CI was not run, the global executable is unchanged, and no
target code, live provider, publication or deployment was invoked. No user input
is needed for continued bounded implementation.

2026-10-24 bounded index statistics: Engine.index/status now use the database's
bounded typed index-metadata API. Encoded statistics are limited to 1 MiB per
project on write, reusing the existing slice encoder before upsert. Reads transfer
at most 1 MiB plus an overflow byte as a SQLite BLOB slice and reject overflow
before JSON decoding. Missing records stay distinct from empty, malformed or
oversized records, which fail explicitly. The API joins caller transactions and
never commits or repairs retained metadata implicitly. Snapshot read failures
release owned transactions; a normal native refresh can recompute valid statistics
after source reconciliation while retaining unchanged file/edge evidence. Legacy
optional timing fields retain their unknown/default behavior. Schema 7 and
analysis semantics 17 remain unchanged; no dependency was added.

The database regression checks exact encoded limits, UTF-8/escape overflow, project
isolation, redacted failure, retained oversized bytes, malformed/empty/null payloads
and caller commit/rollback ownership. The graph regression checks failed status and
snapshot reads, released read transactions, retained metadata before refresh and
successful warm refresh with unchanged files/edges. Full workspace tests pass
(179 Rust tests; one manual latency measurement ignored), all 27 Python harness
tests and strict all-target workspace Clippy pass; formatting/diff checks pass.
README, agent contracts and roadmap/status are updated. Historical detection/query
reports were not rerun for this storage boundary. Cached file IR/edge payloads,
total snapshot budgets, general history pagination, scalable refresh and hard
worker limits remain separate work. External audits, independent labels/holdout,
human studies and reviewed containment remain open phase gates; no competitive,
latency or resource-containment proof is claimed. Hosted CI was not run, the global
executable is unchanged, and no target code, live provider, publication or deployment
was invoked. No user decision is needed for continued bounded implementation.

2026-10-24 distinct import targets (semantics revision 18): two development queries
reproduced repeated imports of one static symbol becoming falsely ambiguous. The
shared resolver now deduplicates candidate symbol IDs before counting possible
call targets. Repeated named and namespace imports retain their unique target;
different imported modules or distinct same-named export definitions stay unresolved.
Syntactic import/dependency evidence is retained, and runtime import hooks, rebinding
and dynamic exports remain unsupported. Revision 18 invalidates cached IR and prior
baseline/job detector identities rather than presenting earlier interpretation as
current evidence. Schema 7 is unchanged and no dependency was added.

Both questions improve from 0/2 to 2/2 on identical source/corpus identities. The
native regression also checks distinct-module and duplicate-definition ambiguity
from the explicit handler owner. Full workspace tests pass (180 Rust tests; one
manual latency measurement ignored), all 27 Python harness tests and strict
all-target workspace Clippy pass; formatting/diff checks pass. All 68 detection
cases and twenty-six distinct authored graph/trace questions pass under revision
18, with seventeen hashed reports retained. Corpus groups ran concurrently for
correctness, not controlled latency comparison. Five correlated development
families remain; no independent labels/holdout or competitive win is claimed.
README, contracts, benchmark instructions, CI configuration and roadmap/status
are updated. Hosted CI was not run, the global executable is unchanged, and no
target code, live provider, publication or deployment was invoked. Large-corpus
proof, scalable refresh, hard worker deadlines, broader reviewed semantics and
external audit/containment/human-study gates remain outstanding. No user input
is required for continued bounded implementation.

2026-10-24 index statistics identity validation: status and snapshot previously
accepted parseable statistics with a different project ID or repository path
inside the current project's metadata row, including a misleading complete flag.
The shared Engine.status boundary now rejects either mismatch with a fixed error
that omits stored identity values. Reads preserve retained bytes and transaction
ownership; normal native refresh recomputes statistics after source reconciliation.
The regression covers missing metadata, empty and foreign identities independently,
owned/caller read transactions, retained corrupt metadata, warm repair and unchanged
file/edge evidence. Existing legacy timing compatibility tests continue to pass.

Full workspace tests pass (181 Rust tests; one manual latency measurement ignored),
all 27 Python harness tests pass, and strict all-target workspace Clippy, formatting
and diff checks pass. README, agent contracts and roadmap/status are updated.
Schema 7 and analysis semantics 18 are unchanged; no dependency was added.
Detection/query benchmark reports were not rerun for this metadata-only guard.
Identity matching does not authenticate cached evidence or establish source
freshness. Scalable refresh, hard worker containment, independent labels/audits,
competitor measurements and human studies remain outstanding. Hosted CI was not
run, the global executable is unchanged, and no target code, live provider,
publication or deployment was invoked. No user input is needed.

2026-10-24 cached file identity consistency: a regression first reproduced a stored
snapshot returning contradictory file IR as complete when its decoded path differed
from the SQLite row. The shared file loader now checks path, language and content
hash against their row columns before native refresh reuse or snapshot return.
Contradictions fail with a fixed error that omits stored values. The regression
checks each field, retained payload/statistics, released owned read/write
transactions, preserved caller transactions and unchanged graph evidence after
restoring the original cached payload. The existing mixed-source explanation test
now injects a consistent row/payload hash together and still requires source
disagreement diagnostics: internal consistency alone cannot imply freshness.

Full workspace tests pass (182 Rust tests; one manual latency measurement ignored),
all 27 Python harness tests pass, and strict all-target workspace Clippy, formatting
and diff checks pass. README, agent contracts and roadmap/status are updated.
Schema 7 and semantics 18 are unchanged, with no dependency added. Detection/query
reports were not rerun for this cache consistency guard. Contradictory file IR is
not automatically repaired; explicit cache recovery, nested IR validation, payload
budgets, scalable refresh and hard worker containment remain separate work. A
database author changing both representations can bypass this consistency check.
Independent labels/audits, competitor evaluation and human studies remain external
phase gates. Hosted CI was not run, the global executable is unchanged, and no
target code, live provider, publication or deployment was invoked. No user input
is needed for continued bounded implementation.

2026-10-28 explicit atomic cache recovery: `sentinel index <project> --rebuild`
and Engine.rebuild_index now reparse current admitted sources without decoding the
discarded graph cache. The existing immediate writer transaction clears only the
current project's files, symbols, security annotations, symbol edges and index
statistics before replacing them. Findings and scan snapshots, baselines, jobs,
audit revisions/coverage/reviews/artifacts, memory and other project rows remain
retained. Ordinary indexing stays incremental and never requests recovery
implicitly. Rebuild counters start from an empty cache; incomplete source analysis
still commits explicitly partial coverage and returns CLI exit 2 rather than PASS.

The graph regression recovers malformed file/statistics payloads, injects a failure
after cache clearing to verify whole-transaction rollback, compares every retained
table, checks unrelated-project cache rows and verifies the next refresh reuses IR.
The CLI regression verifies explicit opt-in, JSON counters, retained memory and
partial-analysis exit status. Full workspace tests pass (184 Rust tests; one manual
latency measurement ignored), all 27 Python harness tests pass, and strict
all-target workspace Clippy, formatting and diff checks pass. README, agent
contracts and roadmap/status are updated. Schema 7 and semantics 18 are unchanged;
no dependency was added. Detection/query reports were not rerun for this explicit
recovery path. Physical database corruption, malicious triggers, hard worker limits,
scalable refresh and independent phase-exit evidence remain outside this milestone.
Hosted CI was not run, the global executable is unchanged, and no target code,
live provider, publication or deployment was invoked. No user decision is needed.

2026-10-28 stored edge consistency: snapshot reads now compare decoded edge
endpoints, kind, file, line, name and resolved flag against the selected SQLite
row. Previously only the JSON payload was read, permitting contradictory indexed
relationship metadata to be returned without an error. Line conversion is checked;
stored resolved flags must be canonical 0/1 rather than arbitrary nonzero values.
Contradictions fail with a fixed message that omits stored values and preserves
retained rows and caller transaction ownership. Ordinary index refresh rebuilds
edges from cached file IR and repairs these contradictions without requiring a
full reparse; explicit rebuild remains available for unusable file caches.

The regression checks all seven metadata fields, negative stored lines, noncanonical
booleans, redacted errors, unchanged retained bytes, owned/caller transactions,
warm repair and unchanged file evidence. Full workspace tests pass (185 Rust tests;
one manual latency measurement ignored), all 27 Python harness tests pass, and
strict all-target workspace Clippy, formatting and diff checks pass. README, agent
contracts and roadmap/status are updated. Schema 7 and semantics 18 are unchanged;
no dependency was added. Detection/query reports were not rerun for this read-time
consistency guard. These checks do not authenticate graph authorship, establish
semantic reachability or bound cache payload sizes. Scalable refresh, hard worker
containment, independent labels/audits, competitor evaluation and human studies
remain open phase gates. Hosted CI was not run, the global executable is unchanged,
and no target code, live provider, publication or deployment was invoked. No user
input is needed for continued bounded implementation.

2026-10-31 external scanner diagnostic privacy: non-success scanner stderr is no
longer copied into coverage notes, and structured scanner diagnostics or malformed
records are summarized by count rather than echoing untrusted message/severity
fields. Partial valid findings remain available and the scan is still marked
incomplete. Regression fixtures put a private marker in stderr, scanner diagnostics
and an invalid severity and verify none reach normalized output. This protects the
report/history boundary from scanners that echo repository content; it is not a
general source-secret detector or a guarantee that arbitrary finding messages are
redacted.

Validation: full workspace tests pass (187 Rust tests; one manual latency measurement
ignored), strict all-target workspace Clippy and formatting pass, and `git diff --check`
passes. No dependency, schema or analysis-semantics revision changed. The
scanner package test includes controlled subprocess fixtures; no repository target
code, live provider, hosted CI, global binary, publication or deployment was invoked.
Phase exit evidence (independent labels/audits, containment review, competitor
measurements and human studies) remains outstanding.

2026-11-02 shared AI context credential heuristic: retrieved source excerpt lines
whose assignment keys contain password/passwd/secret/token/API-key/access-key,
authorization/bearer, credential, private-key or signing-key markers are replaced
with a fixed marker before building the shared provider messages. Common AWS,
GitHub, Slack bot and Google API token prefixes are also checked when embedded in
otherwise unrelated assignment lines. This applies equally to local and cloud modes and preserves
line numbering, context identity determinism and output bounds. A dummy credential
regression asserts the serialized context lacks the value while ordinary source
and existing filename exclusions remain covered. This is defense in depth, not a
general secret detector: arbitrary literals, novel names/formats, and credentials
embedded in unrelated strings may still pass through. Inspect `--context-only`
before cloud use of sensitive repositories.

Validation: all 8 sentinel-llm tests pass, including dummy variable-name and
provider-prefix cases; the full workspace suite passes (187 tests, one manual
measurement ignored), strict all-target Clippy, formatting, and `git diff --check`.
No provider,
repository target code, hosted CI, global binary, publication or deployment was
invoked. Phase 3 secret coverage and its redaction/accuracy gate are not complete.

2026-11-02 finding-prompt redaction: explanation requests now apply the same
credential-key and selected provider-token heuristic to textual finding fields
before serialization. The sanitized clone is sent; the retained finding stays
unchanged, and a changed fingerprint is recalculated only on that clone. The
prompt reports how many field lines were redacted and states heuristic coverage
is incomplete. A regression covers a key/value title plus private-key evidence,
asserts neither fixture value is sent, and checks the retained finding is intact.
All 9 sentinel-llm tests, package Clippy, formatting and diff checks pass. The
workspace suite passes (188 tests, one manual measurement ignored), as do strict
all-target Clippy, formatting and diff checks. Unknown secret formats remain
possible leaks; Phase 3 is not complete.

2026-11-02 finding path privacy: serialized finding file paths are now mapped to
matching project-relative paths from the immutable context, or replaced with a
fixed omission marker if there is no unique match. This avoids sending absolute
host paths while preserving in-context source references. The finding redaction
regression uses an absolute local path and verifies the prompt retains only
`main.rs`; a second test ensures ambiguous basename matches are omitted rather
than guessed. Stored finding data remains unchanged. All 10 LLM tests pass; the
full workspace suite passes (189 tests, one manual measurement ignored), as do
strict workspace Clippy, formatting and diff checks.

2026-11-02 redaction transparency: context coverage notes now count retained
excerpt lines where the heuristic replaced possible credentials and explicitly
state that detection is incomplete. Counts are derived after context-size trimming,
so removed excerpts are not included. The test checks three different credential
patterns, source-value absence and the coverage note. The LLM package's 8 tests,
strict package Clippy, formatting and diff checks pass; the workspace suite was
not rerun. Secret scanning and comprehensive prompt redaction remain open work.

2026-11-03 initial native secret signatures: added five opt-in-to-no-extra-tools,
offline rules for AWS access-key IDs, GitHub tokens, Google API keys, Slack tokens
and npm tokens in supported source files. The matcher applies a minimum Shannon
entropy check and skips lines containing common example/placeholder markers. It
does not contact providers or determine whether a credential is live. Findings
identify the provider and location but withhold the matched value; a CLI audit test
asserts all five dummy values are absent from serialized output. Rule validation
requires the dedicated regex-only secret mode to prevent silent no-match
configurations. Shared AI-context redaction now also covers Google keys with
hyphens/underscores, Slack tokens containing separators, and npm tokens.

Validation: scanner tests cover five provider-positive and five safe-placeholder
cases, withheld evidence, and invalid rule configuration; CLI integration confirms
all five candidates are detected without echoing values. Current gaps: no Git
history, `.env`/configuration, private-key, generic credential, or custom-provider
scanning; no independently adjudicated difficult-safe corpus; token heuristics may
miss leaks or flag test data. This is an initial slice of Phase 3 only, not a
complete secrets suite or quality-gate result.

The complete workspace suite passes (191 tests, one manual latency measurement
ignored), the Python harness suite passes (27 tests), and strict all-target
workspace Clippy, formatting and `git diff --check` pass. No dependency, schema or
analysis-semantics revision changed. No target code, live provider, hosted CI,
global executable, publication or deployment was invoked.

2026-11-03 initial dependency inventory: `sentinel deps [project]` now reads only
the project's `package-lock.json` and inventories npm package names, versions,
development flags and optional flags for lockfile versions 2 and 3. Input is capped
at 16 MiB, package records at 50,000, and estimated JSON output at 2 MiB. Package
records without valid names/versions, unsupported lock versions and either budget
limit are explicitly partial and return exit 2. Paths resolving outside the project
root are rejected. Output is deterministic and advisory-neutral; the command neither
opens/creates Sentinel's database nor uses the network. Tests cover scoped/nested
packages, determinism, unsupported version, incomplete records, input/output bounds
and CLI behavior.
This closes inventory-only coverage for npm lockfiles but is not SCA: no advisory
database, online refresh, dependency-range evaluation, other ecosystems or SBOM.
Validation for this combined Phase 3 increment: the full workspace suite passes
(195 tests, one manual latency measurement ignored), all 27 Python harness tests
pass, and strict all-target workspace Clippy, formatting and `git diff --check`
pass. No dependency or schema changed. No provider, hosted CI or target application
code was invoked.

2026-11-04 secret-signature benchmark slice: added a separate author-labelled
10-case corpus with five synthetic provider-token positives and five matching
placeholder examples. The bounded harness ran all cases against the built Windows
debug binary: 5 TP, 5 TN, 0 FP/FN and 0 failed. Precision and recall are both 1.0
on this tiny mapped scope, with Wilson lower bounds of 0.566; this is a
regression signal, not independent accuracy evidence. The report records binary
and corpus hashes and contains no candidate token values. Benchmark instructions
document the limitation. No held-out labels or external reviewers were used.
