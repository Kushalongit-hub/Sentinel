# Sentinel competitive implementation plan

See the [competitive gap backlog](competitive-gap-backlog.md) for concrete
deliverables and acceptance evidence against the current Nox/Joern comparison.

Status: implementation started. The Phase 0 CLI benchmark harness and 14-case
development seed, plus initial Phase 1 evidence and audit persistence, are implemented.
Release gates and remaining work are tracked in [implementation status](implementation-status.md).
See [benchmark instructions](../benchmarks/README.md). No competitive win is measured.

## Objective and definition of success

Make Sentinel the strongest option for a developer who needs to discover a
security issue, investigate its code path, produce a defensible assessment, fix
it, and verify the change. Compete on measured outcomes against pinned Nox and
joern-mcp/Joern configurations. A broad superiority claim requires evidence in
all declared dimensions; winning one workflow does not establish universal superiority.

The competitors' capabilities described in the October 2026 comparison are
documented claims, not our measurements. Freeze their versions, configurations,
plugins, language frontends, and model settings before each evaluation. Compare
joern-mcp together with its Joern backend and report wrapper/backend costs separately.

| Dimension | Proposed release gate | How to measure |
|---|---|---|
| Detection quality | At least 90% precision and 80% recall in each release-critical supported class; beat the stronger comparator by at least 5 percentage points of recall at matched precision on the common scope | Held-out labelled cases; publish confidence intervals and failures. Targets may need revision after the baseline, never retroactive redefinition to declare victory. |
| Coverage breadth | Explicit support for application injection, secrets, dependencies, infrastructure configuration, and AI/agent risks | Versioned capability matrix; distinguish native checks, optional adapters, agent investigations, and unsupported cases |
| Investigation | Equal or better correctness on source/sink, caller/callee, import, guard and sanitizer questions | Ground-truth graph queries; include opaque calls and unsupported semantics |
| Patch verification | No false PASS in release-critical fixtures with introduced high-impact regressions or incomplete required analysis | Before/after fixtures; test stale evidence, partial adapters and changed dependencies |
| Responsiveness | Proposed p95 below 1 second for one-file refresh and focused context on a 10,000-file target; responsive cancellation | Fixed hardware and corpus; publish cold/warm results, memory and failures. Full-project hashing cannot remain on every focused query. |
| Audit efficiency | Reduce median time to a reviewer-accepted finding and verified patch by 25% versus the stronger baseline workflow | Counterbalanced user tasks; same reviewer rubric and model/cost budget |
| Operational trust | No unrequested cloud calls or target execution; bounded tools and artifact handling | Network/process tests, hostile repositories, independently reviewed execution isolation |

Do not combine these gates into a flattering single score. Publish separate
common-scope accuracy, breadth, graph correctness, workflow time, cost and resource
results. Any gap keeps the related claim provisional.

## Current foundation

Sentinel has 22 embedded rules, bounded Tree-sitter flow interpretation, a
persistent SQLite security graph, ranked context, baseline/diff verification,
CLI/TUI/MCP access, and Ollama/NVIDIA NIM/both explanations. The pinned Cloudflare
workflow adds source snapshots, coverage records, schema validation and imported
review attestations. An external agent still performs the audit.

Current gaps include unbenchmarked accuracy, limited framework and language
semantics, no native audit scheduler, no general secrets/SCA/IaC suites, and no
target execution sandbox. Imported reviewer identities and reproduction records
are attestations, not authenticated proof. Schema v5 now retains normalized,
transactional audit import revisions while preserving legacy memory records.
Artifact descriptors, resumable native jobs and scalable refresh remain outstanding.

## Phase 0 — Establish the scoreboard

Deliver a reproducible benchmark harness before adding more detectors.

- Start with at least 300 labelled cases: 200 vulnerable and 100 safe cases across
  JS/TS, Python and Rust. Expand the safe set before treating precision as representative.
- Include realistic multi-file code, framework routing, sanitizers, guards,
  dynamic calls, secrets, configurations, AI tool permissions, and patched pairs.
- Keep at least 30% held out. Split by vulnerability/project family to prevent
  variants of training fixtures leaking into evaluation.
- Freeze truth labels through reviewer adjudication. Record uncertain cases
  separately; do not silently score them as safe.
- Run each tool on the same source snapshot. Include Nox core and separately
  declared plugin configurations; do not compare a disabled competitor to a fully
  enabled Sentinel. Publish unsupported cases and tool failures.
- Compare deterministic engines separately from AI-assisted end-to-end workflows.
  Measure model tokens, requests, monetary cost and time under identical budgets.
- Record precision, recall, per-class confusion matrices, graph-query correctness,
  cold/warm latency, peak memory, stale evidence and analysis completeness.
- Use confidence intervals and enough runs to distinguish noise from improvement.

Exit: the baseline is reproducible, failures are visible, and all later work can
be prioritized by measured gaps. No automatic fixture refresh changes held-out truth.

## Phase 1 — Build durable evidence and scalable refresh

Extend the current engine before relying on it for autonomous investigations.

- Introduce typed evidence contracts: source snapshot, location, detector version,
  analysis assumptions, trace, confidence basis, provenance and coverage limitations.
- Keep candidate assessment (`confirmed`, `needs_validation`, `rejected`) separate
  from occurrence lifecycle (`new`, `unchanged`, `resolved`, `regressed`).
- Add versioned SQLite tables for audit runs, coverage units, attempts, candidates,
  reviews and artifact descriptors. Migrate current memory records without changing
  their historical meaning. Validate before transactional import.
- Maintain reverse dependencies and affected-symbol sets. Use a file watcher for
  incremental hints, with explicit reconciliation and full refresh for trusted
  verification boundaries. A watcher event is not proof that all changes were seen.
- Persist changed-source invalidation, resumable jobs, budgets and immutable
  evidence snapshots. Stale evidence must be prominently labelled everywhere.
- Add named, bounded security queries. Do not expose SQL, shell or arbitrary
  executable graph queries through MCP.

Exit: migrations preserve existing history; crash/restart resumes safely; graph
answers are correct on the query corpus; larger repositories do not silently exceed scope.

## Phase 2 — Close analysis gaps and evaluate a deeper backend

- Improve import/alias resolution, typed call resolution where available, object
  properties, async flows, exceptions and framework entry points.
- Start with Express/Fastify and Flask/FastAPI adapters. Add other frameworks only
  with reviewed source/sink/sanitizer contracts and positive/negative fixtures.
- Treat authorization guards as candidate evidence until dominance and relevant
  resource ownership are established. Decorators alone do not establish protection.
- Add category-specific sanitization and parameterization modelling; do not let
  an HTML sanitizer remove SQL taint or an opaque helper imply safety.
- Implement a backend interface with shared source identity and trace contracts.
  Evaluate Joern as an optional deeper-analysis backend before rebuilding its
  capabilities in Rust. Measure its actual accuracy/resource benefit on failures.
- If Joern earns inclusion, expose fixed query templates inside an isolated worker.
  Arbitrary Scala/CPGQL execution must not become a repository-bound MCP tool.
- Retain the native fast path. Choose backends explicitly and disclose failures,
  unsupported semantics, versions and disagreement; never silently substitute one.

Exit: held-out graph/flow results improve without dropping precision. A Joern
adapter ships only if it provides measurable value and has a reviewed isolation contract.

## Phase 3 — Add competitive security breadth

| Suite | First implementation | Quality gate |
|---|---|---|
| Secrets | Provider-specific signatures, context/entropy checks, redacted evidence; optional local history scan | Realistic dummy tokens and difficult safe examples; no live credential verification by default |
| Dependencies | Lockfile inventory, local advisory cache, explicit online refresh, version-range evaluation, SBOM export | Ecosystem/version fixtures, database timestamp and unavailable-advisory coverage warnings |
| Infrastructure | GitHub Actions, Dockerfile, Terraform and Kubernetes policies | Distinguish exploitable conditions from hardening notes; inspect surrounding configuration |
| AI applications | Untrusted prompt composition, unsafe output sinks, RAG tenant boundaries, sensitive embeddings and unrestricted tools | Trace a concrete affected principal/resource; avoid calling every LLM invocation vulnerable |
| Agent configuration | Tool grants, hooks, MCP declarations, command interpolation and secret exposure | Configuration-aware analysis with source evidence; no execution of inspected hooks |

Use optional adapters where that closes a gap faster than native implementation.
Normalize outputs into Sentinel evidence while preserving upstream rule IDs,
versions, original severities, source scope and partial failures. Deduplication must
retain corroborating evidence; do not average unrelated confidence values.

Exit: breadth targets are present, each suite meets its accuracy gate, and users
can distinguish native capabilities from adapters. Rule count is not a quality metric.

## Phase 4 — Run the audit workflow inside Sentinel

Introduce a `sentinel-audit` orchestrator and provider-neutral model interface.
Reuse the existing Ollama/NIM/both transport rather than creating a separate cloud path.

Pipeline: reconnaissance → coverage planning → bounded investigation → candidate
validation → independent record review → reporting. Map these phases to the
pinned Cloudflare contracts and retain upgrade provenance.

- Local, NIM and both remain explicit modes with no automatic fallback.
- In both mode, models receive the same immutable evidence/context snapshot.
  Keep their outputs, costs and failures separate. A provider failure does not
  invent an answer or silently cancel a successful peer response.
- Discovery and verification use fresh sessions. Verification starts from the
  source evidence and claim, avoids the discoverer's persuasive narrative, and
  explicitly attempts to disprove it. Same-model review is allowed but labelled;
  different models are not automatically independent or accurate.
- Give workers bounded read-only Sentinel tools. Source text, comments, skills,
  findings and model output are untrusted data, not tool authorization.
- Enforce tool allowlists, repository scope, output limits, structured model
  responses, cancellation, token/request/time budgets and verification reserves.
- Stop honestly on exhausted budgets or missing evidence. Maintain pending
  candidates and deferred units rather than manufacturing complete coverage.
- No candidate becomes confirmed merely because models agree. Record source-only
  review, producer attestation and observed isolated reproduction as distinct evidence levels.
- Cloud runs show the context and configured destination; credentials stay outside
  prompts. Redact secrets without claiming that redaction guarantees no sensitive
  code/context remains.

Exit: hostile prompt fixtures cannot expand tool permissions; interrupted runs
resume; provider modes stay isolated; inaccurate model records fail validation;
workflow utility improves under equal budgets on held-out tasks.

## Phase 5 — Establish observed verification and a patch loop

Execution is an optional separate capability and stays disabled until containment
is independently reviewed. A timeout or ordinary subprocess is not a sandbox.

- Define an OS-enforced worker with no external network, allowlisted environment,
  read-only source/toolchain, scratch-only writes, bounded CPU/memory/processes,
  disk/file sizes and wall time. Do not fetch dependencies during reproduction.
- Begin with one supported Linux containment implementation. On Windows use an
  explicitly configured isolation backend only when it enforces the same controls;
  never fall back to execution on the host.
- Bind artifacts to the source snapshot, worker identity, commands, dummy inputs,
  toolchain versions, measured limits and observed outcome. Promotion must use
  race-safe no-follow operations and per-file/cumulative limits.
- Require external authorization for consequential/live testing. The audit skill
  or a repository file cannot grant it. Keep production probing outside this workflow.
- Generate proposed patches in isolated worktrees. Run deterministic comparisons
  and approved isolated regression tests before recommending a change.
- Distinguish static disappearance of a finding from demonstrated elimination of
  the failure. Missing coverage cannot produce a trusted PASS.
- Add fix/reintroduction tests for source changes, dependencies, policies and
  framework paths. Preserve existing debt instead of hiding it through baseline edits.

Exit: independent containment review passes; hostile artifact/process tests pass;
reproductions are repeatable; protected patch fixtures never receive false PASS.

## Phase 6 — Make the evidence useful in the TUI, editor and CI

- Add an Audit workspace with phase progress, budgets, model contributions,
  coverage gaps, pending candidates, verification level and stale evidence.
- Add navigable source-to-sink traces, relevant guards/sanitizers, changed-path
  impact and before/after patch evidence. Avoid presenting raw JSON as the main UX.
- Add an LSP using the shared engine, with debounce, cancellation and explicit
  diagnostics for unsupported/partial analysis. Start with one maintained editor client.
- Export SARIF, Markdown, HTML and SBOM where relevant, keeping evidence provenance
  and source identities intact. Add reviewed CI templates and configurable policy gates.
- Provide project policies, exclusions and justified suppressions with history and
  optional expiry. A suppression cannot erase audit evidence or change source freshness.

Exit: users finish investigation/patch tasks faster in a counterbalanced study;
the UI remains responsive and makes uncertainty visible; CI results are reproducible.

## Phase 7 — Demonstrate superiority and release responsibly

- Run the frozen benchmark against current pinned comparators and retain artifacts.
- Commission independent audits of both Sentinel and representative target projects.
- Test Windows, Linux and macOS packaging, migrations, cancellation, crashes,
  offline behaviour, provider failures and release upgrades.
- Sign release artifacts, publish checksums and a dependency inventory, and verify
  update provenance. Add reproducible build evidence where feasible.
- Publish supported languages/frameworks, known limitations, failure cases,
  benchmark configuration, cost and resource consumption.
- Claim a win only for dimensions whose gates were met. Do not infer production
  reliability from test count or translate a feature lead into an accuracy claim.

## Implementation order and scope control

Critical path: Phase 0 → Phase 1 → measured Phase 2/3 gaps → Phase 4 → Phase 5 →
Phase 6 → Phase 7. Do not estimate a delivery date until Phase 0 establishes the
actual workload and the team/runtime budget is agreed.

The first implementation milestone is a benchmark harness, a typed evidence
contract and a native bounded audit run with honest unresolved states. It does
not include a plugin marketplace, unrestricted autonomous execution or every
language frontend. Those would dilute the work needed to establish accuracy.

Track each deliverable as a reviewable change with fixtures, resource bounds,
compatibility notes and an exit-gate result. Reprioritize based on failures rather
than adding impressive-sounding features. Optional Nox/Joern adapters can accelerate
the product; any benefit inherited from them must be attributed in results.
