# Static-analysis benchmark foundation

Run from the repository root with Python 3.10+ and a built Sentinel binary:

```powershell
cargo build --locked --release --bin sentinel
python scripts/benchmark.py --binary target/release/sentinel.exe --output baseline.json
python -m unittest discover -s scripts -p "test_benchmark.py"
```

On Linux/macOS use `target/release/sentinel`. No Python dependencies are required.
The harness copies source into disposable directories and invokes only Sentinel's
native static audit. It never runs fixture source, external scanners or AI providers.
Each scan has a configurable timeout; existing output files are never overwritten.

The seed corpus contains **14 author-labelled development cases**, paired
across JavaScript, TypeScript, Python and Rust. These are small regression seeds,
not independently adjudicated vulnerabilities or a representative accuracy study.
The full Phase 0 corpus, realistic multi-file projects, independent labels and
family-disjoint holdout set remain outstanding. No competitor has been measured.

Scoring is case-level: a case is detected when a finding's title matches one of
its declared rule IDs. Safe examples exercise those same IDs. Additional findings
are retained and counted as unscored, so these precision/recall values describe
only the labelled rule scope, not the whole scanner. Failed, timed-out, malformed,
incomplete or incompletely scanned cases are reported separately and cause exit 2;
they never count as true negatives. Accuracy misses remain in the report and do
not fail execution. Exit 0 means the measurement completed, not that quality passed.

Reports include per-class confusion matrices, precision/recall with Wilson 95%
intervals, coverage notes, elapsed wall time per case, corpus/binary hashes and
source hashes. `per_split` keeps development and holdout scores separate even
with `--split all`; the combined summary is not a held-out accuracy estimate.
Precision and recall use completed cases only. `failed_positive` and
`failed_negative` retain the truth-label breakdown of unavailable results.
`completion_rate` divides completed cases by all selected cases;
`positive_detection_rate` divides mapped true positives by all positive labels,
including failed positive cases. The latter is an observed detection/availability
rate, not a reclassification of failures as false negatives or a claim about what
those failed scans would have detected. These additional fields also appear in
per-class, per-engine and per-split summaries. Old reports remain unchanged. Timing includes process startup and database writes; it is a single
cold scan measurement, not a warm latency percentile or memory benchmark. Retain
hardware/OS, build command and tool configuration alongside reports.

The checked-in `seed-baseline.json` was measured on Windows with the locked,
offline release build on 2026-10-07: seven true positives, seven true negatives,
zero mapped false positives/negatives and zero failed scans. The 95% interval for
both precision and recall is approximately 0.646–1.000; the perfect seed score
is not evidence of perfect general detection. This is development data only.

`secrets.json` adds five provider-token positive/placeholder pairs for the initial
AWS, GitHub, Google, Slack and npm signature rules. Its synthetic values are test
fixtures only; placeholder handling is authored by the implementation team. This
10-case corpus is a regression check, not a representative or independently
adjudicated secret-detection benchmark. Generate a local report with:

```powershell
python scripts/benchmark.py --binary target/release/sentinel.exe --corpus benchmarks/secrets.json --output secrets-results.json
```

The checked-in `secrets-results-2026-11-04.json` records a Windows debug-build
run: five mapped positives and five mapped safe examples, with no failures. The
small sample yields a 0.566 lower Wilson bound for precision and recall; it does
not establish broad secret-detection quality. Use the recorded binary and corpus
hashes to distinguish this run from future builds or fixture edits.

`--split holdout` refuses an empty split. Families cannot span development and
holdout, and IDs must be unique. Published development cases cannot later become
blind holdout cases. Add independently reviewed families before release evaluation.

## Graph and request-source measurements

`flows.json` adds eight multi-file development cases for SQL injection, XSS, command injection and path traversal. `framework-sources.json` adds four conventional request-shape cases. There are now 26 development cases in total; none is a blind holdout.

```powershell
python scripts/benchmark.py --binary target/release/sentinel.exe --corpus benchmarks/flows.json --output flows.json
python scripts/benchmark.py --binary target/release/sentinel.exe --corpus benchmarks/framework-sources.json --output framework-results.json
```

Graph cases use `sentinel scan-file ENTRYPOINT --project ROOT`. Rule evaluation targets one file while graph tracing uses the indexed repository. Incomplete traces fail measurement. Reports split scores by engine as well as class.

`flows-baseline.json` measured four true positives and four true negatives. The request-source before report had two false negatives; the after report detects both with two true negatives. These reports use Windows debug binaries on 2026-10-07; do not compare their timing to the release seed report. Request body/query-parameter names are syntactic source recognition, not verified framework API identity or complete framework support.

Fixture validation enforces case/file/byte budgets, case-insensitive path uniqueness, Windows device-name restrictions and scanner-state separation. Complete reports require successful scan exits, typed findings/counts/notes, completed scanner records and (for graph cases) a complete trace. Contradictory or malformed results fail measurement rather than enter the confusion matrix.

## Header and cookie request shapes

`request-metadata.json` adds eight author-labelled graph development cases. Run it
with the same harness and `--corpus benchmarks/request-metadata.json`. The retained
`request-metadata-before.json` / `request-metadata-after.json` release reports show
four misses fixed and four safe query-parameter counterparts preserved. All four
corpora now contain 34 cases, including 20 graph cases; these are development
regressions, not an independent scoreboard. See [source contracts](../docs/framework-source-contracts.md).

## Phase 2 native semantics

`phase2-native.json` adds 14 graph development cases across seven paired families:
Flask/FastAPI strings, namespace async returns, mixed import aliases, lexical
scope, literal fields and branch reassignment. Five corpora now contain 48 cases
(34 graph cases). Installed-baseline and after reports preserve binary/corpus
hashes; the new corpus improves from 5 TP/2 FN/5 TN/2 FP to 7 TP/7 TN. All older
34 cases also pass on the final offline release. These are development labels.

```powershell
python scripts/benchmark.py --binary target/release/sentinel.exe --corpus benchmarks/phase2-native.json --output phase2-results.json
```

CI executes this corpus; Rust regressions guard semantic expectations. Harness
exit zero only means measurement completed, not that accuracy met a release gate.
See [backend feasibility and outstanding evidence](../docs/phase2-backend-evaluation.md).

## Express/Fastify ESM route contracts

`js-routes.json` adds eight graph development cases for inline Express routes,
named Fastify routes, Express Router aliases and cross-file helpers. Before/after
reports show four missed unsafe flows now detected with four safe parameterized
queries preserved. Six corpora total 56 cases (42 graph), all passing the declared
mapped scope on the revision-10 release. Labels are author-generated, not held out.
Run with `--corpus benchmarks/js-routes.json`. Imported handlers/plugins and
middleware lifecycle need further semantics; incomplete cases are not true negatives.

## CommonJS and bounded local plugins

`js-plugins.json` adds twelve graph development cases for literal CommonJS
factories, Express Router handler aliases and inline/named/nested Fastify plugins.
Before/after reports retain corpus and binary hashes. The revision-10 baseline
has 0 TP, 5 FN, 5 TN and two incomplete cases; incomplete cases are unscored,
not counted as misses or safe results. The revision-11 release has 6 TP/6 TN with
no mapped FP/FN or incomplete cases. Seven corpora total 68 cases (54 graph).
Labels are author-generated development evidence, not held-out or independent.
CI measures this corpus; runtime mount reachability, hooks and authorization
ordering are outside the supported contract. See the framework contract document.

## Development regression gate

CI passes `--fail-on-regression` for all seven development corpora. This option
returns 1 for any mapped false positive or false negative, and 2 for incomplete
or failed cases (which remain unscored). The report is written before either
failure exit so investigation retains evidence. Without this option, exit zero
continues to mean measurement completed; historical baseline measurements can
record misses without treating measurement as a harness failure. This gate checks
known development expectations, not independent accuracy or release readiness.

## Scanner identity during measurement

The harness hashes the scanner binary before running cases and again afterward.
Reports retain `binary_sha256` (initial), `binary_sha256_after`,
`measurement_valid` and `measurement_errors`. Replacement or disappearance makes
the measurement invalid and exits 2 after saving the report, even when all case
results look complete. Case failures also invalidate the measurement. A valid
measurement can still contain false positives/negatives; use the regression gate
for that policy. Matching endpoint hashes are a consistency check, not proof
against replacement and restoration between checks or changes to shared libraries,
environment or toolchain. Keep the benchmark binary fixed for the entire run.


## Cold, warm and one-file refresh measurement

Use the dependency-free refresh harness to measure a selected native Sentinel
binary against generated independent Python modules. It runs only `sentinel index`;
fixture code is never executed. Source content and update sequence are deterministic.

```powershell
python scripts/benchmark_refresh.py --binary target/debug/sentinel.exe --files 1000 --repeats 5 --output refresh-1000.json
python scripts/benchmark_refresh.py --binary target/debug/sentinel.exe --files 10000 --repeats 5 --output refresh-10000.json
python -m unittest discover -s scripts -p "test_benchmark*.py"
```

A new temporary repository measures one cold/fresh-database index, repeated warm
unchanged indexes, then one-file edits. Cold does not imply empty OS caches. Wall
time includes process startup and SQLite work; nearest-rank p50/p95 summarize
complete samples only. Each summary retains total/complete counts. Partial indexes,
timeouts, contradictory counters and failures remain in the report, invalidate the
measurement and exit 2. No partial sample establishes supported-scope latency.
Files must be 1..10000, repeats 1..30, and each command timeout is at most 600s.
Output is never overwritten; binary identity is checked before/after and the
initial generated-source manifest is hashed. Endpoint binary checks do not detect
replacement/restoration between checks. Capture actual hardware and build profile
alongside reports; platform/Python version are included. This synthetic workload
has no imports, routes, secrets, dependency graphs or target execution. It measures
neither memory nor cancellation, and does not establish representative latency,
statistical confidence, competitive superiority or the roadmap's 10000-file gate.

Local debug-build reports `refresh-local-2026-10-12-1000.json` and
`refresh-local-2026-10-12-10000.json` retain the first run, including the existing
native file-cap limitation. These are development measurements, not release gates.


`refresh-local-2026-10-12-1000-cleanup-indexes.json` retains the follow-up debug
measurement after additive cleanup indexes and avoiding deletion for new files.
Its three-sample warm/changed timings do not establish an improvement over the
first run; cold time was also higher in this single observation. Query-plan tests
verify the new file indexes are selected, but end-to-end latency still needs
profiling and repeated controlled measurement. The 2000-file admission cap remains.


New index results also retain optional `timings` for source refresh, relationship
analysis and graph persistence. These millisecond stage measurements help locate
costs instead of inferring the bottleneck from end-to-end latency. Source refresh
includes locking/loading/enumeration/reads/parsing; relationship analysis includes
resolution/tracing/counts; persistence excludes the final metadata write/commit.
Stored `duration_ms` now includes graph writes, while older versions measured it
before persistence, so historical internal durations are not directly comparable.
The harness wall-time definition is unchanged. Missing legacy stage timings are
unknown/null, not zero. `refresh-local-2026-10-12-1000-stage-timings.json` retains
the first instrumented debug run; it still does not establish representative,
release-build or 10000-file performance.


`refresh-local-2026-10-12-1000-read-extract-timings.json` refines the first source
stage diagnosis: checked-path/open/read time was 13922ms versus 159ms AST/security
extraction in that cold debug sample. This points to filesystem work in this local
run, not parser construction as the dominant cost. These counters accumulate
per-file durations before millisecond conversion; zero can also mean sub-millisecond
work. Warm source refresh still includes full reconciliation, with no incremental
scope or resource guarantee established. The measured configuration still has the
2000-file cap, and these synthetic observations do not transfer to other workloads.


`refresh-local-2026-10-12-1000-batched-reads.json` measures bounded four-file read
batches. The cold CLI sample was 4.12s versus 18.72s in the previous instrumented
run; warm/changed p95 were 216.43/221.65ms across three samples. This is an observed
local reduction in a single cold sample, not a controlled statistical speedup or
release gate. Warm observations did not improve over the immediately preceding
run. Source-read timing now measures batch wall time including worker launch/join,
not the sum of concurrent worker durations. Scope, counts and binary checks passed;
no file-cap, peak-memory, cancellation or 10000-file guarantee is implied.


`refresh-local-2026-10-12-1000-prepared-edges.json` retains statement-reuse
measurement. Warm graph persistence observed 32..40ms versus 47..48ms in the
preceding report; wall p95 was 211.33ms warm and 223.56ms changed across three
samples. The cold wall sample was higher at 7.02s. These stage observations do not
establish a controlled end-to-end improvement or representative speedup. Binary,
scope and refresh counter checks passed; earlier reports remain unchanged.


For repeated fresh-database observations, pass `--cold-repeats` (1..10, default
1). Each cold sample creates a distinct source root/database with identical
initial source content. Warm and edit samples use the final cold root. All roots
remain inside one owned temporary directory and are removed after measurement.
OS caches are not flushed; this improves repeat accounting without making cold
samples independent hardware trials or yielding confidence from small counts.

```powershell
python scripts/benchmark_refresh.py --binary target/debug/sentinel.exe --files 1000 --cold-repeats 3 --repeats 3 --output refresh-repeated-cold.json
```

`refresh-local-2026-10-12-1000-repeated-cold.json` records three complete cold
samples with p50/p95 2.67/4.58s, warm p95 205.72ms and one-file-change p95 239.38ms.
The spread illustrates why one cold sample cannot justify an overall speed claim.
These remain descriptive synthetic debug measurements; the file cap and broader
resource/latency gates are unchanged. Old reports remain unchanged; new reports
record `cold_repeats` explicitly alongside actual per-stage sample counts.

Pass `--context` to also measure `sentinel context helper_0 --max-items 40` after
warm indexing and after separate one-file edits. These are end-to-end context
requests, including Sentinel startup, full graph reconciliation and optional Git
metadata reads. The edited-context samples do not pre-index their source changes.
The harness requires the expected fixture target, bounded arrays, native backend,
source identity, omission counters and consistent exit/completeness before a sample
can enter latency percentiles. Partial context invalidates overall measurement
and contributes no complete-scope percentile. This is retrieval/latency checking,
not independently labelled semantic graph-query scoring or AI benchmarking.

```powershell
python scripts/benchmark_refresh.py --binary target/debug/sentinel.exe --files 1000 --repeats 3 --context --output refresh-context.json
```

`refresh-local-2026-10-13-1000-context.json` records three complete warm-context
and three edited-context samples with descriptive p95 239.47ms and 256.67ms.
Warm context retained one source identity; every edit produced a different one.
`refresh-local-2026-10-13-10000-context.json` preserves the requested 10000-file
run: all refresh/context stages were partial under the existing 2000-file cap,
so complete-scope percentiles are null and measurement_valid is false. The report
retains partial durations and notes for diagnosis; subsecond partial retrieval
cannot meet the 10000-file release gate. These synthetic debug observations do
not establish representative release performance, resource/cancellation bounds,
independent correctness or a comparative win. Previous reports remain unchanged.

Complete focused-context measurements now compare the returned source identity
against the independently constructed manifest of every generated fixture file,
including all current edits. Each context sample records expected_source_snapshot;
a stale or incomplete manifest reported as complete fails the sample and excludes
its latency. Partial responses retain their indexed-subset identity and remain
partial, rather than being required to match the full fixture. This validates
this synthetic native source contract, not general semantic query correctness.

Fixture writes now explicitly use LF on every platform and reports record
fixture_newlines. Earlier Windows fixture writes translated LF to CRLF, so their
actual indexed bytes differed from the logical generated-text hashes. The first
identity-validation run, `refresh-local-2026-10-13-1000-context-identity.json`,
retains that harness expectation failure and null context percentiles. It is not
a Sentinel stale-source defect. The corrected explicit-LF run is retained in
`refresh-local-2026-10-13-1000-context-identity-lf.json`: all six context snapshots
matched the exact full fixture, with three-sample warm/edited p95 281.75/295.42ms.
Changing newline generation changes fixture bytes; these observations should not
be used as a controlled speed comparison with earlier platform-native fixtures.
The earlier reports remain unchanged. The 2000-file cap, 10000-file gate and
independent review/resource/containment requirements remain open.

## Fixed graph-query development scoring

The separate query runner scores exact multisets of returned `[file, symbol name]`
rows and `[call name, resolved flag]` edges for the fixed `symbols`, `callers` and
`callees` commands. Duplicate edges remain significant.
Optional directed endpoint scoring is described below. Neither projection scores
types, data-flow paths, guards, sanitizers or AI answers. Query expectations use a
separate schema/metric from vulnerable/safe detection
labels, so query cases do not inflate the 68 detection-case count.

```powershell
python scripts/benchmark_queries.py --binary target/debug/sentinel.exe --corpus benchmarks/query-seed.json --output query-results.json --fail-on-regression
```

See query-seed.json for the schema. Each case declares id, family, class, split,
command, target, files and expected symbol/edge lists. Only fixed commands are
allowed. The shared fixture validator rejects traversal, state overlap, portable
path collisions and source-budget overflow. LF writes and compact-JSON hashes
bind complete responses to every declared source file. Fixtures must fit native
indexed scope; ignored or unsupported surfaces cannot silently count as full
query coverage. No fixture code, arbitrary query, provider or external scanner runs.

A complete response must have exit 0, matching source identity, native backend,
valid bounded arrays and zero omissions. Partial exit-2 responses remain explicitly
partial; malformed, stale, truncated, contradictory or timed-out cases fail.
Reports retain full query JSON, expectations, actual scored projection, source,
corpus and binary hashes, errors and wall time. Accuracy among complete responses
and correct responses among all attempted cases have separate Wilson intervals
and per-class/split summaries. Exit 2 takes precedence for failure/partial/binary
drift; --fail-on-regression adds exit 1 for incorrect complete answers. Outputs
are new files and cannot overwrite retained evidence. label_status is a supplied
corpus description, not authenticated reviewer evidence.

The four author-labelled seed queries cover cross-file incoming/outgoing calls,
an unresolved opaque callee and an empty symbol search. All four passed locally
in query-local-2026-10-13.json, but they belong to one development family and their
95% accuracy interval is approximately 0.51..1.00. This is runner/regression
coverage, not independent correctness, a representative graph corpus, held-out
proof or a competitive win. CI now configures these query checks and all benchmark
unit tests; the updated hosted CI has not been run or published by this milestone.

Query cases can additionally label expected.endpoint_edges with exact multisets
of `[owner [file,name], callee [file,name] or null, call name, resolved]` records.
For example, a resolved call from routes.py:first to service.py:helper is:

```json
[["routes.py", "first"], ["service.py", "helper"], "helper", true]
```

Only labelled cases score endpoints; the earlier query-seed.json and its retained
reports remain unchanged. Endpoint call-name/resolution labels must agree with
expected.edges. The runner binds each returned from/to ID to target/neighbor
symbols and rejects inconsistent identity mappings or missing resolved endpoints.
Unresolved destinations can remain null; they never fabricate a callee symbol.
Reversing a call changes correctness even when call names and neighboring symbols
remain identical. File/name labels still cannot distinguish same-named methods
within one file or prove types, control flow, authorization or runtime dispatch.

query-endpoints.json extends the same four author-labelled development questions,
not four additional independently sampled cases. All four directed projections
passed in query-local-2026-10-13-endpoints.json; the original projection also passed
again in query-local-2026-10-13-legacy-projection.json. These small correlated
observations remain regression checks, with no stronger confidence or competitive
claim. The endpoint CI step is configured locally; hosted execution is unverified.

Cases may set `symbol_names` to `qualified` to compare `[file, qualified_name]`
for both symbol rows and directed endpoints. The default remains `name`, preserving
the original seed/projection. The selected mode is retained on each case result.
Call-name labels still describe the literal call name, such as self.helper.
Qualified mode requires qualified_name in returned symbols and fails missing
fields instead of falling back to short names. This distinguishes First.helper
from Second.helper in the same file; it does not prove inherited dispatch,
receiver types, overload selection or runtime identity.

query-qualified.json adds two author-labelled questions from one lexical-method
family. Two classes define the same helper/run short names; each run must call its
own lexical helper. Both qualified projections passed locally in
query-local-2026-10-15-qualified.json; the original four endpoint questions also
passed with the updated runner in query-local-2026-10-15-endpoint-compatibility.json.
There are six distinct development questions across two families, not ten:
query-seed.json and query-endpoints.json are alternate projections of the same
four questions. All remain separate from the 68 detection cases and require
independent review. The qualified family alone has a broad 95% accuracy interval
of approximately 0.34..1.00; two passes cannot establish representative accuracy.
CI is configured to retain this regression check when the changes are published;
no hosted run or publication was performed here.

The fixed query runner also accepts `command: trace` cases with
`expected: {"paths": [...]}`. Each path label is
`[sink category, [source file, line, qualified symbol], [sink file, line, qualified symbol]]`.
For example:

```json
["sql-injection", ["routes.py", 3, "handler"], ["repository.py", 2, "insert_user"]]
```

Endpoint-only trace questions score exact directed endpoint multisets, including
line numbers and category, or an explicitly empty path list for a safe counterpart.
Ordered-step scoring is optional as described below. Neither mode scores confidence,
sanitizer validity, guard dominance or runtime exploitability. Qualified endpoint
symbols are required. The runner fixes
and records traversal budgets at depth 8, paths 200 and visited nodes 10000.
Partial/budget-exhausted responses cannot receive accuracy credit, and complete
responses still require the exact full fixture source identity and native backend.
No fixture executes. The original call/symbol projections remain compatible.

```powershell
python scripts/benchmark_queries.py --binary target/debug/sentinel.exe --corpus benchmarks/query-traces.json --output trace-queries.json --fail-on-regression
```

query-traces.json adds an author-labelled three-file request-to-SQL question and
its parameterized counterpart from one related development family. Both passed
locally in query-local-2026-10-16-traces.json. The earlier qualified cases also
passed in query-local-2026-10-16-qualified-compatibility.json. There are now eight
query questions across three development families; the trace pair is related to
existing detection fixtures and is not independent of that work. Alternate call
projections are not extra cases, and these query totals do not enlarge the 68
vulnerable/safe detection cases or satisfy held-out/reviewer gates. CI is configured
for this trace pair locally; no hosted run, release or publication was performed.

Trace cases may additionally set `trace_steps: true`. Each expected path then
adds a fourth field: the ordered list of `[file, line, qualified symbol]` steps.
The first/last step must match source/sink endpoints. Step lists are required,
nonempty and capped at 1000 entries per path for this scoring contract. Missing,
malformed or boundary-inconsistent output fails measurement. Reordered or omitted
intermediate steps with valid boundaries produce an incorrect complete answer.
Ordering and duplicate steps are retained; only the outer path collection is
compared as a multiset. Operation text, columns, confidence, guard dominance and
runtime validity remain unscored.

query-trace-steps.json extends the same two trace questions without altering the
endpoint-only corpus or increasing the eight-question total. Its vulnerable case
requires handler source, create_user entry, insert_user entry and SQL sink in that
order. Native call steps use callee definition lines, not caller call-site lines;
the source and final sink use their actual expression lines. This is an explicit
native representation contract and still needs independent semantic review.
Both ordered projections passed in query-local-2026-10-16-trace-steps.json, and
endpoint-only compatibility passed in
query-local-2026-10-16-trace-endpoint-compatibility.json. CI includes both modes
locally; no hosted result is claimed. These correlated authored checks remain
separate from release proof and the independently adjudicated corpus requirement.

query-import-scope.json records two Python named-import questions: a module-level
helper colliding with a class method, and a class method with no matching module
export. The prior revision incorrectly left the first import unresolved and
resolved the second to the class method. Both failed in
query-local-2026-10-17-import-scope-before.json. Native semantics revision 12 now
restricts plain named-import calls to module-level definitions; both questions
pass in revision12-query-import-scope-2026-10-17.json with identical source hashes.
An integration regression also covers same-named nested functions and multiple
module-level definitions remaining ambiguous. Namespace attribute chains, dynamic
exports and runtime rebinding are not newly supported.

All 68 detection development cases and ten distinct graph/trace questions passed
again against revision 12. The new revision12-*-2026-10-17.json reports retain
source/binary/corpus identities; preceding reports remain unchanged. Corpus groups
were run concurrently for correctness checks, so their wall times are not controlled
latency comparisons. This is measured repair of two authored scope regressions,
not held-out improvement or a comparative win. Query totals remain separate from
detection counts; independent adjudication, larger realistic families and pinned
competitor measurements remain required. CI is configured for the import cases;
no hosted run or publication was performed here.

query-import-attributes.json adds four questions from the existing Python
import-scope family. They expose namespace/member collisions, method-only exports,
a named import's attribute being mistaken for the imported function itself, and
a deeper namespace/class chain being guessed from its short name. All four were
incorrect in query-local-2026-10-17-import-attributes-before.json. Revision 13
admits only direct Python namespace members and plain named-import calls, and
requires module-level candidates for both. Unsupported attribute chains remain
unresolved; ordinary imported module objects are not treated as callable functions.
All four questions now pass in revision13-query-import-attributes-2026-10-17.json
with identical fixture identities. The integration regression also checks a bare
namespace-module call cannot bind a same-named function inside that module.

All 68 detection cases and fourteen distinct development queries passed after the
change. New revision13-*-2026-10-17.json reports preserve the binary/corpus/source
hashes, and previous corpora/reports remain unchanged. Groups ran concurrently
for correctness checks, so their timings are not controlled performance evidence.
The four additions remain part of the existing correlated import family; there
are still four development query families, no independent labels or held-out
claims, and no measured comparative win. CI now includes the new boundary cases
locally; hosted execution/publication remains unperformed.

query-receiver-chains.json adds a Python and JavaScript question where a deeper
self/this attribute chain was incorrectly bound to the current class's same-named
method. Both were incorrect in query-local-2026-10-17-receiver-chains-before.json.
Revision 14 restricts lexical self/this binding to direct members; both questions
now pass in revision14-query-receiver-chains-2026-10-17.json on identical fixtures.
The integration control also requires direct self.helper/this.helper calls from
the specific Worker.run owner to retain their correct local target.

All 68 detection cases and sixteen distinct authored graph/trace questions pass
under revision 14. The new revision14-*-2026-10-17.json reports retain identities;
older evidence remains unchanged. Corpus groups ran concurrently for correctness,
not controlled latency measurement. These two questions form a related receiver
boundary family, bringing the development family count to five without supplying
independent adjudication, held-out proof or comparative results. CI is configured
locally for the questions; no hosted run, release or publication occurred.

query-python-class-scopes.json adds two questions in the existing Python lexical
method family. A bare helper call inside Worker.run must select the module helper
when present, and remain unresolved when only Worker.helper exists. Both were
incorrect in query-local-2026-10-17-python-class-scopes-before.json; both pass on
identical fixtures in revision15-query-python-class-scopes-2026-10-17.json. A separate
integration control preserves a helper defined inside the enclosing method itself.

All 68 detection development cases and eighteen authored graph/trace questions
pass under revision 15. Revision15 reports preserve identities and older evidence
is unchanged. Corpus groups ran concurrently for correctness; wall times are not
controlled latency measurements. The additions stay within the existing lexical
method family, leaving five correlated development families and no independent
or held-out claim. CI is configured locally; hosted runs/publication remain unverified.

query-import-collisions.json adds two authored questions in the existing Python
import family. Importing files with an unrelated nested helper or class method
must still resolve their bare imported helper to the exporting module. The queries
failed 0/2 in query-local-2026-10-19-import-collisions-before.json and pass 2/2 in
revision16-query-import-collisions-2026-10-19.json, with identical corpus and source
identities. Native regression controls keep visible module/local/enclosing-function
collisions unresolved; full rebinding and import statement scope remain unsupported.

All 68 detection development cases and twenty distinct graph/trace questions pass
under revision 16, recorded in revision16-*-2026-10-19.json. Five correlated
development families remain, with no independent labels/holdout or comparative
claim. Corpus groups ran concurrently for correctness, not controlled latency
measurement. CI includes the new corpus locally; hosted CI remains unverified.

query-import-statement-scopes.json adds four authored questions in the existing
Python import family: sibling-function isolation, class namespace exclusion from
method closures, nearest function import selection and nested-function inheritance.
The first three failed before revision 17; the last was already correct. The corpus
improves from 1/4 in query-local-2026-10-19-import-statement-scopes-before.json to
4/4 in revision17-query-import-statement-scopes-2026-10-19.json with identical corpus
and fixture identities. Native controls also cover namespace isolation and an
unresolved nearer module that must not inherit an outer import's target.

All 68 detection cases and twenty-four distinct authored graph/trace questions pass
under revision 17 (revision17-*-2026-10-19.json). These remain five correlated
development families, not independent/held-out or comparative evidence. Corpus
groups ran concurrently for correctness, so recorded times are not controlled
latency measurements. CI includes the corpus locally; hosted CI remains unverified.

query-duplicate-imports.json adds two authored questions in the existing Python
import family: repeated named bindings and repeated namespace bindings to one
static export. Both failed in query-local-2026-10-24-duplicate-imports-before.json
and pass in revision18-query-duplicate-imports-2026-10-24.json on identical corpus
and fixture identities. Native controls preserve ambiguity for different imported
modules and distinct same-named export definitions; only identical symbol IDs are
deduplicated. Import/dependency records themselves remain retained.

All 68 detection cases and twenty-six distinct graph/trace development questions
pass under revision 18. Seventeen revision18-*-2026-10-24.json reports preserve one
stable binary identity. Corpus groups ran concurrently for correctness, so their
wall times are not controlled latency measurements. The new questions stay in the
existing import family, leaving five correlated authored development families and
no independent labels, holdout or comparative proof. CI includes the new corpus
locally; hosted CI remains unverified.
