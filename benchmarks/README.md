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
source hashes. Timing includes process startup and database writes; it is a single
cold scan measurement, not a warm latency percentile or memory benchmark. Retain
hardware/OS, build command and tool configuration alongside reports.

The checked-in `seed-baseline.json` was measured on Windows with the locked,
offline release build on 2026-10-07: seven true positives, seven true negatives,
zero mapped false positives/negatives and zero failed scans. The 95% interval for
both precision and recall is approximately 0.646–1.000; the perfect seed score
is not evidence of perfect general detection. This is development data only.

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
