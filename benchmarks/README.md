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
