# Phase 2 backend evaluation

## Decision

Retain the native engine. Joern inclusion is deferred pending an executable,
isolated evaluation and measured benefit. This is a feasibility decision, not a
negative accuracy result for Joern. No Joern adapter is shipped or silently selected.

On this Windows workspace on 2026-10-07, `joern` was absent from PATH. Docker was
installed but `docker info` failed because the Docker Desktop Linux engine pipe
was unavailable. Consequently no Joern corpus/resource measurements were produced.
Target code was not executed on the host.

The [Joern installation guide](https://docs.joern.io/installation/) and
[upstream Dockerfile](https://github.com/joernio/joern/blob/master/Dockerfile)
provide starting points for a pinned backend environment. They do not establish
Sentinel's containment boundary.

## Shared evidence foundation

Native `TraceReport` records backend name, version, semantics revision and source
snapshot over admitted indexed files. Missing legacy provenance stays unknown.
A future backend must preserve source identity, locations, coverage notes and
explicit failure/unsupported states in this contract. Source snapshot denotes
analyzed scope, not proof of all project files or runtime behavior.

Before implementing transport, define fixed source/sink and caller/callee query
templates, pinned backend/frontend identities, read-only source input, no network,
no host Docker socket, time/memory/output limits, bounded artifact intake and
independent containment review. Arbitrary Scala/CPGQL must not be exposed through
repository MCP. Backend choice must be explicit; failures and disagreements must
remain visible rather than be replaced with native results.

## Native development evidence

`phase2-native-installed-baseline.json` and `phase2-native-after.json` retain exact
binary/corpus identities. On 14 cases, the installed baseline had 5 TP, 2 FN,
5 TN and 2 FP. The new offline release has 7 TP, 7 TN, no mapped misses or false
positives and no incomplete cases. Existing 34 development cases also pass.
Timing is single cold-process measurement, not p95 or comparative resource proof.

Implemented: lexical resolution, namespace/named aliases, conservative ambiguous
imports/default exports, supported Flask/FastAPI string route inputs, literal
object field precision with reassignment/branch invalidation, ordinary async
return propagation, and source-bound trace provenance. See
[exact supported contracts](framework-source-contracts.md).

Remaining Phase 2 work includes realistic reviewed framework contracts (especially
Express/Fastify registration), type/alias and exception semantics, independent
family-disjoint graph/flow labels, and the isolated Joern benefit measurement.
The roadmap exit gate remains open; development regressions cannot certify
competitive superiority or production-wide framework coverage.
