# Resumable static scan jobs

Native jobs persist in SQLite schema v6 and never execute target code, external
scanners or AI models. They scan supported indexed code using the same rule/graph
engine exposed by `scan-file` and MCP.

```powershell
sentinel job create C:/projects/my-app --max-attempts 100 --max-seconds 300
# Use the returned id:
sentinel job resume JOB_ID --project C:/projects/my-app --max-units 5
sentinel job status JOB_ID --project C:/projects/my-app
sentinel job cancel JOB_ID --project C:/projects/my-app
```

Create freezes indexed relative paths, content identities and detector identity.
Resume reconciles that scope before and after each unit. Added, deleted, changed,
excluded or unreadable code prevents admission from a mismatched snapshot.
Incomplete indexing cannot create a job. Configuration, hidden files, dependencies
and excluded code remain outside the indexed-code scope.

Reservations persist before work starts. Attempts never exceed the creation
budget (1–100); resume batches are bounded to 1–100 units. The cumulative time
budget (1–3600 seconds) is checked between units. This is a cooperative static
budget, **not a hard subprocess deadline or sandbox**. Full reconciliation repeats
on each unit and needs performance work for large repositories. Records are capped
at 2 MiB and retain at most 500 finding IDs per unit, with omitted IDs counted.

Compare-and-swap updates prevent late workers from overwriting cancellation or
another worker's update. Cancellation stops new admitted units; an active unit
may finish and update the ordinary scan database, but cannot commit its result
into a cancelled job. Cancellation is cooperative.

Normal restart resumes a pending job from recorded completed units. A crash inside
an active unit leaves `running`. Stop the old worker before explicitly using
`--recover-interrupted`; unknown elapsed time conservatively exhausts the remaining
budget, and the attempt is not refunded. Create a new job for remaining work.
Uncertain crash results are never silently promoted to completion.

Statuses: `pending`, `running`, `completed`, `cancelled`, `stale`,
`budget_exhausted`, `failed`. Status reads stored state without reconciling current
source freshness. Completion means declared static units finished, not that a
project is safe or a Cloudflare audit is complete. Findings remain candidates.
Resume exits 0 only for completed jobs, otherwise 2; successful create/status/
cancel operations exit 0. Budgets cannot increase on resume.

Analysis semantics revision 2 invalidates old cached IR even for unchanged files.
Detector changes invalidate pending jobs. Missing or changed detector provenance
prevents baseline comparisons from returning PASS.
