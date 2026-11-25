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
Admission checks completeness and file hashes from the same committed graph
snapshot, rather than pairing a refresh result with a separately read manifest.
Incomplete indexing cannot create a job; an incomplete admission snapshot marks
a pending job stale before reserving another attempt. Configuration, hidden files, dependencies
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

## Browse retained jobs

`sentinel job list [project] --limit 20` lists newest job metadata first; limits
are 1–100. In the TUI, `o` opens the latest 20 jobs in Investigation. Listings
show recorded state, unit count, reserved attempts, elapsed/budget time, active
file and source snapshot. Large per-file manifests and findings are omitted.
A `has_more` flag makes truncation explicit. Lists use a consistent database read
transaction and fail on malformed stored job contracts.

Listing never indexes source, contacts a provider, executes targets, resumes work,
or asserts freshness. `Completed` is a recorded workflow state, not a clean security
verdict. Resume/cancel are explicit CLI or TUI actions; source and detector identity
are checked by resume. Merely listing or selecting a job never resumes it.

## Stored record consistency

All status, list, cancel and resume reads reject contradictory stored job records.
Results must name distinct admitted files, fit reserved attempts, and reconcile
retained finding IDs plus omitted counts. Running records require an unrecorded
active file and an outstanding reservation; completed records require complete
results for every declared unit and no active file. Cancelled records may retain
an admitted active file because cancellation is cooperative. These checks detect
inconsistent records; they do not authenticate a database against deliberate
rewrites or establish source freshness. Overshooting a cooperative time budget
remains valid recorded accounting, rather than a reason to discard the record.

Cancellation regression coverage includes a deterministic second-writer simulation
at the reservation boundary. The admitted unit may finish its ordinary scan, but
its late compare-and-swap cannot overwrite cancellation or record a job result;
a fresh engine cannot admit subsequent units. An active file in a cancelled
record also requires an outstanding reserved attempt. This is transaction/state
regression evidence, not a stress test of all concurrent schedules or OS worker
containment.

## TUI job controls

Press **o** in Investigation to load the latest 20 jobs. **Up/Down** or **j/k**
select a job, **Home** selects the newest, and **Enter** reads its stored details.
**r** explicitly resumes at most one unit with the job's existing attempt/time
budgets; **C** (uppercase) cancels the selected persisted job. **o** reloads the
list after an action. Detail arrows scroll rather than switching the selected
job. Completed, cancelled and stale jobs cannot be resumed into new work.

Resume may return a pending record with exit 2 because other units remain. The
TUI retains its results and budgets instead of treating valid JSON as a protocol
failure. Status and cancellation do not establish source freshness. Cancellation
is cooperative; an admitted unit can finish its ordinary scan but cannot commit
results into the cancelled job.

The TUI permits one primary operation and, only during static resume, one
concurrent cancellation worker. In Investigation, **C** requests persisted
cancellation while the resume worker is still running. Selection, settings and
new operations remain locked until both workers settle. A matching cancelled
record stops the owned resume worker after cancellation is acknowledged. If
completion wins the race, the actual terminal state is displayed; cancellation
errors do not stop or relabel the resume operation. Existing engine
compare-and-swap checks prevent a late result from replacing cancelled state.

**Esc** stops both owned UI workers. It does not guarantee a cancellation request
has committed; reload status before further actions. Killing a resume worker can
leave a Running reservation; explicit `--recover-interrupted` remains CLI-only
and must follow stopping the previous worker. Recovery does not refund the attempt
and conservatively exhausts unknown remaining time. The TUI never automatically
recovers interrupted jobs, increases budgets or executes target code. These process
controls are not an OS containment boundary or hard deadline guarantee.

Job selection is frozen while a TUI worker is active. Details must name the
selected job before they replace the displayed record. This prevents a resume
response for one job from being shown while subsequent actions target a different
selection. Status/detail scrolling does not change the selected job; reload with
o when choosing another job.

TUI workers retain at most 16 MiB of stdout and 64 KiB of stderr, plus one
overflow byte per reader for limit detection. Oversized output, read errors and
reader disconnection fail the operation instead of producing a partial success.
The original exit status and both completed streams are preserved. Deadline and
post-exit pipe-grace checks run when the UI polls; they are not hard OS deadlines
or proof that all descendants have been contained or reaped.

Stored job reads select at most 2 MiB plus one overflow byte from SQLite before
Rust parses the JSON. Oversized records fail status, listing, resume and cancel;
UTF-8 size is measured in bytes. This limits payload transfer/deserialization,
not SQLite's overall memory use or the database file size.

Job listing also transfers at most 65 bytes per stored identity and creation
timestamp, including its pagination lookahead row. Identities must be 64 hex
characters; timestamps must be nonempty, at most 64 bytes and free of controls.
Invalid UTF-8 or metadata fails the listing without returning partial summaries
or changing jobs. These shape checks do not authenticate timestamps or establish
source freshness.
