---
name: sentinel-security-audit
description: Run evidence-based security audits using Sentinel's repository-bound MCP tools, Cloudflare's coverage-led audit workflow, and independently reviewed findings. Use for requested security audits or vulnerability investigations.
---
# Sentinel security audit

Use [Cloudflare's workflow](upstream/security-audit/SKILL.md) for reconnaissance,
coverage-led hunting, independent validation, and reporting. Focused questions use
guidance mode. Full audits follow its six phases and execution isolation rules.
This adapter does not authorize cloud submission, production probing, or target
execution. Sentinel does not supply an execution sandbox.

## Start a full audit

Run `sentinel audit-workflow init /absolute/repository --output /external/new-run`.
The output parent must exist and be outside the target. The command creates a
new run, exports this skill and upstream references under `skill/`, snapshots
bounded selected source, and seeds planned coverage from the deterministic index.
The initial ledger is a starting plan, not a threat model or completed coverage.
Read its omissions and expand trust boundaries, attack classes, and starting paths
from reconnaissance. Files outside the recorded snapshot require a fresh run with
an explicit `--include` path; do not claim ignored or excluded paths are covered.

The parent alone owns run-metadata.json, coverage-ledger.json, findings.json,
and verification.json. Delegate only if the user/platform permits it; otherwise
record the unavailable independent review as a blocker. Read relevant companion
references on demand, including AI-AND-LLM.md for hybrid AI/tool trust boundaries.

## Use Sentinel evidence

Call `sentinel_get_audit_workflow` for the adapter and command contract.
Use `sentinel_index_project`, `sentinel_find_symbol`, `sentinel_get_callers`,
`sentinel_get_callees`, and `sentinel_get_security_context` during reconnaissance.
Use `sentinel_scan_file`, `sentinel_trace_taint`, and `sentinel_explain_finding`
to develop source-grounded candidates. Rule matches and approximate flows are
leads; they do not prove exploitability. Use `sentinel_verify_patch` after edits.
Track every reviewed unit, blocker, deferred task, and candidate in the ledger.

Both local and cloud models may use the same context snapshot. Give discovery
and verification separate sessions and distinct reviewer IDs. Shared context or
two agreeing model answers do not establish independent verification.

## Validate and retain

Keep Cloudflare's findings.json and coverage-ledger.json contracts unchanged.
Do not place unvalidated leads in findings.json. For each confirmed finding, add
a verification.json record with fingerprint, discoverer, verifier (distinct safe
agent IDs), source_snapshot (from metadata), method `sandboxed-local`, observed_result
(exactly matching execution.observed_result), and sandbox object containing true
network_disabled, environment_allowlisted, read_only_target, scratch_only_writes,
resource_limited, plus a nonempty limits description. These are audit attestations,
not authenticated identities or independently proven execution results.

Without the required OS sandbox or observed result, use needs_validation with the
exact unresolved fact. Never fabricate verification or reproduction evidence.

Run `sentinel audit-workflow validate /repository --run /external/run` after updates.
This runs pinned upstream validators with Node.js, verifies evidence locations,
cross-links candidates to units, checks recorded review independence, and compares
the current source snapshot. It never runs run-directory scripts or target code.
Set metadata.run_status to `complete` only after all units and candidates are
accounted for; blocked/deferred coverage remains explicitly partial.

Run `sentinel audit-workflow import /repository --run /external/run` to retain the
validated report separately from deterministic scan findings and verification gates.
Use `sentinel_get_audit_status` or TUI `u` to inspect the imported report and stale
source warnings. Export with `sentinel audit-workflow report /repository --output
/external/REPORT.md`. Revalidate changed source in a new run rather than carrying
confirmation forward blindly. Node.js is needed for validation/import only.
