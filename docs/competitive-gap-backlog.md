# Competitive gap implementation backlog

This turns the current Nox/Joern comparison into implementation work and supplements
the [phased roadmap](competitive-roadmap.md). No competitive accuracy win is measured.

| Priority | Gap | Deliverable | Acceptance evidence |
|---|---|---|---|
| P0 | Measurement is too small | Realistic development families, graph queries, patched pairs and pinned competitor configurations | Independent labels, family-disjoint holdout, per-class confidence intervals, unsupported/error accounting |
| P0 | Evidence/job reliability | Propagate source/detector identity; bounded artifacts and worker deadlines; cancellation-race tests | Source changes, upgrades, interruption and partial analysis cannot yield false PASS |
| P1 | Nox leads secrets coverage | Provider signatures, context/entropy checks, redacted findings and shared-context redaction | Dummy tokens and hard safe examples; no credential bytes in reports/logs/prompts; no live validation |
| P1 | Nox leads dependency coverage | Lockfile inventory, versioned local advisory cache, explicit online refresh, version-range matching and SBOM | Ecosystem fixtures; timestamp/provenance and offline/stale/unavailable coverage |
| P1 | Nox leads configuration/AI coverage | Actions/Docker/Kubernetes/Terraform policies; agent hooks/tool/MCP permissions; AI input/output flows | Reviewed threat contracts and positive/negative fixtures; principal/resource evidence; inspected hooks never executed |
| P1 | Joern leads semantic depth | Framework contracts, import/alias/object/async resolution, category-specific sanitization and parameterization | Ground-truth cross-file queries/flows, hard negative cases and disclosed unsupported semantics |
| P2 | Deeper backend integration | Evaluate optional isolated Joern on native misses; expose fixed query templates | Measured accuracy/resource benefit, shared source identity and reviewed isolation; no arbitrary executable MCP queries |
| P2 | Hybrid AI is explanation-only | Native bounded recon/investigation/review using Ollama/NIM/both, immutable contexts and persistent budgets | Provider isolation, separate outputs/costs, fake-provider failures, prompt-injection and cancellation tests |
| P2 | Runtime patch proof is absent | Reviewed Linux containment, dummy-input reproduction and isolated patch/test loop | Enforced network/filesystem/resource controls, hostile workers/artifacts and no host-execution fallback |
| P2 | Evidence navigation/editor support | Structured TUI audit/jobs/history, navigable traces, LSP, CI policies and exports | Responsive cancellation, stale/partial labels, editor protocol tests and independent workflow-time study |
| P3 | Release/superiority proof | Multi-platform packaging/migrations, signed provenance, independent audits and pinned comparative evaluation | Publish configuration, limitations and failures; claim wins only in passing dimensions |

Next slices: finish strict measurement and graph/patch scoring; harden existing
jobs/evidence; begin secrets with redaction before provider integration; add
dependency inventory/advisory freshness; improve semantics against recorded misses.
Do not pad the corpus with duplicate templates to meet a count target.

The intended advantage is a coherent scan → investigate → explain → patch → verify
workflow with explicit local/cloud choice and durable evidence. Coverage, depth,
accuracy, latency and workflow utility each require separate comparative results.
