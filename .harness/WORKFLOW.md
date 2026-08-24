# Harness Workflow

- Schema version: 4
- Project ID: project-25bc2383-ce85-49b1-b32b-49387e479288
- Run ID: RUN-ff934524c3ec446b9b01047596b5d8d1
- State authority: `STATE.json`
- Memory revision at load: 0

## Request and route

- User request: Execute the remaining ShipProof development plan, identify and fix additional worthwhile gaps, use the user-provided local Harness installation, and continue until the plan is genuinely finished.
- Operation: resume — the user explicitly reopened the same run from the Acceptance Gate for further rework.
- Requested scale: auto
- Selected scale/reason: full — release readiness, security contracts, rule quality, and performance/scale are material.
- Client/provider/model/effort when known: Codex desktop; GPT-5 family; primary-agent sequential role passes.
- Capability profile ID or summary: Local unrestricted filesystem and shell; pinned Harness 0.3.1; ShipProof 0.10.0 release candidate based on `c9785ab`; no isolated QA claimed.
- Explicit exclusions: No tag/push/public release, production/external mutation, load/DAST/fuzz traffic, package installation, telemetry, default-path network calls, or bulk rule promotion without fixtures and false-positive evidence. The earlier explicit request authorizes a local version update and commit only after all applicable gates pass.

## Current-turn overrides

These expire with this run and do not mutate durable memory.

| Key | Override | Conflicting record ID | Reason | Future action |
|---|---|---|---|---|

## Acceptance criteria

| ID | Criterion | Verification | Status |
|---|---|---|---|
| AC1 | Every stable public JSON command has a deterministic golden contract and compatibility fixture strategy. | Focused Node/Python contract tests and checked-in normalized fixtures. | Complete |
| AC2 | Rule assurance reports every executable rule and blocks newly added rules without positive and negative contract cases. | Structure tests plus machine-readable inventory output. | Complete — zero-debt fail-closed baseline |
| AC3 | No detector severity, threshold, or snapshot is weakened to make tests pass; no unsupported rules are bulk-promoted. | Diff/self-review and full scanner tests. | Complete |
| AC4 | Harness, repository checks, packed-artifact smoke test, and high-gate self-scan pass. | `harness doctor`, focused tests, `npm run check`, direct Python high-gate scan. | Complete |
| AC5 | Performance/package evidence remains within current project budgets, with estimates distinguished from measurements. | Existing benchmark/package budget commands on the same local environment. | Complete |
| AC6 | Every executable scanner rule has a machine-executed positive/negative/adversarial contract at the severity minimum, including exact finding-field assertions. | Successor manifests, contract runner, assurance report with zero debt, full scanner suite. | Complete — 620 complete, 0 partial, 0 uncontracted, 0 metadata debt |
| AC7 | Candidate promotion remains evidence-gated; only non-duplicate direct candidates with current primary-source semantics, fixtures, and measured shadow results may enter `RULES`. | Candidate records, provenance, duplicate analysis, controlled corpus metrics, benchmark delta. | Complete for local batch-A scope — 3 fixture-ready, 22 rejected, 0 promoted; representative shadow evidence remains external |
| AC8 | Optional evidence adapters fail closed, remain bounded/redacted, and do not add dependencies or network access to the default path. | Adapter contract tests covering unavailable, timeout, crash, findings, output caps, version probe, discovery consent, and redaction. | Complete |
| AC9 | P4/P5 and CLI 1.0 roadmap requirements are either implemented and locally verified or explicitly classified as external evidence that cannot honestly pass from repository fixtures alone. | Benchmark/corpus/release matrix, parser migration tests, docs and residual-evidence ledger. | Complete for local scope — representative findings remain unreviewed and 1.0 promotion/removal stays closed |
| AC10 | The final local version update and commit include only reviewed project changes; tag, push, and publication remain excluded. | Version consistency tests, clean staged diff review, commit identifier. | Complete — 0.10.0 candidate verified and prepared for the authorized local commit |

## Checkpoints and gates

| Checkpoint/gate | Required decision or evidence | Status | Human/date |
|---|---|---|---|
| Intake | Route, scope, risk, capabilities | Complete | Codex/2026-08-24 |
| Plan | Scope, exclusions, task graph, contracts | Approved by the user's explicit instruction to execute the plan | User/2026-08-24 |
| Design | Triggered design contract only | N/A — no UI or design direction change | |
| Decision | Durable/risky choices | N/A within approved plan; release/external actions remain excluded | |
| Integration | Stable contracts and ownership | Complete — P1 contracts, P2 decision record, P3 adapters, P4/P5 harnesses, CLI gate and 0.10 metadata integrated | Codex/2026-08-24 |
| Verification | Acceptance matrix and evidence | Complete — final full gate, package smoke, generated-artifact checks, doctor, and self-scan pass | Codex/2026-08-24 |
| Acceptance | Delivery only; review uses findings handoff | Waiting for final human acceptance; tag/push/publication remain excluded | User/2026-08-24 |

## Capability bindings

| Capability ID | Backend/version | Permission/isolation | State | Fallback/limitation |
|---|---|---|---|---|
| filesystem.read/write | Local workspace | Unrestricted project scope; primary-agent owner | READY | Preserve unrelated user changes; use reviewable patches. |
| shell.execute | PowerShell; Node 24.15.0; Python 3.12.10 | Local diagnostics/tests only | READY | No installation, external targets, or active traffic. |
| evidence.static | Local ShipProof 0.10.0 candidate based on `c9785ab` | Read-only preflight; same repository under test | READY | Self-evidence is not independent approval. |
| evidence.runtime | Repository test/benchmark scripts | Local deterministic checks | READY | Production load, soak, DAST, and fuzz evidence are not authorized. |
| agents.isolated | None used | Same-context sequential passes | UNAVAILABLE | Final QA must be labeled self-review. |
| docs.versioned/web.search | Available on demand | Read-only, minimal non-sensitive queries | READY | Primary sources required for material rule claims; not a substitute for fixtures. |

## Role packets

| Packet ID | Role/pass | Isolation label | Objective | Scope/owned files | State | Return evidence |
|---|---|---|---|---|---|---|
| RP-PLAN | Planner/Researcher | same-context | Convert residual roadmap into bounded release contracts using repository evidence. | Read-only repository/docs and Harness state. | Complete | Eight command contracts identified; rule debt measured without treating legacy references as explicit coverage. |
| RP-BUILD | Backend/Tooling engineer | same-context | Implement P0/P1 contracts with minimal package/runtime impact. | Contract fixtures, tests, scripts, and directly affected docs only. | Complete | Golden/schema/inventory tests plus full check pass. |
| RP-QA | Tester/Reviewer/QA | same-context self-review | Challenge compatibility, false-positive, packaging, and scale claims after integration. | Read-only final diff and deterministic gates. | Complete | Fixed Ruff scope pollution, EPERM parse ordering, and aggregate coverage omissions; no open change-specific blocker. |

## Task graph

| Task | Owner/pass | Depends on | Deliverable | State |
|---|---|---|---|---|
| Establish baseline and gap map | RP-PLAN | Intake | Reproducible baseline plus affected contracts. | Complete |
| Add public JSON golden/compatibility fixtures | RP-BUILD | Baseline | Deterministic fixtures and drift tests. | Complete |
| Add rule-assurance inventory/new-rule gate | RP-BUILD | Baseline | Machine-readable coverage report and structural enforcement. | Complete |
| Harness-guided risk review and bounded fixes | RP-QA then RP-BUILD | Integration | Confirmed findings fixed with regressions. | Complete |
| Full verification and handoff | RP-QA | All build tasks | Package, scan, performance, Harness evidence. | Complete |
| Complete executable-rule contracts | RP-BUILD | P1 inventory | Successor manifests/runner with zero incomplete executable IDs. | Complete |
| Promote evidence-backed candidate batches | RP-PLAN, RP-BUILD | Complete executable-rule contracts | Candidate lifecycle records, shadow results, only eligible promoted rules. | Complete locally — no candidate eligible for promotion without external shadow evidence |
| Finish evidence adapters and scale/evaluation gates | RP-BUILD, RP-QA | Stable candidate/engine contracts | Bounded optional adapters, reproducible corpora and measured budgets. | Complete locally; representative alert labels remain external evidence |
| Complete CLI 1.0 migration and release candidate | RP-BUILD, RP-QA | Prior milestones | Tested removal gate, migration docs, version-consistent local commit. | Complete locally; actual alias removal stays gated on 1.0 |

## Memory recall manifest

| ID | Scope | Load state | Verification state | Used? | Reason |
|---|---|---|---|---|---|

## Memory transactions

`MEMORY.json` is authoritative. This table is an audit projection and may be rebuilt from its last committed transaction.

| Tx ID | Operation | Record ID | Before revision | After revision | Result/adapter state |
|---|---|---|---|---|---|

## Verification summary

Put detailed bug, performance, scale, security, research, UI, or ShipProof evidence in conditional `EVIDENCE.md`.

| Check | Command/method | Result | Evidence location | Date |
|---|---|---|---|---|
| Harness health | `python .harness/runtime/scripts/memory_ops.py doctor --project . --logical-scope .` | PASS/HEALTHY | Repository-pinned runtime; `.harness/` | 2026-08-24 |
| ShipProof preflight | `node bin/shipproof.mjs doctor . --json` | PASS; Node 24.15.0; Python 3.12.10 | Local command output | 2026-08-24 |
| Command golden contracts | `node tests/node/command-contracts.test.mjs` | PASS; 8/8 command reports exact-match | `fixtures/command-contracts/` | 2026-08-24 |
| Command schema compatibility | `python -m unittest tests.test_command_contracts tests.test_evidence_schemas -v` | PASS; 8 tests | Versioned v1 JSON fixtures and current schemas | 2026-08-24 |
| Rule assurance | `python scripts/rule_assurance_report.py --format json --check` | PASS fail-closed gate; 620 complete, 0 partial, 0 uncontracted, 0 metadata debt | `docs/rule-assurance.md`; `tests/rule_assurance_legacy.json` | 2026-08-24 |
| Successor rule contracts | `python -m unittest tests.test_secret_rule_quality tests.test_legacy_rule_contracts tests.test_legacy_structural_contracts tests.test_rule_assurance_inventory -v` plus all three builders in `--check` mode | PASS; 620 complete, 0 partial, 0 uncontracted, 0 metadata debt | `tests/rule-contracts/`; `tests/rule_cases_secrets.json`; `docs/rule-assurance.md` | 2026-08-24 |
| P2 batch-A triage | `python -m unittest tests.test_promotion_batch_a -v` and deterministic builder check | PASS; 25 reviewed, 3 fixture-ready prototypes, 22 rejected, 0 silently promoted | `research/promotion-batch-a.json` | 2026-08-24 |
| Full repository gate | `npm run check` | PASS; 602 Python tests plus 2 demo tests, all Node suites, 113-file package allowlist, packed-artifact smoke | Local deterministic output | 2026-08-24 |
| Python coverage | `npm run test:python:coverage` | PASS; 84% total branch-aware coverage | `coverage.xml` (ignored local artifact) | 2026-08-24 |
| Node coverage | `npm run test:node:coverage` | PASS; enforced line threshold met with complete aggregate suite imports | Local deterministic output | 2026-08-24 |
| High-gate self-scan | `python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high` | PASS; 267 files, 0 findings | Local deterministic output | 2026-08-24 |
| Scanner benchmark | `python scripts/benchmark-scanner.py --files 1000 --samples 3` | PASS; median 0.9747 s, p95 0.9879 s, peak RSS 25.57 MB; deterministic samples and all budgets passed | Windows/Python 3.12.10 local synthetic corpus | 2026-08-24 |
| Harness portability | `python .harness/runtime/scripts/validate_portability.py --project . --project-only --json` | PASS; repository-pinned Harness runtime | Local Harness 0.3.1 | 2026-08-24 |

## Defect loop

| Blocker ID | Attempt | Classification | Evidence | Routed to | Result |
|---|---|---|---|---|---|

## Handoff snapshot

- Outcome: The full local 0.10.0 release-candidate plan is complete and waiting for human acceptance, not public release approval.
- Material changes or findings: Eight versioned command snapshots; compatibility validation; complete contracts for all 620 executable rules; bounded optional evidence adapters; deterministic benchmark/evaluation harnesses; a 25-candidate research decision record with 0 unsupported promotions; and a tested CLI 1.0 removal gate.
- Passed checks: Harness doctor/portability, generated-artifact checks, focused contract tests, full `npm run check`, Node/Python coverage gates, 113-file package smoke, 267-file high-gate self-scan, and clean/adversarial/large-file benchmark budgets.
- Not verified: Production load/soak/DAST/fuzz, human labeling of representative-repository alerts, the hosted multi-runtime CI matrix from this workstation, or independent QA.
- Residual risks: Three research prototypes remain shadow-only; 310 application findings from the pinned public corpus are explicitly unreviewed; local synthetic benchmarks do not prove production capacity.
- Human decisions: Accept or request rework; tag, push, and public release remain separate explicit actions.
- Memory/adapter changes: Harness initialized and pinned at 0.3.1; no durable project-memory records were added; QA was same-context self-review.
- Reusable next command: `python scripts/rule_assurance_report.py --format json --check`

## Rework checkpoint — 2026-08-24

- Trigger: The user explicitly requested continuation of the same objective from `WAITING_ACCEPTANCE`.
- Transition: `WAITING_ACCEPTANCE -> REWORK`; selected scale remains `full`.
- Baseline preserved: P0 command contracts and the transitional P1 inventory remain passing evidence, but the 560 incomplete rule contracts are now an active acceptance failure.
- Highest-value hypothesis: A versioned successor fixture schema with named, executable source providers can replace placeholder/reference-only coverage without embedding secret literals or claiming that a rule is complete before its detector and exact finding metadata are exercised.
- Iteration bounds: one coherent rule-contract batch at a time; focused tests before the full gate; no detector promotion until AC6 reports zero debt; two no-progress cycles maximum per blocker.
- Rollback point: current uncommitted worktree and Git commit `c9785ab`; no destructive Git operation is authorized.

## P1 closure checkpoint — 2026-08-24

- Result: AC6 is complete. All 620 executable rules now have versioned machine-executed contracts with positive, negative, and adversarial cases, exact finding metadata, stable fingerprints, minimum severity, CWE/control mapping, remediation, and false-positive analysis.
- Coverage split: 50 runtime-generated secret contracts, 484 regex/pattern contracts, 25 structural contracts, and 1 artifact contract.
- Fail-closed behavior: `tests/rule_assurance_legacy.json` is empty and `--update-baseline` refuses to expand debt; new executable rules without complete contracts fail the structure gate.
- Evidence boundary: mechanically derived pattern witnesses are deterministic detector-regression evidence, not representative-repository precision evidence. Candidate promotion and severity calibration remain gated by separate measured corpus/shadow evidence under AC7.
- Next action: triage the bounded P2 batch against current primary documentation, deduplicate it against existing rules, and reject candidates whose risk is not locally observable without runtime or taint evidence.

## P2 batch-A checkpoint — 2026-08-24

- Reviewed: 25 direct-tier candidates at the documented ecosystem caps across C#, TypeScript, PHP, React, Go, C++, Angular, JavaScript, and SQL.
- Result: 3 fixture-ready research prototypes (`SP5301`, `SP5951`, `SP6309`), 22 rejected from this batch, and 0 promoted into the executable scanner.
- Controlled evidence: each prototype has two positive, four negative, and two adversarial cases executed against its narrow research-only matcher.
- Duplicate/route evidence: every claimed existing-rule duplicate resolves to a current executable ID; candidates requiring data flow, lifetime, deployment policy, or a different framework route were not approximated with broad regexes.
- Primary semantics checked: current CWE plus owning Microsoft, PHP, Go, Angular, React, TypeScript, Node/PostgreSQL, and SEI documentation; community sources did not satisfy promotion.
- External dependency: representative repositories must be revision-pinned and license-reviewed before shadow TP/FP/FN/TN and runtime deltas can be measured. Until then, batch B and all promotions remain closed.
