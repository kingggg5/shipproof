# ShipProof 0.12.0 verification record — 2026-10-22

Status at this pre-push snapshot: **required local code gates pass; publication is
conditional** on exact remote CI and the tag-signing/protection decision. A pending
gate is not a pass. Remote outcomes belong to the commit's GitHub check runs and
release workflow, not to a self-referential commit hash embedded in this file.

## Scope and authority

The user requested a substantial update, commit/push and the next release, then
explicitly added PHP2Shell. The integration preserves the pending TypeScript,
Roblox/Rust, metadata and historical-release fixes. It adds the dated SP683 version
advisory and narrows SP668/SP670, for **652 executable rules**. No npm publication,
exploitation, production changes, new model/API service or private target-source
upload to an analysis service is in scope. Publishing this repository to its
existing GitHub remote was explicitly authorized.

Current runtime/plugin/package identity is `0.12.0`. Exact tags are immutable;
the repository's pre-1.0 GitHub workflow marks 0.x releases prerelease. The existing
moving major alias is maintained only by that successful release workflow.

## Evidence gates

| Gate | State / evidence |
| --- | --- |
| Security | Local high-gate self-scan exits 0: 452 inspected files, complete selected-source coverage, 0 application findings and 32 intentional test-scope findings. Dependency audit went from 1 critical / 2 high / 2 moderate to zero. Remote security checks pending. |
| Correctness | `npm run check` passes: 868 Python tests (3 existing platform skips), 2 demo tests, Node suites, lint, package allowlist and isolated CLI/Action/MCP consumer smoke. Contract freshness, compile, rule assurance and precision-trend gates pass. |
| Data & privacy | Default remains offline/read-only. Synthetic credential echo in the new advisories was confirmed and fixed with normalized evidence/minimized contexts; regressions cover JSON, SARIF, terminal, Markdown and full fix prompts. No claim that all arbitrary private source can be recognized as non-sensitive. |
| Scale | Both final 1,000-file profiles pass the unchanged 8 s / 256 MiB limits; measurements below. Package is 111 files, 484,874 packed / 1,857,107 unpacked bytes, below unchanged 500,000 / 1,870,000 ceilings. No production-scale claim. |
| Operability | Packed consumer and missing-optional-peer smoke pass. Node instrumented coverage passed at 87.44% line coverage. Windows Python coverage is inconclusive; exact Linux CI and publication checks remain required. |
| Supply chain | SDK 1.32.1, fast-uri 3.1.8, hono 4.13.13, proxy-addr 2.0.8, ip-address 10.7.4; install scripts disabled, audit zero. Signed/protected-tag requirement or an explicit owner exception still needs resolution before tagging. No npm publication was performed. |

## Bounded measurement details

Windows 11, Python 3.12.10, one scanner worker, one warm-up and ten measured samples
per profile; deterministic inputs. Final profiles ran after the earlier competing
test/diagnostic jobs ended. These are absolute budget checks, not a claimed speedup
against another scanner, a different host or the earlier three-sample runs.

| Profile | Files / bytes | Samples (seconds) | Median / p95 | Peak RSS | Findings |
| --- | --- | --- | --- | --- | --- |
| Python clean | 1,000 / 128,000 | 1.2543, 1.2116, 1.0920, 1.2263, 1.1443, 1.1408, 1.1144, 1.0655, 1.0706, 1.0782 | 1.1276 / 1.2543 s | 28.91 MiB | 0 |
| TypeScript configuration | 1,000 / 512,000 | 2.1738, 2.1542, 2.2416, 2.1355, 2.1223, 2.2228, 2.3795, 2.1098, 2.0700, 2.2698 | 2.1640 / 2.3795 s | 28.15 MiB | 0 |

The PHP/native contract cohort has 68 authored scenarios (32 PHP, 17 C/C++, 19 C#),
plus the preceding TypeScript and Roblox/Rust corpora. Privacy regressions were
executed against all returned findings, not only a filtered advisory list. Rule
assurance remains 652 complete, 0 partial/uncontracted/metadata debt, 94 rules with
realistic negatives, 558 near-miss-only and 423 high/critical realistic-negative debt.

## Python coverage limitation

An initial non-verbose Windows run was stopped after prolonged CPU activity and
buffered progress output. A verbose timer-based diagnostic reached later tests but
exited with a native access violation (`-1073741819`). Focused invariants, research
catalog and baseline-suppression coverage probes passed. These diagnostics do not
establish a ShipProof application crash or a successful full coverage result.

The coverage command now prints test names; its measurement scope, branch flag and
80% floor are unchanged. The full non-instrumented suite passes. Linux CI's normal
coverage job is required before an exact release tag; no exclusion or threshold
was added to hide this unknown, and the diagnostic wrapper is not shipped.

## Publication gate

At capture, the public repository had no tag ruleset and this machine had no
configured signing key. The owner was asked to choose signing/tag protection or
an explicit one-time unsigned annotated-tag exception. No answer is assumed from
a default UI choice. Commit/push is authorized; tag/release creation waits for that
decision and exact-commit CI. Exact-version tags must never be force-updated.

## Review and residual risk

Planning, security decisions and integration are primary-agent work. A bounded
helper performed mechanical version/reference edits only; that is not independent
security approval. The source review is self-review plus separately executed tests.

New cohorts stay advisory pending representative, human-labeled repository data.
SP683 does not prove deployed PHP patch status or reachability; no live PHP,
container or web target was tested. XML/format checks are bounded syntax views,
not complete native compilers. Existing realistic-negative debt is not relabeled
as resolved merely because all rules meet the minimum polarity contract.

Observed remote CI/release outcomes must be reported separately for the exact commit.
Logs and audit/benchmark outputs remain in ignored `.cache/`, not the package.
