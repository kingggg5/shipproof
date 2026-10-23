# Luau / TypeScript precision cohort — 23 October 2026

## Engineering contract

- Baseline: `f4459ba0bf081e9c9bc70a3dd5712661e0860191`, clean
  `codex/field-precision-ts-dotnet-dart`; previous full check: 919 Python tests.
- Objective: extend direct Luau remote-input checks to simple typed callbacks
  and RemoteFunction, add narrowly observable module/deletion boundaries, and
  cover additional import-bound JWT/HTTP security opt-outs in TypeScript.
- Proposed IDs: SP690 (client-selected require), SP691 (client-selected Destroy),
  SP692 (explicit RSA signing key-size safeguard bypass). Reuse SP672, SP676 and
  SP679 for additional syntax/API variants; do not inflate the count with aliases.
- New Luau IDs require a local `Instance.new` RemoteEvent/RemoteFunction binding,
  a two-parameter callback and a single direct sink statement. Guards, unrelated
  objects, aliases, escapes, rebinding and complex parameter types are unresolved.
- All new coverage is structural advisory, not demonstrated exploitability.
  Runtime permissions, deployment, effective key strength and other controls are
  not inferred. No thresholds, existing positive expectations or baselines lowered.
- Gates: at least 3 positive / 5 negative / 2 adversarial cases per new rule;
  real walker, scope, redaction, CLI/SARIF parity and advisory-gate tests; pinned
  public source replay; full check, assurance, package budgets and high self-scan.
- Budgets: three implementation/review passes, 90-minute checkpoint, no paid API
  use; at most two new public repository snapshots and 20 documentation requests.
  Keep runtime dependency-free, offline, read-only and bounded at 50,000 tokens;
  retain 1 MB source and 500,000 / 1,870,000 byte package ceilings.
- Evidence: ignored `.cache/luau-ts-20261023/`; commit source, authored cases,
  provenance and aggregate results only. Never execute downloaded project code.
- Out of scope: Roblox Studio/game mutation, broad taint engine, native Roblox
  exploitation, dependency installs in scanned projects, merge and release.
- Commit/push continue the previously authorized branch workflow after gates.
  Stop on two no-progress passes or an authority/safety blocker; baseline commit
  remains the rollback reference without resetting unrelated work.

## Primary references

Context7 resolution was attempted for Roblox and Node.js; its monthly quota was
exhausted. Owning documentation/source is the fallback, not community claims.

- [Roblox client/server boundary](https://create.roblox.com/docs/scripting/security/client-server-boundary):
  client arguments must be validated, especially dynamic require and arbitrary
  instance deletion. Does not prove that a particular game is deployed/exploitable.
- [RemoteFunction](https://create.roblox.com/docs/reference/engine/classes/RemoteFunction):
  first server callback argument is Player; following arguments come from caller.
- [Luau types](https://luau.org/types/): annotations are static checking, not a
  substitute for runtime authorization or input validation.
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) and
  [sign implementation](https://github.com/auth0/node-jsonwebtoken/blob/master/sign.js):
  explicit size/type opt-outs and header algorithm override semantics.
- [Node HTTP](https://nodejs.org/api/http.html): explicit insecure parser modes.

## Accepted implementation and precision boundaries

- SP690/SP691 require a directly constructed native remote, exactly one handler,
  no receiver escape/rebinding, and the declaration before use without an
  intervening block/branch boundary. Whole callback bodies must be the direct
  client-argument sink (optionally returned). This deliberately misses guarded,
  aliased and complex flows; it does not certify their safety.
- SP672 reuses the existing ID for simple typed parameters and OnServerInvoke.
  Multi-local declarations and loop bindings now invalidate builtin evaluator
  identity. Legacy event-like receivers remain advisory/unresolved, unlike the
  stricter construction requirement of the two new rules.
- SP692 requires an imported JWT sign call, explicit RS/PS algorithm, true size
  opt-out, and no header override. SP676 extends the existing compatibility
  opt-out to sign with explicit asymmetric algorithms. HMAC/default algorithms,
  type-only/custom imports, local shadows and unknown overriding options stay
  silent. No private keys are inspected or collected.
- SP679 additionally recognizes explicit insecure HTTP validation on supporting
  Node releases. Strict/relaxed modes and conflicting legacy switches are not
  reported by this signature. Its coarse prefilter was extended too, and the
  contract runs through the repository walker, not just the helper.
- Nested Luau interpolated strings remain entirely opaque. Their contents cannot
  escape into callback recognition; malformed input and 32-string/128-brace
  limits report incomplete coverage. Interpolation expressions are not analyzed.
- A name-to-position index and prefix block-boundary counts keep remote binding
  checks linear in the token inventory rather than rescanning the whole file for
  every local declaration. The 50,000-token ceiling remains unchanged.

There is no semantic duplication with the HTTP-response execution rule SP671,
code-string evaluation SP672, or HTTP-route authorization rules. Shared CWE roots
are retained in the generated research deduplication index, not counted as new
research discoveries. All three new rules remain nonblocking at every gate floor.

## Verification

- Full `npm run check`: **930 Python tests**, three Windows symlink-privilege
  skips, two demo tests, Node contracts, package allowlist and isolated
  CLI/Action/skill smoke passed. Full Python coverage: **86%**, unchanged 80% gate.
- New cohort: **117 authored cases** (25 positive, 68 negative/unresolved,
  24 adversarial), plus real-walker, source-scope, inline-ignore, stable-anchor,
  redaction, parser-limit, dense-local-binding and Python/Node JSON/SARIF checks.
- All five MCP tools passed from source and fresh tarballs on Node 24.22.1,
  SDK 1.32.1 and Zod 3.25.76 / 4.6.7 with **no peer skips**. New Luau and TS
  snippets are included; original dependency metadata was restored unchanged.
- Rule assurance: **661/661 complete**, 109 realistic-negative contracts;
  552 near-miss-only contracts and the existing 419 high/critical realistic-negative
  debt remain visible. No debt baseline, thresholds or suppressions were weakened.
- High self-scan: **0 application findings / 32 pre-existing intentional test
  findings**, complete source coverage. The main scanner remains 998,712 bytes,
  below its unchanged 1,000,000-byte input ceiling.
- Existing paired corpus: 30 packages / 867 files per leg. Original 130 application
  observations and all 54 high/critical signature locations retained; the
  remediated leg has 72 observations, zero high/critical, 16 gate-medium findings,
  no blocked packages and no false-positive budget violations. Source pins,
  original positive labels and approved remediation recipes were unchanged.

### Native API probe

An isolated, authored Node 24.22.1 probe used jsonwebtoken **9.0.3** with installation
scripts disabled. An in-memory 1024-bit RSA key was rejected by default and accepted
with the explicit size opt-out; a 2048-bit key signed without the opt-out. Tokens
and keys were not logged or persisted. The HTTP constructor accepted strict,
relaxed and insecure modes and rejected conflicting option names. No listeners
or outbound requests were opened; this is option/API behavior, not an attack test.
No Luau interpreter was installed, and Roblox Studio/game execution was not used.

### Public-source compatibility replay

The [Luau manifest](../benchmarks/luau-cohort-repositories.json) pins Knit and
roblox-lua-promise (MIT, nine total source files). It records exact commits,
license hashes and case-sensitive source-tree digests. An initial scratch digest
for Knit used case-insensitive path ordering; it was independently recomputed
with the evaluator's ordinal ordering before replay. The earlier receipt is
preserved, not treated as a valid pin.

Together with the existing [six-project field corpus](../benchmarks/field-cohort-repositories.json),
the final replay covers **8 snapshots / 2,615 source files**, including 1,504 TS/JS
files. All selected-source hashes/counts were verified before and after scanning.
The six older projects retain the exact same 201 rule/fingerprint observations;
the two Luau libraries have zero observations before and after. **Zero new
observations is compatibility evidence, not a zero-FP or recall claim.** The Luau
sample is small and library-only; new rules do not fire in these public projects.
Authored positives are separate evidence. Existing unreviewed findings were not
relabelled. No downloaded project was built, imported or executed.

Metadata-only [observations](luau-typescript-observations-2026-10.json) bind the
baseline and candidate runtime-source digests and raw-report hashes. To replay
prepared source snapshots without downloading or executing them:

```sh
python scripts/eval-field-cohort.py --workspace <prepared-luau-snapshots> --manifest benchmarks/luau-cohort-repositories.json --output <new-report.json>
python scripts/eval-field-cohort.py --workspace <prepared-six-project-snapshots> --output <another-new-report.json>
```

### Performance

Same driver and fixture bytes on Windows 11 / Python 3.12.10; 1,000 files,
512 bytes/file, one warm-up, three measured sequential scans. Before is f4459ba;
after is runtime digest `1245940dcf8fdc886d7cfec46dd9afd31aadff71f019afeec12e4b3b8c240f35`.

| Profile | Median before / after | p95 before / after | Peak RSS before / after |
| --- | ---: | ---: | ---: |
| Guarded Luau remotes | 0.8621 / 0.8677 s | 0.8640 / 0.8773 s | 29.00 / 28.87 MiB |
| TS configuration | 2.3220 / 2.3393 s | 2.3490 / 2.4208 s | 29.00 / 28.98 MiB |

Both profiles produced zero findings and passed the unchanged 8-second/256-MiB
limits. The final measurements are slightly slower; no speed-up is claimed.
These small generated workloads are not representative production throughput.
`--profile luau-remotes` is now reproducible in `scripts/benchmark-scanner.py`;
its deterministic guarded fixtures have their own walker regression test.

## Review outcome and remaining work

Three bounded passes: implement and fixture-test; inspect lexical/identity edge
cases; freeze and verify. Semantic review was by the primary agent, **not an
independent security audit**. Mechanical documentation and public pin inventories
were delegated. The engineering skill required fixed budgets, paired evidence and
explicit unknowns; those constraints kept the cohort advisory and source-only.

Next valuable evidence is a broader licensed Roblox application corpus, typed
engine-reference resolution and reviewed source-to-sink flows. Do not promote
these rules to blocking based on this small compatibility sample. Native game
permissions, deployment and ownership policy still need separate validation.
No merge, release, dependency addition or version change is part of this update.
