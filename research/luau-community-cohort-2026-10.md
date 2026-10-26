# Luau community/source cohort — 26 October 2026

## Engineering contract

- Baseline: clean b7477f854286d5c89a5aa0af989917472b2650da, 667 executable
  rules, 970 Python tests/87% coverage, green CI16/16, Security and Benchmarks.
- User requested Luau additions and multi-source research including Reddit.
  Community reports identify failure questions; owning docs/source establish
  semantics. Do not copy third-party detector packs or project implementations.
- Six selected advisory families: SP708 reversed literal numeric bounds, SP709
  nil-returning in-place table operation used as a table, SP710 mutation of a
  just-frozen table, SP711 noncallable result passed to task scheduling, SP712
  direct yield inside a native DataStore UpdateAsync transform, SP713 unsupported
  native signal timeout. Extend SP707 persistent-key authorization for direct
  RemoveAsync/IncrementAsync without creating variant IDs.
- Source-only scope: standard-library runtime, read-only/offline defaults, no
  dependency/tool installation, target code execution, live Roblox/Studio/game
  mutation, network probes, permissions, merge or release. No native Luau runtime
  is installed; vendor source and authored contracts do not become a native-game
  execution claim. Context7 resolution failed on quota; official pages are used.
- Each addition needs >=3 positive/5 negative/2 adversarial original cases,
  source/CWE/remediation/FP boundary, real walker, bindings/shadows/opaque data,
  scope/ignores/anchors/privacy, all advisory floors and CLI/JSON/SARIF/MCP parity.
- Keep existing thresholds, source pins, original/remediated labels and all54
  required original high/critical signatures. Two new source-only projections:
  ProfileStore and RbxUtil, pinned commit/license/context/digests, <=2500files/
  25MB each. These are libraries, not deployed-game precision/recall evidence.
- Preserve 1MB/50k-token limits and 500000/1870000 package ceilings. Compare
  identical 1000-file/512-byte fixtures, 1 warm-up/3 samples, jobs1, 8s/256MiB.
  Three bounded implementation/review passes, checkpoint90minutes; stop after two
  no-progress passes. Cache: .cache/luau-research-20261026/. Commit/push remains
  authorized; version0.12.0 and PR49 are reused. No executable-rule count target
  overrides source semantics or meaningful safe counterparts.

## Research disposition

Reddit, DevForum, Stack Overflow, Luau RFCs, GitHub issues/implementation and
official Roblox/Luau documentation are separate evidence types. Equal random
bounds are valid; a community claim to the contrary must not become a rule.
Scheduling APIs return threads, not the generic resume-function description seen
in one discussion. Shallow cloning/freezing, missing WaitForChild nil guards,
missing waits/disconnects and generic client input are not promoted on keywords:
their safety depends on ownership, lifecycle or dataflow not established here.

## Source review

The [20-source inventory](luau-community-sources-2026-10.json) records URL, year,
source kind and disposition. It includes Reddit, Roblox DevForum, Stack Overflow,
GitHub implementation/issue pages, a Luau RFC and owning documentation. Most
community leads are from 2021–2026; the 2019 sort question is explicitly historical.
No post, vote count or model suggestion establishes detector accuracy.

| Family | Community discovery | Owning basis / chosen boundary |
| --- | --- | --- |
| SP708 | [Reddit 2022 random bounds](https://www.reddit.com/r/robloxgamedev/comments/zc7up9/), [DevForum 2021 clamp](https://devforum.roblox.com/t/playermodulecameramoduletransparencycontroller-invalid-argument-3-to-clamp/1131588) | [Native math implementation](https://raw.githubusercontent.com/luau-lang/luau/master/VM/src/lmathlib.cpp): ordered decimal signed-32-bit integer limits. Equal bounds stay silent. Computed/fractional/large values are not inferred. |
| SP709 | [Historical sort return question](https://stackoverflow.com/questions/57064238/calling-table-sort-returns-nil) | [Native table implementation](https://raw.githubusercontent.com/luau-lang/luau/master/VM/src/ltablib.cpp): sort/insert/clear return no table. Only direct indexing, length or native iteration consumption is supported; ordinary in-place use and returned-table APIs are distinct. |
| SP710 | [DevForum 2022 immutability](https://devforum.roblox.com/t/how-to-define-immutable-constant-variables/1626919) | [Luau library](https://luau.org/library/#table-library), [clone RFC](https://rfcs.luau.org/function-table-clone.html): direct top-level write to a fresh frozen literal, or its unique simple same-region local. Nested children and mutable copies stay silent. This is not deep-freeze analysis. |
| SP711 | [DevForum 2023 scheduler arguments](https://devforum.roblox.com/t/how-to-force-for-iv-to-start-a-function-but-not-wait-for-it-to-finish-and-keep-looping/2565641), [Reddit 2026 scheduling discussion](https://www.reddit.com/r/robloxgamedev/comments/1vcool6/this_is_probably_really_inefficient_in_some_way/) | [Task API](https://create.roblox.com/docs/reference/engine/libraries/task): recognized noncallable builtin results in the function/thread slot. Function values, closures, coroutine values and unknown factory returns are not guessed. |
| SP712 | [DevForum 2021 UpdateAsync](https://devforum.roblox.com/t/how-to-properly-utilize-updateasync/1133216) | [Owning reference source](https://raw.githubusercontent.com/Roblox/creator-docs/main/content/en-us/reference/engine/classes/GlobalDataStore.yaml): a native transform cannot yield. Supported inline transform begins with task.wait/wait then returns. Nested/dynamic control flow stays unknown. |
| SP713 | [DevForum 2022 signal waits](https://devforum.roblox.com/t/what-is-better-repeat-until-or-eventwait/1990098) | [Native signal reference](https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal): no timeout parameter. Only supported native Players/RunService or fresh BindableEvent/RemoteEvent signals and a positive integer duration; custom Signal libraries stay silent. No actual hang is demonstrated. |

The Reddit equal-random-bound claim is rejected rather than turned into an alert.
The fractional random example is only a discovery lead for this integer-only
signature. A type-solver frozen-indexer issue is routed to compiler analysis,
not described as a runtime readonly bypass. The detailed inventory preserves these
distinctions and deferred questions instead of counting every link as a new rule.

## Implementation and precision limits

- SP708–SP713 are medium, L1 structural, explicitly advisory at every severity/
  proof floor. SP707 reuses its persistent-key authorization family for direct
  client-selected RemoveAsync/IncrementAsync; it does not prove record corruption,
  correct value types, remote exposure or a private rather than shared-store policy.
- The original bounded lexer keeps quoted/long/interpolated data opaque. The new
  module reuses paired delimiters, per-file name positions and bounded arguments.
  Visible shadows/changed globals, getfenv/setfenv and escaped names invalidate
  native assumptions. This is not a general Luau compiler or interprocedural engine.
- Local receiver resolution is intentionally narrow: unique unescaped names,
  constructor before use and a conservative block-region check. Read aliases,
  functions/wrappers, complex scope/type syntax and computed expressions can be
  missed. A silent unsupported case is not labeled safe. Ordinary Lua embeddings
  with different host globals also need review of the stated Luau API assumptions.
- Transform pcall wrappers are outside the direct signature; error catching does
  not authorize persistent keys or make yielding valid. Existing wrong-family
  keyword detectors are not added to compensate for missing flow evidence.
- Six semantic families are six IDs; API spellings and persistence variants are
  not counted as extra rules. Default operation remains offline/read-only and
  uses only the standard library. The approved runtime module is shipped so CLI,
  Action and MCP share the implementation and offline explanation metadata.

## Executed validation

The authored cohort has **132 cases**: 40 positive, 65 negative/unresolved and
27 adversarial, including the SP707 variants. The six new IDs account for 118;
the 14 remaining cases extend SP707. All run through the real filesystem walker
with target execution forbidden. Both suffixes, shadows, opaque literals, range
limits, block escapes, line/fingerprint movement, inline ignores, test scope,
minimal reports/fix prompts and Python/CLI/JSON/SARIF parity are checked. Existing
Roblox/Rust, Luau/TS and I/O regressions still pass. Official-SDK MCP exercises all
six new families; peer matrices are checked on the pushed commit.

No Luau interpreter/Lupa was available locally, and none was installed. No Roblox
Studio session, game or DataStore was accessed. Native language/API execution is
therefore not claimed: evidence is the vendor implementation/reference plus
executed scanner contracts and compatibility observations. A future scoped game
test harness must retain that boundary rather than execute downloaded projects.

## Public-source comparison

The [manifest](../benchmarks/luau-community-cohort-repositories.json) adds all regular
Lua/Luau files from two pinned source exports, verified byte-for-byte against Git
blobs with license/context/tree hashes:

| Library | Revision | License | Files / bytes |
| --- | --- | --- | ---: |
| MadStudioRoblox/ProfileStore | 45c9847cbcf1fc260369c50eb335aba7c35aecdd | Apache-2.0 | 2 / 83,363 |
| Sleitnick/RbxUtil | 31f9120fca021e3dec275b42bc7047d626962082 | MIT | 69 / 417,310 |

With the unchanged Knit/roblox-lua-promise pins, the Luau sample is **four
libraries / 80 files**, all complete and no new observation sites. These are not
deployed games and do not establish recall or a zero-FP rate. No third-party code
was copied into tracked fixtures and no source project was built or executed.

Across all [receipts](luau-community-observations-2026-10.json): **12 repositories /
13 projections**, 3,614 selected / **3,613 scanned** files; twelve projections are
complete. The existing FastAPI Python3.14 syntax omission remains explicit under
local Python3.12.10 (INCOMPLETE/exit2). Observations remain **544 → 544**, no
added/removed sites or relabeling. Umami TS/SQL are two projections of one repo.

The original/remediated 30-package benchmark preserves 867 files per leg, all54
required original high/critical signatures, labels, source pins and recipes.
Original: 130 app observations and chi intentionally blocked. Remediated: 72,
zero high/critical/blocked packages and 16 gate-eligible medium observations. The
existing precision-trend/FP budgets pass without lowering thresholds.

## Local gates and cost

| Check | Result |
| --- | --- |
| npm run check | Pass: 978 Python tests (3 Windows privilege skips), two demo tests, Node suites, allowlist and isolated CLI/Action/two-skill smoke |
| Python branch-aware coverage | Fresh full run: 87%, existing 80% floor retained |
| High self-scan | Complete; zero app /32 existing test findings; no suppression/parser/size omissions |
| Assurance | 673/673 complete; 128 realistic negatives, 545 near-miss-only, 409 high/critical realistic-negative debt |
| Package | 112 files, 483,455 packed /1,869,253 unpacked bytes; original 500,000/1,870,000 ceilings retained |
| Freshness / paired trend / whitespace | Pass |

The initial full suite found stale current-count prose; it was corrected to the
derived 673 registry count without changing tests or thresholds. The subsequent
full check passes. Historical cohort and release counts remain unchanged.

Comparable Windows11/Python3.12.10, jobs1, 1,000 files/512,000 bytes, one warm-up /
three samples, identical fixtures before/after and before other validation workers:

| Workload | Baseline samples, median / p95 s | Candidate samples, median / p95 s | Peak RSS MiB before / after |
| --- | --- | --- | --- |
| guarded Luau + safe API contracts | [0.9366,0.9156,0.9185], 0.9185 /0.9366 | [1.1902,1.2620,1.1959], 1.1959 /1.2620 | 28.57 /28.53 |
| typescript-config | [2.4062,2.2082,2.1556], 2.2082 /2.4062 | [2.2404,2.2229,2.1668], 2.2229 /2.2404 | 28.42 /28.52 |

Both are finding-free and pass 8s/256MiB. Luau has measured additional cost from
the new checks; no speed-up is claimed. The existing luau-remotes fixture now also
contains safe numeric/table/scheduler/store/signal counterparts; its digest is
db778fb24405d6249fff1e5d72df0056c8c53afe80b1f18f97632943bcfa4458.
Only the fixture driver is copied to the frozen baseline; runtime bytes stay
unchanged. Candidate runtime-source digest:
73bec40c62c4f6bcf494984d18aa205694985c6e1e8ef34d14996064e45e3668.

At the checkpoint selected code and source review are complete; commit/push and
exact-head CI remain. QA is primary-agent semantic review with executed checks,
not an independent security audit. Fast-agent work was mechanical Git export,
manifest/doc updates. Version0.12.0 is unchanged; no merge/release is included.
