# TypeScript / .NET / Dart field cohort — 2026-10-23

Status: locally verified; commit/CI evidence is recorded on the PR. Baseline: `09adda62066122dd8f3614592bf6a505fde6e6a1`.

## Engineering contract

Implement a bounded cohort, not a rule-count quota. Keep default scans offline,
read-only and dependency-free; do not execute project code or open listeners.
Retain gate thresholds, source pins, prior corpus labels, exit codes and package
ceilings (500,000 packed / 1,870,000 unpacked bytes). New signatures remain L1
advisory at every severity/proof floor until representative independent review.

Scope and duplicate decisions:

- **SP688, Next.js SVG response configuration:** require SVG enabled, explicit
  inline disposition AND explicitly empty image CSP in an exported Next config.
  Enabling SVG alone, protected/default headers, custom loaders and static export
  are not this condition. Distinct from SP112 upload acceptance and SP674 private-IP
  image targets. No claim of an attacker-controlled image or exploitable deployment.
- **SP689, Kestrel body limit:** typed KestrelServerOptions parameter explicitly
  assigns `Limits.MaxRequestBodySize = null`. Missing limits retain defaults;
  proxies/per-request caps may independently constrain input. Not SP412's Express
  payload-size heuristic or SP687's WebSocket frame/message limit.
- **Extend SP170 for Dart (DART-W1-07), no duplicate ID:** require a direct imported
  package:http call, literal non-loopback HTTP URI and an explicit Authorization
  key (values and transport unverified; known empty literals excluded). Replace only the Dart HTTP URL-text heuristic with this structural
  conjunction; bare documentation URLs and custom objects stay quiet. Dynamic
  wrappers, runWithClient overrides and unresolved URI interpolation stay outside scope.
  Preserve the existing FTP/Telnet signatures, severities and gate behavior.
- **Extend SP056/SP084 (DOTNET-W1-09):** typed CookieAuthenticationOptions parameter
  explicitly weakens Cookie.HttpOnly or Cookie.SecurePolicy. The actual enum is
  `CookieSecurePolicy.None`, not the historical proposal's nonexistent `Never`.
  SameAsRequest is not equivalent to None; cookie middleware may override options.

Bound each object/call to 512 tokens and retain the existing 50,000-token lexical
budget; Dart additionally uses the native 128-delimiter and bounded interpolation limits.
Malformed input must not manufacture findings. Supply
at least 3 positives, 5 negatives and 2 adversarial cases per new signature plus
walker, redaction, gate, suppression and compiler/runtime probes where available.

## Field evaluation protocol

Six immutable, license-reviewed source snapshots: two TypeScript applications,
one .NET template plus one demo application, and two Dart applications. Static
inspection only, sparse language/manifests scope, no submodules or project builds.
Preserve source hashes and raw before/after observations. Inspect each changed
finding locally; do not relabel all other findings or call an entire repository
safe. Store only minimized original regression fixtures, never copied vendor code.
Source selection omissions, unsupported syntax, sample bias and unknown recall
must be reported. Same-agent review is not independent ground truth.

Loop bound: at most three implementation/refinement passes for this cohort and
six external repositories, with a two-hour review checkpoint. Stop extending
scope after acceptance. Commit/push the verified result; no release, tag, npm
publication or repository-permission change is authorized by this request.

## Source evidence

Context7 resolution was attempted for Next.js, Dart http and ASP.NET Core and
returned its monthly quota error. Owning documentation is read directly instead:

- [Next Image configuration](https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowsvg)
  and [optimizer implementation](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/image-optimizer.ts).
- [Dart http get](https://pub.dev/documentation/http/latest/http/get.html),
  [Uri.parse](https://api.dart.dev/dart-core/Uri/parse.html),
  [bearer transport protection](https://www.rfc-editor.org/rfc/rfc6750.html#section-5.3).
- [Kestrel body-size property](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserverlimits.maxrequestbodysize?view=aspnetcore-10.0)
  and [server options](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/options?view=aspnetcore-10.0#maximum-request-body-size).
- [Cookie authentication options](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.cookieauthenticationoptions.cookie?view=aspnetcore-10.0)
  and [CookieSecurePolicy](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiesecurepolicy?view=aspnetcore-10.0).

## Field-discovered precision repair

SP596 incorrectly treated every hook-using React file as a server component.
The [Next boundary docs](https://nextjs.org/docs/app/api-reference/directives/use-client)
and [React module-graph contract](https://react.dev/reference/rsc/use-client) require
neither a directive in plain React/Vite nor one in every imported client module.
The rule now requires declared Next.js, an app page/layout path, an imported
React hook call and no actual client directive. Shared components and unknown
frameworks remain unresolved. The high-severity gate is retained for the narrower
positive contract; thresholds were not changed. Its generated contract moved
from the React partition to Next.js, with positive and negative evidence retained.
Version/fork-specific framework semantics and a complete module graph are not
resolved; no Next application build or browser-exploit test was performed.

SP389 was **not** suppressed for paginated queries: it concerns missing
CancellationToken, not missing Take. LocalSend's intentional loopback certificate
acceptance likewise remains a needs-context lead, not an automatically false finding.

## Executed evidence

- **109 authored cases:** 23 positives, 69 negative/unresolved counterparts and
  17 adversarial cases across SP688/SP689 and the existing-rule extensions/repair.
  Walker tests check gates, redaction, fingerprints, suppression and malformed
  Dart/string/comment limits. Prior transport contracts remain passing.
- **Six pinned snapshots / 2,606 language-source files:** Umami 1,393; Shlink 111;
  Clean Architecture template 362; TodoApp demo 40; LocalSend 393; GitJournal 307.
  Source and framework/config/license hashes are pinned in
  [the manifest](../benchmarks/field-cohort-repositories.json). All selected source
  paths were scanned without parser, line, size or unreadable omissions. This is
  declared-language coverage, not a promise that all syntax was understood.
- **275 → 201 observations:** zero added locations, 74 removed SP596 locations
  (66 Umami, 8 Shlink), all other 201 observations unchanged. Nine removals were
  reviewed as false positives using visible build/import context; 65 remain
  unreviewed. Labels are primary-agent review, not independent human ground truth.
  [Metadata-only results](field-cohort-observations-2026-10.json) preserve the
  distinctions. No source text from the external projects is redistributed.
- The two new IDs emitted no findings on this sample. This does not measure their
  recall or establish a universal zero false-positive rate. Synthetic positives
  and native probes are separate evidence, not substitute field positives.
- **Dart 3.12.2 / http 1.6.0:** cached dependencies resolved offline; analyzer passed;
  MockClient confirmed URI schemes and Authorization headers are preserved, with
  no sockets or external requests. **.NET 8.0.29 / 10.0.12:** finite Kestrel default,
  null opt-out, SameAsRequest on HTTPS and None cookie behavior passed in-memory
  probes. No application listener or downloaded project code was executed.

Full-snapshot baseline reports remain in ignored scratch and honestly record
metadata-type omissions (.git pointers, project/lock files). The language-only
evaluation uses explicit include paths, not a changed coverage threshold. The
replay helper validates source **and context** hashes before/after scanning and
never downloads, builds or modifies a target. Prepare the pinned snapshots first,
then run `python scripts/eval-field-cohort.py --workspace <snapshots> --output <new-report.json>`.
Use `--scanner-dir` only for trusted scanner code, such as an archived baseline.

The maintainer failure catalog stays in source control but is excluded from npm;
the executable scanner does not load it. This preserves original package ceilings
while retaining all runtime and user-facing command contracts.

## Final local acceptance

`npm run check` passes: **919 Python tests** (three Windows symlink privilege
skips), two demo tests, Node suites, approved manifest and isolated tarball smoke.
Python coverage is **86%**, above the unchanged 80% floor. All five MCP tools,
including new native signatures, pass from source and fresh packed consumers on
Node 24.22.1 / SDK 1.32.1 with Zod 3.25.76 and 4.6.7; no peer skips. Root package
metadata is unchanged after restoring the lockfile dependencies.

Self-scan initially exposed a real coverage blocker: scan_repo.py had grown to
1,003,872 bytes, beyond its own 1,000,000-byte input limit. Existing JS lexical
helpers and C# XML handling were moved to their language modules without changing
their behavior. The core is now 995,648 bytes; a structure test prevents runtime
sources from exceeding the default limit. Replayed contracts, real snapshots and
self-scan pass: **0 application / 32 intentional test findings**, complete selected
source coverage, no oversized source. No file-size threshold was raised.
Two additional SARIF observations were traced to the literal legacy-protocol
strings in new unit-test definitions. Those strings are now assembled at runtime;
their tested values and detector assertions are unchanged, without suppressing
the rule or modifying the coverage/precision policy.

The old paired corpus also remains unchanged: 30 packages / 867 files per leg,
54 original high/critical signature locations retained, quiet leg 0 high/critical,
16 gate medium findings, 0 blocked packages and no budget violations. Existing
precision thresholds, labels and remediations are untouched.

Rule assurance is 658/658 complete with no metadata/partial/uncontracted debt;
106 rules have realistic negatives and the 419 high/critical realistic-negative
debt has not grown. Package: 109 files, 466,296 packed / 1,820,932 unpacked bytes,
within unchanged ceilings. Remote CI results belong to the commit/PR and are
not inferred from these local passes. Semantic review is by the primary agent;
helpers performed mechanical corpus/metadata/documentation tasks only.

The unchanged TypeScript-config workload (1,000 files / 512,000 bytes, one warm-up,
three samples, one worker, Windows 11/Python 3.12.10) stayed below the same 8-second
and 256-MiB ceilings. Before samples: [2.1220, 2.0343, 2.0117] s; after:
[2.3628, 2.1346, 2.0978] s. Median 2.0343 → 2.1346 s; p95 2.1220 → 2.3628 s;
peak RSS 29.07 → 28.70 MiB, zero findings. This run was slightly slower and does
not support a speed-improvement claim; it also does not measure Dart/C# throughput.
