# Roblox/Luau and Rust cohort — 2026-10-20

Implementation baseline: `dd589b5`. New executable IDs: SP671–SP673;
existing-family extension: SP104. These checks read local source and have no
Roblox Studio, network, compiler, or project-code execution dependency.

## Scope and evidence contract

| ID | Observed local condition | Deliberate silence / limitation |
| --- | --- | --- |
| SP671 | A local HttpService binding feeds GetAsync's response straight to loadstring and immediately invokes the compiled function. | Require one declaration/one use; no alias propagation, response variables, long argument expressions or compilation-only calls. HTTP and LoadStringEnabled permissions are unknown. |
| SP672 | An untyped two-parameter OnServerEvent callback's entire body immediately executes its client data parameter using loadstring. | Guarded, typed, nested, aliased and reassigned flows are unmodeled; no claim that absence of a match establishes authorization or safety. |
| SP673 | A direct fully qualified std/core mem::zeroed call explicitly requests a reference type. | Raw pointers, integers, Option references, MaybeUninit storage, module shadowing and complex nested generics stay outside the signature. |
| SP104 extension | A direct fully qualified reqwest Client builder reaches build() with a final literal true for certificate/hostname acceptance. | False or unknown overrides an earlier true; imported Client aliases and detached builder assignments are unmodeled. |

The new checks emit structural L1 evidence and remain advisory in runtime
policy, including lowered severity/proof thresholds. Severity is medium for
new IDs; this does not assert a low impact if remote code execution is actually
reachable. Runtime gate promotion requires representative labels.

## Correctness repairs included

- Remove the incorrect SP104 branch treating Dart `withTrustedRoots: false`
  as a verification bypass; it creates an initially empty/custom trust store.
- Enforce the documented advisory status of SP666–SP670 in precision policy.
- Preserve historical release counts from the actual 0.10.0–0.11.2 tags;
  live registry counts no longer rewrite those artifact histories in tests.
- Lua/Luau generic foreign-language patterns are not enabled automatically;
  initial coverage comprises its own signatures plus provider-secret checks.
- Lexical input limits and unfinished comments/strings report parser_limit
  instead of producing a complete clean result.

## Primary sources reviewed

Official documentation/source was queried through Context7 on 2026-10-20.
Implementation and fixtures are original; no external detector pack was copied.

- [Roblox client/server boundary](https://create.roblox.com/docs/scripting/security/client-server-boundary): client data must be validated on the server; distinguish Player from user data.
- [Roblox loadstring](https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#loadstring) and [script capabilities](https://create.roblox.com/docs/scripting/capabilities): compilation/invocation and server permissions are separate prerequisites.
- [Rust zeroed](https://doc.rust-lang.org/std/mem/fn.zeroed.html): constructing an all-zero reference violates reference validity.
- [Reqwest ClientBuilder](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html): certificate and hostname verification switches, including compatibility spellings.
- [Dart SecurityContext](https://api.dart.dev/dart-io/SecurityContext/SecurityContext.html): trusted-root population is distinct from unconditional certificate acceptance.
- CWE-94, CWE-494 and CWE-665 supply classification; the owning API defines the observable condition.

## Verification and maintenance

Authored v2 cases: at least 3 positive, 6 negative and 3 adversarial per new ID.
`tests/test_roblox_rust.py` executes them through temporary repository scans and
checks anchors, fingerprints, advisory gating, strings/comments, lexical limits,
JSON/SARIF, override order, scope and generator consistency. This is self-review;
representative-repository precision and live Roblox runtime behavior remain open.

Historical release notes remain in the source repository and are omitted from
the npm artifact to make room for executable code within the existing package
budgets. The new runtime companion is explicitly allowlisted.

Follow-up: broaden safe import/type resolution, typed Luau callbacks, real
RemoteEvent ownership, guarded source flows and representative Rust/Roblox
corpora before widening signatures or gate eligibility. SP670 XML semantics
and SP668 syslog argument handling from the long-term plan remain separate work.

## Local verification — 2026-10-20 working tree

- `npm run check`: exit 0; Python 843 tests (3 platform skips), demo 2 tests,
  Node suites, lint, exact package allowlist and packed-artifact smoke all pass.
- The 10-test Roblox/Rust suite includes 38 authored walker cases, CLI/Python
  parity and threshold/override regressions. No new rule is asserted to have
  representative real-world precision from these authored cases.
- Required direct `scan_repo.py . --fail-on high`: exit 0; 445 selected files,
  0 application findings, 32 test findings; completeness true, no limit/errors.
- Generated clean workload: 1,000 files / 128,000 bytes, jobs 1, warm-up 1,
  samples 3; median 1.1724s, p95 1.2005s, peak RSS 28.78 MiB; zero findings;
  8s / 256 MiB budgets pass (Windows 11, Python 3.12.10).
- npm artifact: 113 files, 484,998 packed bytes, 1,849,565 unpacked bytes;
  existing size ceilings retained.
- Lua provider-secret probe still redacts credential evidence and blocks at
  the high gate, independently of advisory-only game checks.

Verification used normal isolated system temp directories after the restricted
Windows temp environment produced unrelated filesystem/Git-identity failures.
Assertions were retained. Remote CI, live Studio execution, Rust compilation
and Miri were not run for this uncommitted working tree.
