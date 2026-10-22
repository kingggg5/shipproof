# TypeScript / JavaScript precision cohort — 2026-10-20

Status: implemented locally; advisory, not a release or independent security certification.
Baseline entering this cohort: 643 executable rules including the preceding
Roblox/Rust changes. This cohort adds 9, retires 1, and leaves **651 executable
rules** in the `SP001`–`SP682` namespace. No research slot is counted as a detector.

## Engineering contract

Keep scanning offline, read-only, deterministic and dependency-free. Do not execute
submitted TypeScript, install a compiler, contact endpoints, upload code or fetch
documentation during a scan. Preserve exit codes and default gate policy. New
findings are `L1` evidence of a local configuration/signature, always advisory;
their severity or proof floor must never promote them into a blocking result.

Use original bounded lexical checks rather than vendor rule packs. Existing JS
tokenization is reused. Configuration expressions have a 512-token bound; imports
have a 256-token bound. Last literal duplicate properties take effect. Any spread,
computed/escaped key, accessor or shorthand that could change options makes the
object unresolved. Import aliases are supported, but shadowed/escaping/reassigned
bindings are conservatively excluded file-wide.

## Source registry and decisions

Reviewed official documentation on 2026-10-20. Context7 supplied initial Node,
Prisma and Next.js evidence, then returned a monthly-quota error; remaining pages
were read directly. Community posts and model suggestions are discovery inputs,
not promotion evidence. Source claims and CWE mappings also live beside the cases
in `tests/rule_cases_v2.json`.

| Rule | Primary source | Observable boundary / limitation |
| --- | --- | --- |
| SP674 | [Next.js Image](https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowlocalip), [config file formats](https://nextjs.org/docs/app/api-reference/config/next-config-js) | Exported `next.config.js`/`.mjs`/`.ts` permits private-IP image requests. Private origins may be intentional; no reachable SSRF is inferred. Unsupported `.cjs`/`.cts`, shadowed module objects and multiple exports stay silent. |
| SP675 | [jsonwebtoken verifier](https://github.com/auth0/node-jsonwebtoken/blob/master/verify.js), [JWT time claims](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4) | Imported `verify` explicitly ignores `exp` or `nbf`. Independent lifetime enforcement and renewal workflows remain review questions. |
| SP676 | [jsonwebtoken options](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) | Explicit asymmetric-key compatibility opt-out; not a claim that signatures are wholly unchecked. |
| SP677 | [Node crypto](https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options), [NIST 2026 pre-draft announcement](https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd) | Literal AES-GCM with accepted 4/8-byte tags. NIST's proposed sub-96-bit removal is not a finalized standard. Legacy protocol bounds can be legitimate. |
| SP678 | [Node Buffer](https://nodejs.org/api/buffer.html#what-makes-bufferallocunsafe-and-bufferallocunsafeslow-unsafe) | Explicit Buffer import, positive bounded literal size, immediate full string conversion before overwrite. It does not prove external disclosure or override zero-fill runtime flags. |
| SP679 | [Node HTTP](https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener) | Imported HTTP(S) API explicitly enables parser leniency. Smuggling additionally depends on HTTP-hop behavior and a working payload. |
| SP680 | [Electron security](https://www.electronjs.org/docs/latest/tutorial/security/#6-do-not-disable-websecurity) | Direct imported BrowserWindow disables origin protections; loaded content is unknown. |
| SP681 | [Electron context isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation), [sandboxing](https://www.electronjs.org/docs/latest/tutorial/sandbox) | Node-enabled renderer also disables context isolation. Explicit/global sandbox enforcement stays silent. No renderer injection is inferred. |
| SP682 | [Puppeteer troubleshooting](https://pptr.dev/troubleshooting#setting-up-chrome-linux-sandbox) | Explicit Chrome sandbox-disabling launch argument. Firefox, computed arguments and independently supplied host isolation are not classified as proven compromise. |

Each ID also links to the corresponding [MITRE CWE](https://cwe.mitre.org/) entry
in its executable contract. CWE is a taxonomy, not evidence that a detector works.

## False-positive corrections and duplicate triage

- **Retire SP429; reserve the ID permanently.** The [Express/body-parser docs](https://expressjs.com/en/resources/middleware/body-parser/#limit)
  specify a default limit of 100 KB. An omitted `limit` does not mean unlimited
  input. SP412 remains responsible for explicitly excessive limits; do not reuse
  SP429 to create a second copy of that rule.
- **Correct SP591 in place.** [TypeScript 3.8](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-8.html#type-only-imports-and-export)
  erases type-only imports; [TypeScript 4.5](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-4-5.html#type-modifiers-on-import-names)
  adds per-specifier type modifiers. A whole `import type` declaration is erased.
  Under [verbatimModuleSyntax](https://www.typescriptlang.org/tsconfig/verbatimModuleSyntax.html),
  inline-only type specifiers can leave an empty side-effect import; these remain
  unresolved and silent here, not proven safe. A real directive prologue and a
  source-level value/side-effect import are required. Compiler elision and final
  bundle behavior are not inferred from syntax.
  The finding is a medium advisory bundling-boundary concern, not a critical
  credential-leak assertion. A framework may reject it at build time.
- **Do not promote a Prisma Unsafe-name rule.** [Prisma documentation](https://github.com/prisma/web/blob/main/apps/docs/content/docs/guides/upgrade-prisma-orm/v3.mdx)
  permits safely binding values separately with `$queryRawUnsafe`. A future SP103
  extension needs SQL argument provenance, not a suffix match on the method name.
- **Do not flag SVG enablement alone.** Next.js documents restrictive CSP and
  attachment mitigations. Merely seeing `dangerouslyAllowSVG` is insufficient.
- No new generic `any`, assertion, missing-config, empty-dependency-array or
  unchecked-fetch keyword rule was added. Existing SP599 remains the JSON
  dereference rule; JWT signature, TLS and weak-cipher IDs are not duplicated.

## Executed corpus and checks

The authored v2 cohort contains **128 cases**: 27 positives, 74 negative/unresolved counterparts
and 27 adversarial cases (9 must detect, 18 must stay silent). All are executed
through the real filesystem walker as well as the matcher contract. The 92 silent
cases are directed regression evidence, **not** an independent real-world FPR.

Additional integration tests cover all eight source suffixes, ESM/CommonJS aliases,
typed parameter shadows, property rebinding, require wrappers, unknown object
overrides, comments/strings/regexes, config exports, invalid Buffer ranges, huge
number tokens, inline ignores, stable fingerprints, JSON/SARIF, Python/Node CLI
parity and advisory gates at every severity/proof combination. SP591 tests also
cover mixed type/value imports and misleading client-directive strings.

Node v24.15.0 runtime probes separately confirmed the installed Express JSON
parser rejects oversized input at 102,400 bytes and accepts GCM tag sizes of
4/8/12/16 bytes. These probes used local in-memory data, not external endpoints.
No browser, JWT package or Next.js application was installed or executed.

The checked-in `typescript-config` benchmark profile exercises six safe Node/JWT/
Electron/Puppeteer configurations through actual `.ts` files. Windows/Python 3.12.10,
one worker, 1 warm-up, 3 measured samples, 1,000 files / 512,000 bytes:
`[2.3559, 2.2371, 2.2627]` seconds; p95 **2.36 s**, peak RSS **27.73 MiB**, zero
findings and no 8 s / 256 MiB budget failure. This is a workload-specific result,
not a speed comparison against another tool or the prior Python-only workload.

A read-only compatibility smoke also scanned the existing Apache-2.0
`alibaba/open-code-review` checkout at revision
`3d4f364e6a6dda8fec644a56cfc754f80fb432e6`: 115 selected TS/TSX files, complete file
coverage and no new-cohort findings. Its 44 other findings were not relabeled or
declared false positives. This single sample is not a clean or representative
precision benchmark. No third-party source was copied into scanner tests.

Final local verification:

| Check | Result |
| --- | --- |
| `npm run check` | Pass: lint, Node suites, 857 Python tests (3 existing platform skips), 2 demo tests, package manifest and isolated packed-artifact smoke |
| Required self-scan `--fail-on high` | Exit 0, 448 scanned files, 0 application findings, 32 existing test-scope findings, complete file coverage |
| Rule assurance | 651/651 complete; no partial, uncontracted or metadata debt; 93 rules with realistic negatives, 558 with only near misses, 423 high/critical realistic-negative debt |
| Contract freshness | TypeScript, Roblox/Rust and both legacy generators pass `--check` |
| Package | 111 files; existing 500,000 packed / 1,870,000 unpacked byte limits retained and passed |
| Diff whitespace | Pass |

These are local checks, not remote CI results. No commit, push or release was made.

Passing these checks must not be described as eliminating all false positives.
The broader assurance inventory still reports legacy realistic-negative debt.
QA here is same-agent self-review with separately executed checks, not an
independent human or isolated-agent review.

## Remaining limitations and next useful cohort

This is not a TypeScript compiler or general dataflow engine. Interpolated template
contexts, ambiguous JSX/regex syntax, generic calls, imported wrapper functions,
dynamic configurations and large/unresolved expressions are outside the new local
signatures. Other uses of an imported binding can conservatively suppress a check.
File-completeness metadata is not a guarantee that every language construct was
understood. Existing rules keep their own suffix and framework applicability.

Next: label findings on revision-pinned real TypeScript applications before any
blocking promotion. Prioritize precision review of existing Express version
semantics and Next.js/React boundaries, then one shared source-aware SQL extension
for Prisma/Drizzle/Knex rather than multiplying query-name rules. Keep production
runtime/compiler evidence optional and explicitly consented.
