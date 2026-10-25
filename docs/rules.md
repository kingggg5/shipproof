# Detection rules reference

ShipProof applies 667 deterministic executable rules (`SP001`-`SP701`, with deliberate reserved gaps). This shipped guide describes boundaries and ecosystem mapping; the complete source catalog is linked below.

Every finding carries an evidence `proof_level`: `L0` means a pattern match, `L1` means structural evidence (Python AST, whole-file structural analysis, or an inspected artifact such as a SQLite header), and `L2` marks taint-engine flows (the shipped interprocedural engine covers Python and, since 0.8, JavaScript/TypeScript route-to-sink chains via `--cross-file`). ShipProof does not claim runtime exploitability. Only the entries in these tables are executable rules; research catalogs are planning inputs and cannot emit findings.

Run `shipproof explain SP108` for why a rule exists, its attack scenario, false-positive boundary, and regression-test guidance.

`SP136` remains a low-confidence regex signature for an explicit `_ = err` assignment. It does not infer Go types or identify an error return from tuple arity.

`SP346` now uses Python AST context and is limited to an import-bound standalone
`asyncio.create_task(...)` expression that is not awaited, returned, or assigned.
Its existing severity and eligibility remain. `SP348` is retired and its ID will
not be reused: `ThreadPoolExecutor` supplies a bounded default worker count, so
omitting `max_workers` alone is not an unbounded-pool signal. `SP375` reports
`SetMaxOpenConns(0)`; `SetMaxIdleConns(0)` retains no idle connections and does
not disable the open-connection cap. Its legacy name-only `db` receiver match
otherwise remains.

`SP666`–`SP687` are runtime advisory findings pending representative-repository
review; lowering the severity or proof floor does not make them blocking.
`SP688`–`SP701` are additional source-level advisories with their own bounded
syntax below; none establish deployment behavior or exploitability.
These cohorts, `SP591` and advisory Rust TLS evidence expose only normalized risk
details. Unrelated arguments/comments and neighboring source are omitted from
report and fix-prompt contexts to avoid credential echo. Inspect the local source
at the reported location; affected fingerprints can change across this boundary.
The Rust reqwest extension of `SP104` is also advisory and recognizes a fully
qualified `reqwest::[blocking::]Client::builder()` chain ending in `build()`;
the final literal value of each TLS switch controls the result.

The JS/TypeScript cohort `SP674`–`SP682` requires exported Next.js configuration
or direct runtime ESM/semicolon-delimited const-require bindings, balanced lexical
context and literal effective options. It supports `.js`, `.jsx`, `.mjs`, `.cjs`,
`.ts`, `.tsx`, `.mts` and `.cts`; older detectors retain their own suffix lists.
Comments, strings, regular-expression literals, type-only imports, local shadows,
binding escapes and safe duplicate-property overrides do not establish evidence.
Spreads, computed/escaped keys, accessors, interpolated templates, wrapper APIs,
large expressions and unresolved syntax stay outside these signatures. Silence
is not a TypeScript compiler result or proof that the application is safe.
The Next.js signature accepts only `next.config.js`, `.mjs` and `.ts`; shadowed
CommonJS module objects, multiple exports and unsupported config extensions stay
silent rather than being treated as deployed image configuration.

`SP676` also covers imported `jsonwebtoken.sign` calls when an explicit RS/PS/ES
algorithm and `allowInvalidAsymmetricKeyTypes: true` occur without header overrides;
verification retains its existing boundary. `SP679` additionally recognizes
`httpValidation: 'insecure'` on supporting Node versions. Strict/relaxed modes and
conflicting legacy switches stay silent. Neither check establishes runtime behavior.
`SP692` requires imported `jsonwebtoken.sign`, `allowInsecureKeySizes: true`, an
explicit RS/PS algorithm, and no header override. It does not inspect the actual
RSA key strength and remains advisory.

`SP596` is limited to a declared Next.js project with an app page/layout entry,
an imported React client hook call, and no actual client directive. Shared
components and ordinary React files do not each require their own directive;
this is not a complete client/server module-graph analysis.

`SP591` is a medium advisory for an explicit client-module/value-import boundary,
not a confirmed credential leak or compiled-bundle result. Whole `import type`
declarations are excluded; inline-only type imports remain unresolved because
`verbatimModuleSyntax` can retain an empty side-effect import. `SP429` is retired
and its ID will not be reused: Express JSON parsing
has a default body-size limit, so omitting an explicit option is not evidence of
an unbounded parser. Oversized explicit limits remain covered by `SP412`.

Luau and Rust additions use a bounded lexer to exclude quoted/long/raw strings
and comments, including nested Rust comments. Unterminated lexical input or
exceeding 50,000 tokens records `parser_limit` in the completeness ledger.
Luau interpolated strings stay wholly opaque, including nested backticks; their
expressions are not analyzed. Nesting beyond 32 strings or 128 braces records
`parser_limit`. Aliases and complex Rust types remain outside these
signatures; a silent result does not establish their safety. For `SP672`, simple
optionally typed parameters and `OnServerInvoke` are supported, with the optional
return accepted in either callback form; event ownership remains unresolved.
New `SP690`/`SP691` signatures require a locally constructed `Instance.new`
RemoteEvent/RemoteFunction, one unescaped receiver/handler, two simple optionally
typed parameters, and a single direct sink statement (`require` or `Destroy`).
Guards, aliases, custom or type-only-reference receivers, and complex parameters
remain unresolved. These are advisory checks, not deployment evidence. No
submitted source is executed by these checks.

Go deadline/cancellation and Rust route-context checks share the bounded native
lexer (50,000 tokens, 128 delimiter levels). Go comments do not nest; Rust comments
do. Dynamic configuration, custom bindings, complex imports and unsupported
route forms are unresolved. `SP212` recognizes bare environment-dump commands in
step `run` scalars, not YAML metadata, command arguments or heredoc data.

`SP631` requires an explicit literal Edge runtime declaration and a native runtime import. It does not classify ordinary Node.js serverless code, comments, quoted examples, or type-only imports as Edge execution. Its boundary follows the official [runtime configuration](https://github.com/vercel/next.js/blob/canary/docs/01-app/03-api-reference/03-file-conventions/02-route-segment-config/runtime.mdx) and [Edge API limitations](https://github.com/vercel/next.js/blob/canary/docs/01-app/03-api-reference/07-edge.mdx), checked through Context7 on 2026-09-04. This local structural check does not resolve computed/multiline declarations, ambiguous JSX/template contexts, build-time polyfills, or deployment settings.

## Transport and cookie options

`SP686`/`SP687` are medium, nonblocking structural advisories. Imported Node
TLS/HTTPS options selecting TLS 1.0/1.1 do not prove a successful handshake.
For imported `ws` server constructors, literal `maxPayload` zero or a bounded
decimal integer becoming nonpositive after signed-32-bit conversion disables
the cap; omission has a finite default. Unknown overrides remain unresolved.

Existing `SP056`/`SP084` gain an additional C# variant, not new IDs: a typed
`CookieAuthenticationOptions` parameter explicitly assigns `false` to
`Cookie.HttpOnly` or `CookieSecurePolicy.None` to `Cookie.SecurePolicy`. These
local options may be overridden by middleware. Dart HTTP coverage of `SP170`
requires imported `package:http`, a literal external HTTP URI and an explicit
Authorization key. Header values and transport remain unverified. This variant
is advisory; bare HTTP URL text and custom objects stay quiet. Existing FTP/Telnet
signatures are unchanged. See the
[source and boundary record](https://github.com/kingggg5/shipproof/blob/main/research/field-cohort-ts-dotnet-dart-2026-10.md).

`SP688` and `SP689` are medium, nonblocking structural advisories. `SP688` requires
an exported Next.js image configuration that enables SVG, sets inline content
disposition, and explicitly empties image CSP together. It does not establish
attacker control or deployed response behavior. `SP689` requires a typed
`KestrelServerOptions` parameter explicitly assigning
`Limits.MaxRequestBodySize = null`; omission retains defaults, and proxy or
per-request limits may still apply. The field cohort has bounded source scope;
results do not imply zero false positives or final precision/performance counts.
See the [field-cohort research record](../research/field-cohort-ts-dotnet-dart-2026-10.md).

## Broad quality cohort — 2026-10-23

`SP693` requires directly imported Node HTTP(S) server options with both literal
`requestTimeout: 0` and `headersTimeout: 0`; upstream and per-request bounds remain
unknown. `SP694` requires a direct await of a literal empty array passed to native
`Promise.race`, or to Dart `Future.any` with explicit `dart:async` import. Standard
Promise methods need no import; wrappers, inferred/custom bindings and complex
syntax are unresolved. `SP695` is limited to a literal array with at least two
elements and a simple sort callback whose comparator returns only a boolean.

`SP696` requires inline settings passed directly to `XmlReader.Create`, with DTD
parsing enabled, entity-character limit zero and no finite document-size cap. It
describes internal entity-expansion limits, not proof of external entity access.
`SP697` requires directly imported `logging.config.listen`, a literal valid port,
`verify=None` and immediate `start()`. The standard listener binds to loopback;
this does not prove remote code execution. `SP698` requires a directly awaited,
imported Node synchronous zlib call; input size and actual work remain unknown.
All six are medium advisory findings and do not establish deployment behavior.
The cohort evaluation is pending; no test or performance metrics are claimed. See
the [cohort record](../research/broad-quality-cohort-2026-10.md).

## Node.js version declarations

`SP684` is a high-severity advisory for an exact declared Node.js release before
its branch's 21 October 2026 security baseline: **22.23.4**, **24.22.1**, or
**26.12.1**. These are branch remediation baselines, not inferred introduced-version
ranges. `SP685` is a medium advisory for the known upstream EOL branches
**18, 20, 21, 23, and 25** in the reviewed October 2026 schedule.

Both checks remain nonblocking and emit at most one finding per exact declaration,
with minimal version-only evidence. Supported declarations are `.nvmrc`,
`.node-version`, the Node entry in `.tool-versions`, and a final static official
Node Docker image, following local stage aliases through the existing resolver.
The checks add no dependency or network path.

Engines ranges, floating/prerelease/vendor pins, custom images, digest overrides,
ambiguous declarations, and compatibility-CI versions remain outside these
signatures. A declaration establishes neither the installed/deployed binary,
vendor backport status, affected API use, nor runtime exploitability.

Primary references: [Node.js October security bulletin](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
[official release schedule](https://github.com/nodejs/Release/blob/main/schedule.json),
and [official Node Docker image variants](https://github.com/nodejs/docker-node/blob/main/README.md#image-variants).

## PHP2Shell version evidence

`SP683` uses a dated offline snapshot of CVE-2026-109618 and CVE-2026-109619,
disclosed 21 October 2026 and reviewed 22 October. It recognizes exact upstream
pins in `.php-version`, a single PHP entry in `.tool-versions`, or the final static
official PHP FPM/Apache image stage (following local stage aliases). Branch fixes
are **8.2.35**, **8.3.36**, **8.4.27** and **8.5.12**; they are not one global minimum.

The upstream issues are critical. The scanner reports a medium advisory about a
declared version, not an exploited or reachable deployment. Verify distribution
backports, the actual web-serving binary and worker restart. Composer constraints,
CLI-only images, custom registries, floating/prerelease/vendor versions, dynamic
arguments, unresolved digests and heredocs remain outside the signature; silence
does not establish patch status. No live PHP/container/network probe is performed.
Application validation or INI mitigations are not treated as a complete patch.

Primary references: [PHP announcement](https://www.php.net/archive/2026.php#2026-10-21-5),
[OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w),
[stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

`SP668` preserves the format-position boundary (syslog's second argument) and
filters quoted/comment examples; ambiguous C++ raw strings and semantic binding
remain unresolved. `SP670` now requires one literal XmlReaderSettings initializer
with Parse plus XmlUrlResolver and direct XmlReader.Create consumption. Null,
throwing/secure resolvers, prohibiting modes, rebinding, local type look-alikes and
ambiguous C# string forms stay silent. Internal DTD parsing is not itself XXE;
entity-expansion limits are a separate concern.

## Ecosystem-aware detection

ShipProof uses file suffixes, manifests, and bounded structural context to select applicable checks. Framework detection narrows where a rule runs; it is not proof that a framework is configured or deployed exactly as the repository suggests.

| Ecosystem / Framework | Detection Source | Target Production Checks |
| :--- | :--- | :--- |
| **Next.js, Nuxt, SvelteKit, Remix, Astro** | `package.json` (`next`, `nuxt`, `@sveltejs/kit`, `@remix-run/*`, `astro`) | Secrets in `NEXT_PUBLIC_` (`SP403`), CSP header evaluation (`SP408`), Serverless DB connection leaks (`SP313`), Middleware static asset matcher (`SP413`), Server Action authorization (`SP420`) |
| **React, Vue, Angular, SolidJS** | `package.json` (`react`, `vue`, `@angular/core`, `solid-js`) | Exposed service role keys (`SP503`), Credential logging in client bundles (`SP204`), Unsanitized SVG uploads (`SP112`), Raw HTML injection (`SP116`), Angular sanitizer bypass (`SP125`), Vue `v-html` (`SP415`), Array index keys (`SP414`) |
| **Express, Fastify, NestJS, Koa, Hono, Elysia** | `package.json` (`express`, `fastify`, `@nestjs/core`, `koa`, `hono`, `elysia`) | Missing security headers/helmet (`SP401`), Rate-limited auth routes (`SP402`), CSRF on cookie sessions (`SP407`), Open redirects (`SP121`), SSRF via request URLs (`SP124`), Raw error object leaks (`SP406`), Body parser limits (`SP412`), Unhandled stream pipes (`SP336`), In-memory session leaks (`SP337`), Synchronous crypto in event loop (`SP339`), `process.exit` in handlers (`SP343`), Insecure Stripe webhooks (`SP502`), Unmetered AI routes (`SP501`) |
| **Prisma, Drizzle, TypeORM, Mongoose, Supabase** | `package.json` (`@prisma/client`, `drizzle-orm`, `typeorm`, `mongoose`, `@supabase/*`) | Raw SQL interpolation (`SP103`), Non-singleton DB clients in serverless (`SP313`), Supabase RLS bypass (`SP503`), Unbounded queries (`SP302`), Missing connection pool limits (`SP328`), Per-row commit locks (`SP326`) |
| **FastAPI, Starlette, Litestar, Sanic** | `pyproject.toml`, `requirements.txt` | Unprotected admin routes (`SP108`), Missing `response_model` (`SP409`), Wildcard CORS credentials (`SP419`), N+1 queries in loops (`SP307`), Unbounded pagination (`SP305`), Missing HTTP timeouts (`SP304`), Dropped asyncio task refs (`SP335`, `SP346`), ThreadPool per request (`SP344`), local logging configuration listener (`SP697`) |
| **Django & Flask** | `pyproject.toml`, `requirements.txt` | Hardcoded `SECRET_KEY` (`SP404`), Wildcard `ALLOWED_HOSTS` (`SP405`), Debug enabled (`SP201`, `SP411`), Flask hardcoded `secret_key` (`SP410`), String-interpolated SQL (`SP103`), SSTI via `render_template_string` (`SP137`) |
| **Go (Gin, Echo, Fiber, Chi)** | `go.mod` | Missing server timeouts (`SP131`), Ignored errors (`SP136`), Response body leak (`SP315`), Goroutine context leaks (`SP309`), Unbuffered channel deadlocks (`SP332`), WaitGroup race conditions (`SP333`), Insecure secret fallbacks (`SP004`), Outbound request timeouts (`SP304`), Unbounded concurrency (`SP306`) |
| **Rust (Actix-web, Axum, Rocket)** | `Cargo.toml`, `.rs` | Committed keys/credentials (`SP001`, `SP002`, `SP003`), direct reqwest TLS bypass (`SP104`, advisory), invalid zero-initialized references (`SP673`, advisory), SSRF to metadata (`SP109`), credential logging (`SP204`) |
| **Roblox / Luau** | `.lua`, `.luau` local source files | HttpService response executed as source (`SP671`), direct client-source execution in simple RemoteEvent/RemoteFunction callbacks (`SP672`), client-selected module require (`SP690`), client-selected instance destruction (`SP691`), provider-secret checks. Initial support excludes general Lua data-flow and binary place files. |
| **JS / TypeScript configuration** | Runtime ESM/const-require imports; `next.config.*` exports | Image private-IP opt-out (`SP674`), JWT time/key-type opt-outs on verify/sign (`SP675`, `SP676`), short GCM tags (`SP677`), direct uninitialized Buffer read (`SP678`), lenient HTTP parsing including insecure validation opt-out (`SP679`), Electron origin/privilege boundaries (`SP680`, `SP681`), Chromium sandbox opt-out (`SP682`), RSA signing key-size safeguard opt-out (`SP692`), disabled HTTP receive deadlines (`SP693`), empty Promise.race await (`SP694`), boolean array comparator (`SP695`), awaited sync zlib (`SP698`). All are advisory. |
| **PHP (Laravel, Symfony)** | `composer.json` | Dynamic code evaluation (`SP101`), SQL injection interpolation (`SP103`, `SP128`), Path traversal (`SP110`), Loose equality credential comparison (`SP127`), Reflected XSS (`SP129`), Open redirect (`SP130`), Object injection (`SP113`) |
| **Ruby (Rails, Sinatra)** | `Gemfile` | Secret key leakage (`SP003`), Unsafe deserialization with Marshal/YAML (`SP106`), Debug mode enabled (`SP201`), CSRF forgery disabled (`SP417`), Dynamic code execution (`SP101`), Missing payment idempotency (`SP504`) |
| **Java / Kotlin (Spring Boot, Quarkus, Micronaut)** | `pom.xml`, `build.gradle`, `build.gradle.kts` | Committed keys/credentials (`SP001`, `SP002`, `SP003`), Insecure CORS with credentials (`SP107`), Path traversal (`SP110`), Spring Boot actuator public exposure (`SP416`), Binary ObjectInputStream deserialization (`SP168`) |
| **C# / .NET (ASP.NET Core, Web API)** | `*.csproj`, `packages.config` | Sync-over-async thread starvation (`SP132`), `debug="true"` configuration (`SP133`), Unconditional `UseDeveloperExceptionPage` (`SP418`), Insecure deserialization (`SP106`) |
| **Dart async APIs** | `.dart` source with explicit `dart:async` import | Directly awaited empty `Future.any` input (`SP694`); wrappers, type inference and complex bindings are unresolved. Advisory. |
| **C# XML settings** | `.cs` source | Inline XmlReader settings passed to `XmlReader.Create` remove the entity-character limit while enabling DTD parsing (`SP696`); this is not proof of external entity access. Advisory. |
| **C / C++** | `CMakeLists.txt`, `Makefile` | Unbounded legacy string manipulation `strcpy`/`gets` (`SP135`), Insecure temporary file permissions (`SP139`, `SP169`) |
| **Containers, Kubernetes & CI/CD** | `Dockerfile`, Compose, Kubernetes YAML, `.github/workflows` | Root/container privilege (`SP205`, `SP637`–`SP640`), mutable dependencies (`SP202`, `SP203`), workflow trust boundaries (`SP209`, `SP210`, `SP658`–`SP660`), Kubernetes RBAC/admission posture (`SP656`, `SP657`, `SP661`) |

## Detection Rules Reference

`SP347` and `SP350` are retired, with their IDs reserved. Propagating an exception
from `asyncio.gather` is normal behavior; missing pool keywords in `create_engine`
do not prove unlimited capacity across dialects/pool classes.

`SP699` checks qualified primitive Rust NonZero constructors with literal zero.
`SP673` also checks uninitialized references; custom/imported module identities,
raw identifiers and stringify token data are not affirmative evidence. No unsafe
sample is executed and arbitrary macro expansion/type aliases remain unresolved.

`SP700` checks imported Node timers at the correct callback/promise delay position.
Exact decimal values and products of at most nine bounded operands are supported;
other computed expressions and global/browser timers remain unresolved.

`SP701` checks import-bound native QueuePool constructors with explicit unlimited
size/overflow. It does not import SQLAlchemy, infer engine defaults or resolve
custom pool classes. Typed SslStream client calls extend `SP104` only when inline
options provide an unconditional four-parameter certificate callback. These new
source-level checks remain advisory and do not prove deployed exposure or load.

The complete rule catalog is maintained at the [canonical GitHub source catalog](https://github.com/kingggg5/shipproof/blob/main/docs/rule-catalog.md). This page remains the boundary guide. The scanner's rule metadata is embedded in the runtime, so `shipproof explain SPxxx` continues to return the rule explanation and remediation offline.

