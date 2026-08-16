# ShipProof Failure Catalog

> Research-grounded catalog of failure modes in AI-written and human-written production code.
> Sources: web research (OWASP, CWE, Reddit, Stack Overflow, engineering blogs — see
> [References](#references)) plus first-principles engineering review. Each item records
> how it could be detected: `SHIPPED SPxxx` (a ShipProof detector exists today),
> `L0/L1` (detectable with today's engine class), `DATAFLOW` (needs taint/call-graph),
> `RUNTIME` (needs execution or measurement), `CONFIG` (infrastructure file analysis),
> `DEP` (dependency/SCA tooling), or `MANUAL` (process/human review).
> This catalog feeds the Rule Factory: high-value L0/L1 items become detector candidates.

Status: v1 — 463 items across 21 sections (failure-mode categories, language supplements, and dataset guide).

## 1. Web security — injection & input handling

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| SEC-001 | SQL built by string interpolation | Attacker changes query semantics → parameterize | SHIPPED SP103/SP118 | CWE-89 |
| SEC-002 | `eval`/`exec`/`new Function` on external input | Arbitrary code execution → safe parsers | SHIPPED SP101/SP117 | CWE-95 |
| SEC-003 | Timer/interval string arguments | Implicit eval → pass functions | SHIPPED SP118 | CWE-95 |
| SEC-004 | `pickle`/`yaml.load`/`node-serialize` on untrusted data | RCE via gadget chains → JSON | SHIPPED SP106/SP120 | CWE-502 |
| SEC-005 | OS command built by concatenation | Command injection → argv lists | SHIPPED SP102 | CWE-78 |
| SEC-006 | Command built even when only displayed | Shell metacharacters in echoed output | L1 | CWE-78 |
| SEC-007 | Path from request used in file ops | Path traversal → allowlist + resolve in base dir | SHIPPED SP110/SP119 | CWE-22 |
| SEC-008 | Zip extraction without entry-name validation | Zip-slip writes outside target dir → validate each entry | L1 | CWE-22 |
| SEC-009 | XML parsed with entity resolution on | XXE file read / billion laughs → hardened parser | SHIPPED SP115 | CWE-611 |
| SEC-010 | XSLT transforms on user XML | Code execution via XSLT extensions → disable | L1 | CWE-611 |
| SEC-011 | Unsanitized user HTML rendered raw | Stored XSS → sanitize (DOMPurify) or escape | SHIPPED SP116 | CWE-79 |
| SEC-012 | `document.write` with request data | DOM XSS → textContent | L0 | CWE-79 |
| SEC-013 | `innerHTML` assignment from fetch/body data | DOM XSS → textContent/sanitize | L0 | CWE-79 |
| SEC-014 | SVG uploads served inline | Script inside SVG executes → force download or sanitize | SHIPPED SP112 | CWE-79 |
| SEC-015 | Unescaped template rendering (user-controlled) | Reflected XSS in server templates → auto-escape | DATAFLOW | CWE-79 |
| SEC-016 | Markdown rendered with raw HTML enabled | XSS via HTML in markdown → sanitize renderer | L1 | CWE-79 |
| SEC-017 | Open redirect from request value | Phishing on your domain → allowlist | SHIPPED SP121 | CWE-601 |
| SEC-018 | URL from request fetched server-side | SSRF to internal/metadata → allowlist + IP checks | SHIPPED SP109/SP124 | CWE-918 |
| SEC-019 | DNS-rebinding-safe SSRF missing (resolve-then-check) | Bypass of URL allowlists → resolve and pin IP | RUNTIME | CWE-918 |
| SEC-020 | Redirect chain accepting `data:`/`javascript:` schemes | Script execution via scheme confusion → scheme allowlist | L0 | CWE-601 |
| SEC-021 | Credentialed wildcard CORS | Any site reads authenticated data → exact origins | SHIPPED SP107 | CWE-942 |
| SEC-022 | Reflected URL/JSON in content-type text/plain sniffed | MIME confusion → explicit headers + nosniff | CONFIG | CWE-430 |
| SEC-023 | Missing CSRF token on state-changing cookie routes | Cross-site forged requests → CSRF middleware | SHIPPED SP407 | CWE-352 |
| SEC-024 | JWT `algorithms` includes `none` or is unset | Forged tokens → pin algorithm + verify | SHIPPED SP105 | CWE-347 |
| SEC-025 | JWT verified but signature result ignored | Token accepted regardless → check return | L1 | CWE-347 |
| SEC-026 | Password reset token compared with `==` | Timing oracle → constant-time compare | L1 | CWE-208 |
| SEC-027 | Session ID in URL query string | Leakage via logs/referrer → cookies only | L0 | CWE-598 |
| SEC-028 | Error pages echo stack traces | Info disclosure → generic errors + server-side logs | SHIPPED SP406 | CWE-209 |
| SEC-029 | Validation only on the client | Trivially bypassed → server-side validation | MANUAL | CWE-602 |
| SEC-030 | Mass assignment from request body to model | Users self-promote to admin → field allowlists | L1 | CWE-915 |
| SEC-031 | IDOR on object IDs from request | Access other tenants' rows → ownership checks | DATAFLOW | CWE-639 |
| SEC-032 | Sequential guessable IDs for private resources | Enumeration → UUIDs or authorization | L1 | CWE-639 |
| SEC-033 | File upload without type/size limits | DoS + malicious payloads → validate magic bytes + cap | L1 | CWE-400 |
| SEC-034 | Uploaded files stored under web root | Direct execution → store outside/serving layer | CONFIG | CWE-434 |
| SEC-035 | GraphQL depth/complexity unbounded | Query DoS → depth limits + cost analysis | CONFIG | CWE-400 |
| SEC-036 | Regex from user input compiled directly | ReDoS/RCE → literal mode or sandbox | L1 | CWE-1333 |
| SEC-037 | Nested quantifier regexes on input | Catastrophic backtracking → rewrite/timeout | SHIPPED SP114 | CWE-1333 |
| SEC-038 | Template engine rendering user-supplied templates | SSTI RCE → never render user templates | L1 | CWE-1336 |
| SEC-039 | `child_process.exec` with template string | Node command injection → `execFile` argv | L0 | CWE-78 |
| SEC-040 | Deserialized cache objects trusted blindly | Poisoned cache → RCE → signed/integrity-checked | DATAFLOW | CWE-502 |

## 2. Authentication, authorization & sessions

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| AUTH-001 | Admin/internal route without visible authorization | Privilege escalation → explicit dependency/middleware | SHIPPED SP108 | CWE-862 |
| AUTH-002 | Authorization checked in UI only | Bypass via direct API call → server checks | MANUAL | CWE-602 |
| AUTH-003 | Passwords hashed with MD5/SHA1/unsalted | Offline cracking → argon2id/bcrypt | L0 | CWE-916 |
| AUTH-004 | Password compared before hashing exists | Logic-order flaw → hash-then-compare | L1 | CWE-840 |
| AUTH-005 | No rate limit on login/reset endpoints | Credential stuffing → throttling + lockout | SHIPPED SP402 | CWE-307 |
| AUTH-006 | Generic "wrong username or password" missing | Username enumeration → unified message | MANUAL | CWE-204 |
| AUTH-007 | Reset token single-use not enforced | Token replay → invalidate after use | RUNTIME | CWE-613 |
| AUTH-008 | Reset token long-lived without expiry | Window for takeover → short TTL | L1 | CWE-613 |
| AUTH-009 | Session not invalidated on password change | Stolen sessions persist post-rotation → revoke all | RUNTIME | CWE-613 |
| AUTH-010 | Logout only clears client state | Session still valid server-side → revoke | RUNTIME | CWE-613 |
| AUTH-011 | Cookies missing `Secure`/`HttpOnly`/`SameSite` | Theft/CSRF → set flags | CONFIG | CWE-1004 |
| AUTH-012 | Token stored in localStorage | XSS steals tokens → httpOnly cookies | L1 | OWASP ASVS V3 |
| AUTH-013 | Hardcoded service credentials | Rotation impossible → secret manager | SHIPPED SP003 | CWE-798 |
| AUTH-014 | Secret fallback defaults in code | Known keys in prod → fail closed | SHIPPED SP004 | CWE-798 |
| AUTH-015 | API keys in client bundles (`NEXT_PUBLIC_`, `VITE_`) | Public secrets → server-only vars | SHIPPED SP403 | CWE-200 |
| AUTH-016 | Service-role/admin keys in frontend env | Full DB bypass → never expose | SHIPPED SP503 | CWE-200 |
| AUTH-017 | OAuth state parameter omitted/skipped | CSRF on OAuth flow → state + PKCE | L1 | CWE-352 |
| AUTH-018 | Redirect URI not validated in OAuth | Token theft via open redirect → exact match | L1 | CWE-601 |
| AUTH-019 | JWT in localStorage with no expiry check | Zombie sessions → verify `exp` | L1 | CWE-613 |
| AUTH-020 | API endpoints trust client-declared role | Self-escalation → derive role server-side | DATAFLOW | CWE-284 |
| AUTH-021 | Internal endpoints bound to 0.0.0.0 without auth | Direct DB/cache exposure → bind localhost/auth | CONFIG | CWE-284 |
| AUTH-022 | Default credentials never rotated | Documented logins work → force change | CONFIG | CWE-798 |
| AUTH-023 | Password policy enforced client-only | Weak passwords accepted → server policy | MANUAL | CWE-521 |
| AUTH-024 | 2FA codes not rate-limited | Brute-force 6 digits → attempt caps | CONFIG | CWE-307 |
| AUTH-025 | API tokens without scope/expiry | Over-privileged forever tokens → scoped, expiring | MANUAL | CWE-284 |

## 3. Cryptography & secrets

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| CRY-001 | TLS verification disabled (`verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`) | MITM → restore verification | SHIPPED SP104 | CWE-295 |
| CRY-002 | Security tokens from `Math.random`/`random` | Predictable → crypto RNG | SHIPPED SP122 | CWE-338 |
| CRY-003 | Hardcoded cipher IV | Pattern leakage + block replay → random IV | SHIPPED SP123 | CWE-329 |
| CRY-004 | ECB mode used for data | Identical blocks visible → GCM/CBC+IV | L0 | CWE-327 |
| CRY-005 | Password "encryption" instead of hashing | Reversible passwords → argon2id | L0 | CWE-916 |
| CRY-006 | MD5/SHA1 for signatures/integrity | Collisions → SHA-256+ | L0 | CWE-328 |
| CRY-007 | Key derived from password without KDF | Weak keys → scrypt/argon2 | L1 | CWE-916 |
| CRY-008 | Static HMAC key committed in repo | Forgery → rotate + env | SHIPPED SP003 | CWE-798 |
| CRY-009 | Nonce reuse in AES-GCM | Key recovery → unique nonce per message | DATAFLOW | CWE-323 |
| CRY-010 | Comparing signatures with `==` | Timing attack → constant-time | L1 | CWE-208 |
| CRY-011 | Secrets logged (tokens, passwords, headers) | Log-store leakage → redact | SHIPPED SP204 | CWE-532 |
| CRY-012 | `.env` committed to git | Permanent secret exposure → gitignore + rotate | SHIPPED SP001-3 | CWE-798 |
| CRY-013 | Private keys committed | Impersonation → revoke + rotate | SHIPPED SP001 | CWE-798 |
| CRY-014 | Cloud metadata credentials in code/config | Account takeover → IAM roles | L0 | CWE-798 |
| CRY-015 | Webhook signature not verified before processing | Forged events → verify raw-body signature | SHIPPED SP502 | CWE-347 |
| CRY-016 | Random GUID v4 used as security token | Not crypto-random in some impls → crypto RNG | L1 | CWE-338 |
| CRY-017 | Salt hardcoded and shared across users | Rainbow-table defeat only → per-user salt | L1 | CWE-916 |
| CRY-018 | Encryption key stored next to ciphertext | Encryption theater → KMS/secret manager | CONFIG | CWE-321 |
| CRY-019 | Crypto seeded with time (`srand(time)`) | Predictable → CSPRNG | L0 | CWE-337 |
| CRY-020 | JWT secret shorter than hash output | Brute-forceable → ≥256-bit secret | L1 | CWE-326 |

## 4. SQL & databases

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| SQL-001 | `SELECT *` without LIMIT on growing tables | OOM under growth → paginate | SHIPPED SP302 | SO anti-patterns |
| SQL-002 | Query inside loop (N+1) | Latency multiplies → batch/join | SHIPPED SP307 | SO #346659 |
| SQL-003 | Missing index on FK/join/filter columns | Full scans → index review | CONFIG | SO #621884 |
| SQL-004 | Function wrapped around indexed column in WHERE | Index bypass → computed column/range | L0 | leveluperef |
| SQL-005 | `NOT IN` with nullable subquery | Silent empty results → `NOT EXISTS` | L0 | PG mistakes |
| SQL-006 | `SELECT DISTINCT` masking broken join | Wrong data hidden → fix join cardinality | L0 | SQL anti-patterns |
| SQL-007 | Leading wildcard `LIKE '%x'` | Index unusable → trigram/full-text | L0 | common mistakes |
| SQL-008 | Huge `IN (...)` lists (1k+) | Plan blowup → temp table/join | L0 | lackofimagination |
| SQL-009 | Transactions held across external HTTP calls | Pool exhaustion → move calls outside | SHIPPED SP316 | mydba.dev |
| SQL-010 | Transaction per row in import loops | 10k commits → batch commit | L1 | PG tuning |
| SQL-011 | Connection per request (no pool) | Connection storms → pool | SHIPPED SP313 | Releem |
| SQL-012 | Non-singleton DB client in serverless | Per-invocation connections → global client | SHIPPED SP313 | Prisma docs |
| SQL-013 | Missing pool `acquire` timeout | Hangs under saturation → timeout + sizing | CONFIG | Releem |
| SQL-014 | ORM query with `.all()` then filter in app | Transfers whole table → filter in SQL | L1 | SO |
| SQL-015 | Offset-based pagination on deep pages | O(n) scans → keyset pagination | L1 | use-the-index-luke |
| SQL-016 | Count(*) on every list request for pagination | Expensive counts → estimate/cache | RUNTIME | PG blogs |
| SQL-017 | Unbounded migrations at deploy (table rewrite) | Downtime → incremental migrations | CONFIG | Reddit PG |
| SQL-018 | `ALTER TABLE` taking aggressive lock in busy hours | Blocked traffic → lock-aware migrations | CONFIG | Reddit PG locks |
| SQL-019 | No statement timeout set | Runaway queries starve pool → timeouts | CONFIG | PG tuning |
| SQL-020 | Implicit type conversion in join conditions | Index skipped → matching types | L1 | MySQL mistakes |
| SQL-021 | Storing serialized JSON queried by contents | Unindexable → columns/jsonb indexes | CONFIG | PG blogs |
| SQL-022 | Deleting in one giant transaction | Locks + replication lag → chunked deletes | L1 | PG blogs |
| SQL-023 | Missing composite index for query shape | Multi-column filters scan → composite index | CONFIG | coddykit |
| SQL-024 | Indexes never reviewed after schema growth | Bloat → periodic review | MANUAL | coddykit |
| SQL-025 | `ORDER BY RAND()` for sampling | Full sort → `TABLESAMPLE` | L0 | MySQL mistakes |
| SQL-026 | ORMs logging all queries with parameters | Secrets in logs → redact/minimize | SHIPPED SP204 | CWE-532 |
| SQL-027 | Read-after-write on async replicas | Stale reads for UX correctness → sticky/read-your-writes | RUNTIME | PG docs |
| SQL-028 | Missing unique constraint assumed by app | Duplicate rows appear → DB constraint | CONFIG | SO |
| SQL-029 | Money stored as float | Rounding drift → integer cents/decimal | L1 | classic |
| SQL-030 | Timestamps without timezone (`timestamp` not `timestamptz`) | DST bugs → tz-aware types | CONFIG | PG mistakes |
| SQL-031 | String dates compared lexically | Wrong ordering across formats → date types | L1 | classic |
| SQL-032 | Blind retry of failed transactions | Lost updates → retry with backoff on serialization errors only | L1 | PG docs |
| SQL-033 | DELETE without WHERE generated dynamically | Mass data loss → guarded deletes | DATAFLOW | classic |
| SQL-034 | ORM `save()` on objects with stale version | Overwrites concurrent edits → optimistic locking | L1 | CWE-362 |
| SQL-035 | Migration files not reviewed in PRs | Irreversible changes slip → review gate | MANUAL | CI practice |

## 5. APIs & integration

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| API-001 | Outbound HTTP without timeout | Worker exhaustion → set connect/read timeouts | SHIPPED SP304 | CWE-1088 |
| API-002 | Unbounded retries on dependencies | Retry storms → stop condition + jittered backoff | SHIPPED SP318 | SRE practice |
| API-003 | Retries on non-idempotent POSTs | Duplicated payments → idempotency keys | L1 | Stripe docs |
| API-004 | No circuit breaker on flaky dependency | Cascading failure → breaker + fallback | L1 | SRE |
| API-005 | Pagination accepts unlimited page size | Memory DoS → max page size | SHIPPED SP305 | CWE-770 |
| API-006 | Endpoint returns unbounded lists | Payload/heap growth → paginate | SHIPPED SP302 | CWE-400 |
| API-007 | Missing request body size limit | Memory DoS → body caps | CONFIG | CWE-400 |
| API-008 | Unmetered LLM/AI routes | Bill DoS → auth + quota | SHIPPED SP501 | cost |
| API-009 | Webhook processed with parsed JSON only | Signature verification impossible → raw body | SHIPPED SP502 | CWE-347 |
| API-010 | API version absent from routes | Breaking changes for clients → version prefix | MANUAL | API design |
| API-011 | Breaking schema changes without versioning | Client breakage → additive evolution | MANUAL | API design |
| API-012 | Trusting client `Content-Length` alone | Smuggling/DoS → framework limits | RUNTIME | CWE-436 |
| API-013 | Internal errors leaked in 5xx bodies | Stack traces exposed → generic bodies | SHIPPED SP406 | CWE-209 |
| API-014 | No idempotency on payment/order creation | Double-submit duplicates → idempotency key | L1 | Stripe |
| API-015 | Polling endpoints without caching | Thundering herd → ETag/cache headers | CONFIG | HTTP |
| API-016 | Long-running work done in request thread | Timeouts + thread starvation → queues | L1 | SRE |
| API-017 | Third-party SDK called on startup path | Boot fails when vendor blips → lazy init | L1 | reliability |
| API-018 | Feature flags fetched synchronously per request | Latency + vendor dependency → cached snapshot | L1 | perf |

## 6. Performance & scale — backend

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| PRF-001 | Redis `KEYS` in request path | Blocks single-threaded server → `SCAN` | SHIPPED SP301 | Redis docs |
| PRF-002 | Redis O(N) ops (`SMEMBERS`, `HGETALL`) on big keys | Latency spikes → `SSCAN`/redesign | L0 | Redis |
| PRF-003 | Cache without TTL on growing keys | Memory leak → TTLs | L0 | Redis |
| PRF-004 | Cache stampede on hot-key expiry | DB spike → jittered TTL/lock | L1 | classic |
| PRF-005 | `Promise.all`/`gather` over unbounded lists | FD/memory exhaustion → bounded pools | SHIPPED SP306 | CWE-400 |
| PRF-006 | JSON serialized per row inside loop | CPU waste → batch serialize | L1 | node blogs |
| PRF-007 | Sync logging call in hot path with console locks | Contention → async appenders | RUNTIME | SRE |
| PRF-008 | Regex recompiled per request | CPU waste → precompile | L1 | classic |
| PRF-009 | In-memory session store across instances | Random logouts → shared store | L1 | scale |
| PRF-010 | Global lock around request handling | Serializes throughput → fine-grained/atomic | L1 | perf |
| PRF-011 | Worker count = CPU count on IO-bound service | Under-utilization → tune per workload | CONFIG | SRE |
| PRF-012 | No backpressure on queues/streams | Unbounded buffers → OOM | DATAFLOW | SRE |
| PRF-013 | Event listeners added per request, never removed | Listener leak → EventEmitter caps | L1 | Node |
| PRF-014 | Timers not cleared on teardown | Keeps process alive + stale handlers | L1 | Node |
| PRF-015 | Large payloads inflated in memory (base64 buffers) | 2-3x memory → streaming | L1 | Node |
| PRF-016 | `readFileSync` inside request handler | Event-loop block → async IO | L0 | Node |
| PRF-017 | CPU-bound work in web process | Blocks event loop/workers → job queue | L1 | Node |
| PRF-018 | Missing HTTP keep-alive on outbound client | Handshake per call → agent reuse | CONFIG | Node |
| PRF-019 | DNS lookup per outbound request | Latency → cache/resolver tuning | RUNTIME | SRE |
| PRF-020 | Templates/layouts re-rendered per request | CPU → precompile/cache | L1 | perf |
| PRF-021 | O(n²) dedup/check inside loop | CPU blowup on growth → set/map | L1 | algorithms |
| PRF-022 | List `.index()`/`in` scans in hot loop | Hidden O(n²) → dict/set | L1 | Python |
| PRF-023 | String concatenation in long loops | Quadratic copying → join/buffer | L1 | Python |
| PRF-024 | Whole file read when streaming suffices | Memory spikes → streams | L1 | IO |
| PRF-025 | Deep-copy of large objects per request | CPU+GC → structural sharing | L1 | JS |
| PRF-026 | `structuredClone` of entire collections for filters | Clone only returned slice | L1 | JS |
| PRF-027 | Microservice chatty calls for one user action | Latency stacking → aggregate/BFF | DATAFLOW | arch |
| PRF-028 | No CDN for static assets | Origin load + latency → CDN | CONFIG | web perf |
| PRF-029 | Compression disabled on large responses | Bandwidth waste → gzip/brotli | CONFIG | web perf |
| PRF-030 | Missing `Connection: close` handling on proxies | FD leaks → pooling config | CONFIG | SRE |
| PRF-031 | Health endpoint runs real dependency checks | Health flaps cascade → lightweight checks | L1 | SRE |
| PRF-032 | Startup prefetch of everything | Slow boots/scale-outs → lazy/on-demand | L1 | SRE |
| PRF-033 | One shared queue for fast+slow jobs | Head-of-line blocking → separate queues | L1 | SRE |
| PRF-034 | Scheduled jobs without leader election | Duplicate runs cluster-wide → lock/leader | CONFIG | SRE |
| PRF-035 | Rate limiter state per instance only | Limit is N×instances → shared counter | L1 | correctness |
| PRF-036 | Unindexed user lookup by email at login | Login latency → index | CONFIG | DB |
| PRF-037 | Logging serialized whole objects in loops | Log volume costs → sample/summarize | L1 | observability |
| PRF-038 | GC pressure from per-request big-array allocations | Latency jitter → reuse/streams | RUNTIME | perf |
| PRF-039 | A/B variant computed by full table scan per request | DB melts at traffic → precompute | DATAFLOW | scale |
| PRF-040 | Load test never run before launch | Unknown ceiling → k6 rehearsal | RUNTIME | SRE |

## 7. Frontend (JS/TS, React, browsers)

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| UI-001 | useEffect without cleanup on subscriptions | Memory leaks + ghost updates → return cleanup | L1 | React docs |
| UI-002 | useEffect dependency array omitted | Stale closures → exhaustive-deps | L1 | React |
| UI-003 | State updater reading stale state (`count+1`) | Lost updates → functional updates | L1 | React |
| UI-004 | Direct DOM mutation alongside React state | Divergence bugs → single source | L1 | React |
| UI-005 | Array index as key on reorderable lists | Wrong rows reused → stable IDs | L1 | React |
| UI-006 | Fetch in effect without abort | Race conditions/out-of-order responses → AbortController | L1 | React |
| UI-007 | Infinite re-render from object deps | Frozen page → memoize/primitives | L1 | React |
| UI-008 | Unhandled promise rejections in effects | Silent failures → error boundaries | L1 | JS |
| UI-009 | Secrets in `VITE_`/`NEXT_PUBLIC_` env | Bundled to public → server-only | SHIPPED SP403 | CWE-200 |
| UI-010 | `dangerouslySetInnerHTML` with data | XSS → sanitize | SHIPPED SP116 | CWE-79 |
| UI-011 | `target="_blank"` without `rel="noopener"` | Tab-nabbing → add rel | L0 | HTML |
| UI-012 | postMessage handler without origin check | Cross-origin data theft → validate origin | L1 | CWE-346 |
| UI-013 | Client-side-only input validation | Bypass → server validation | MANUAL | CWE-602 |
| UI-014 | Tokens in localStorage | XSS exfiltration → httpOnly cookies | L1 | OWASP |
| UI-015 | Whole-store subscription causing global re-renders | Jank → selectors | RUNTIME | Redux |
| UI-016 | Large lists without virtualization | DOM blowup → windowing | L1 | perf |
| UI-017 | Images without dimensions/lazy loading | Layout shift + bandwidth → width/height + lazy | L0 | web perf |
| UI-018 | Sync heavy computation in render path | Frozen UI → memo/web worker | RUNTIME | React |
| UI-019 | setInterval driving derived state | Drift/duplication → derive + single timer | L1 | React |
| UI-020 | Error boundaries missing at route level | One crash blanks app → boundaries | L1 | React |
| UI-021 | Forms without double-submit guard | Duplicate orders → disable/idempotency | L1 | UX |
| UI-022 | window.onload stacking assumptions | Fragile ordering → DOMContentLoaded/defer | L0 | JS |
| UI-023 | Global namespace mutation for module state | Collisions → modules | L1 | JS |
| UI-024 | `==` comparisons with mixed types | Coercion bugs → `===` | L0 | JS |
| UI-025 | Floating point money math on client | Rounding display bugs → cents/decimal lib | L0 | JS |
| UI-026 | Timezone-less date rendering | Off-by-hours globally → tz-aware | L1 | JS |
| UI-027 | Accessible labels missing on interactive elements | A11y failures + legal risk → labels | CONFIG | WCAG |
| UI-028 | Third-party scripts loaded sync in head | Blocks first paint → async/defer | L0 | web perf |
| UI-029 | Service worker never updated/cleaned | Users stuck on old code → versioned SW | CONFIG | PWA |
| UI-030 | Console logging tokens/PII in production | Leakage → strip in build | L0 | CWE-532 |

## 8. Python-specific

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| PY-001 | Blocking call inside `async def` | Event-loop freeze → await/to_thread | SHIPPED SP303/SP317 | asyncio pitfalls |
| PY-002 | Missing `await` on coroutine | Silent no-op coroutine created → lint/ast | L1 | asyncio mistakes |
| PY-003 | `requests` in async context | Blocks loop → aiohttp/httpx | SHIPPED SP317 | plainenglish.io |
| PY-004 | Creating event loop per request | Loops leak/interfere → single loop | L1 | cloud funcs |
| PY-005 | Fire-and-forget tasks without reference | GC cancels tasks → hold references | L1 | asyncio docs |
| PY-006 | Un-awaited task exceptions swallow | Invisible failures → done-callback logging | L1 | asyncio |
| PY-007 | Shared mutable default argument (`def f(x=[])`) | State leaks across calls → None sentinel | L1 | classic |
| PY-008 | Mutable class attributes as instance state | Cross-instance sharing → instance attrs | L1 | classic |
| PY-009 | `except:` bare swallows KeyboardInterrupt | Unkillable broken loops → narrow except | L0 | PEP8 |
| PY-010 | Exception handler that logs and continues silently | Hidden corruption → explicit handling | MANUAL | SRE |
| PY-011 | `is` comparison for literals/values | Intermittent wrongness → `==` | L0 | classic |
| PY-012 | Chained comparison misuse (`a == b == c`) | Surprising semantics → explicit | L1 | classic |
| PY-013 | Late-binding closure over loop var | All closures see last value → bind arg | L1 | classic |
| PY-014 | `open()` without context manager | FD leak on exceptions → `with` | L0 | classic |
| PY-015 | `subprocess` with `shell=True` and vars | Injection → argv | SHIPPED SP102 | CWE-78 |
| PY-016 | `os.path.join` with absolute second arg | First path discarded → normalize | L1 | docs |
| PY-017 | `readlines()` on huge files | Memory blowup → iterate | L1 | perf |
| PY-018 | `pickle` for cross-boundary data | RCE + fragile → JSON | SHIPPED SP106 | CWE-502 |
| PY-019 | `yaml.load` without SafeLoader | RCE → safe_load | SHIPPED SP106 | CWE-502 |
| PY-020 | Django `SECRET_KEY` hardcoded | Session forgery → env | SHIPPED SP404 | CWE-798 |
| PY-021 | `ALLOWED_HOSTS=['*']` | Host-header poisoning → explicit hosts | SHIPPED SP405 | CWE-20 |
| PY-022 | Flask/FastAPI debug mode in prod | Debugger RCE | SHIPPED SP201 | CWE-489 |
| PY-023 | Route methods include unsafe verbs implicitly | Unexpected state changes → explicit methods | L1 | Flask |
| PY-024 | ORM `objects.get()` assuming existence | 500s on missing rows → get_or_404/handling | L1 | Django |
| PY-025 | N+1 via related access in templates | Hidden query storm → select_related | SHIPPED SP307 | Django |
| PY-026 | `time.sleep` for scheduling in servers | Blocked workers → schedulers/async | L0 | SRE |
| PY-027 | Global DB connection without pool checks | Exhaustion under concurrency → pool | L1 | DB |
| PY-028 | `threading` for IO-bound scaling | Memory per thread → asyncio | L1 | py docs |
| PY-029 | `requirements.txt` unpinned | Irreproducible builds → lock | DEP | packaging |
| PY-030 | `python:latest` base image | Silent breaking upgrades → pin | SHIPPED SP202 | supply chain |

## 9. Concurrency & distributed systems

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| ASY-001 | Check-then-act on shared state without lock | Lost updates/races → atomic ops | L1 | CWE-362 |
| ASY-002 | Read-modify-write on cache/counter non-atomically | Undercounting → INCR/atomic | L1 | Redis |
| ASY-003 | Double-checked locking without volatile/memory barrier | Torn state → correct sync | L1 | JVM-classic |
| ASY-004 | Shared module-level client mutated per request | Cross-request contamination → immutable/instantiate | L1 | Node/Py |
| ASY-005 | TOCTOU on file existence checks | Race on create → atomic open/lock | L1 | CWE-367 |
| ASY-006 | Distributed job without idempotent handler | Redelivery duplicates work → idempotency | L1 | queues |
| ASY-007 | Queue consumer acks before work completes | Crash loses jobs → ack after | L1 | AMQP |
| ASY-008 | Dead-letter queue never monitored | Silent job loss → alerting | CONFIG | SRE |
| ASY-009 | Optimistic locking absent on shared entities | Concurrent edits overwrite → version column | L1 | CWE-362 |
| ASY-010 | Lock ordering inconsistent across code paths | Deadlocks → global ordering | DATAFLOW | concurrency |
| ASY-011 | `asyncio.gather` without `return_exceptions` decision | One failure cancels/misses others → explicit policy | L1 | asyncio |
| ASY-012 | Unbounded coroutine fan-out per request | Resource exhaustion → semaphores | SHIPPED SP306 | asyncio |
| ASY-013 | Awaiting inside lock scope unnecessarily | Serializes throughput → shrink critical section | L1 | perf |
| ASY-014 | Background task capturing request-scoped state | Stale references/leaks → copy needed data | DATAFLOW | frameworks |
| ASY-015 | Clock-based ordering across machines | Skew breaks logic → logical clocks/DB time | MANUAL | distributed |
| ASY-016 | Cron interval shorter than job duration | Overlapping runs → advisory lock | CONFIG | cron |
| ASY-017 | Cache-aside update without invalidation on failure | Permanent stale data → write-through/invalidate+retry | DATAFLOW | caching |
| ASY-018 | Read replica used for write-then-read UX | Stale read confusion → read-your-writes | RUNTIME | DB |
| ASY-019 | Signal handlers doing complex work | Re-entrancy hazards → minimal handlers | L1 | OS |
| ASY-020 | Process pools sharing un-picklable/locked resources | Deadlocks at fork → initialize per-worker | RUNTIME | multiprocessing |

## 10. Reliability, resilience & operations

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| REL-001 | No timeout on any dependency call | Cascading hangs → timeouts everywhere | SHIPPED SP304 | SRE |
| REL-002 | Retry without exponential backoff + jitter | Thundering herd → backoff + jitter | SHIPPED SP318 | AWS builder's lib |
| REL-003 | Fallback missing when dependency is down | Hard cascade → degrade gracefully | L1 | SRE |
| REL-004 | Health checks not distinguishing liveness/readiness | Restart storms or dead-but-serving → split checks | CONFIG | k8s |
| REL-005 | Startup order assumptions without wait/retry | Random boot failures → readiness waiting | CONFIG | compose/k8s |
| REL-006 | Graceful shutdown not implemented (SIGTERM ignored) | Dropped requests on deploys → drain | L1 | k8s |
| REL-007 | Long-lived connections not re-established | Silent dead sockets → reconnect logic | L1 | reliability |
| REL-008 | Unbounded in-memory queues between stages | OOM under burst → bounded + spill | L1 | SRE |
| REL-009 | Feature kill-switches absent for new risky paths | Can't disable fast → flags | MANUAL | SRE |
| REL-010 | Batch jobs without checkpointing | Full restart on partial failure → checkpoints | MANUAL | data |
| REL-011 | Single-instance stateful service | Restart loses users → externalize state | L1 | arch |
| REL-012 | Timeouts longer than upstream's own timeout | Retry storms amplification → tune hierarchy | L1 | SRE |
| REL-013 | Alerts on symptoms without runbooks | Alert fatigue → link runbooks | MANUAL | SRE |
| REL-014 | Logs without request/correlation IDs | Can't trace incidents → propagate IDs | L1 | observability |
| REL-015 | Structured logging absent (free-text only) | Unqueryable ops → JSON logs | L1 | observability |
| REL-016 | Metrics for saturation/errors missing | Blind to degradation → RED/USE | MANUAL | SRE |
| REL-017 | Silent catch-and-default on parse errors | Corrupt data spreads fast → fail loudly | MANUAL | data |
| REL-018 | Config validated only at runtime deep in call paths | Late failures → validate at boot | L1 | config |
| REL-019 | Timezone-mixed cron/cron-like schedules | Jobs fire at wrong hours → UTC everywhere | CONFIG | ops |
| REL-020 | File descriptors/sockets never capped or monitored | FD exhaustion → limits + metrics | RUNTIME | ops |
| REL-021 | Memory limits absent on workers | OOM killer chaos → cgroup limits | CONFIG | k8s |
| REL-022 | External state mutated during deploys in-place | Drift between versions → migrations | MANUAL | ops |
| REL-023 | Data backups never restore-tested | Backup theater → scheduled restores | MANUAL | ops |
| REL-024 | Queue depth unmonitored | Latency creep invisible → dashboards + alerts | CONFIG | SRE |
| REL-025 | Client-side circuit state not shared | Partial protection → centralized breaker | L1 | resilience |
| REL-026 | Long transactions holding locks during retries | Deadlock amplification → shorten + backoff | L1 | DB |
| REL-027 | Pagination cursors opaque to concurrent inserts | Skips/duplicates rows → stable cursors | L1 | DB |
| REL-028 | Third-party JS/widgets fail → page breaks | Render blocking deps → async + fallbacks | L0 | web |

## 11. Containers, cloud & infrastructure

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| INF-001 | Container runs as root | Privilege escape blast radius → non-root user | CONFIG | Picus Top-10 |
| INF-002 | `latest` base image tag | Unreproducible builds → digest pinning | SHIPPED SP202 | supply chain |
| INF-003 | No resource requests/limits on pods | Node starvation/noisy neighbors → set both | CONFIG | k8s |
| INF-004 | Missing NetworkPolicy (allow-all default) | Lateral movement → default deny | CONFIG | arXiv k8s study |
| INF-005 | Secrets as plain env in manifests | Leak via describe/logs → secret volumes/KMS | CONFIG | Red Hat |
| INF-006 | Dashboard/admin services exposed publicly | No-auth admin → bind internal + auth | CONFIG | KubeOps |
| INF-007 | `hostPort`/`hostNetwork` used casually | Port conflicts + exposure → avoid | CONFIG | k8s |
| INF-008 | Privileged containers / extra capabilities | Container escape → drop caps, no privileged | CONFIG | Picus |
| INF-009 | readOnlyRootFilesystem not set | Tampering persists → immutable fs + tmp volumes | CONFIG | hardening |
| INF-010 | Image scanning absent in CI | Known CVEs ship → trivy/grype gate | DEP | supply chain |
| INF-011 | Writable volume mounts of host paths | Host compromise → named volumes | CONFIG | hardening |
| INF-012 | TLS terminated but internal hops plaintext | MITM inside cluster → mTLS | CONFIG | zero trust |
| INF-013 | Public S3/object buckets | Data exposure → private + signed URLs | CONFIG | CSPM |
| INF-014 | Over-permissive IAM (`*` actions/resources) | Blast radius → least privilege | CONFIG | CSPM |
| INF-015 | Security groups 0.0.0.0/0 on admin ports | Open DBs/SSH → narrow rules | CONFIG | CSPM |
| INF-016 | No autoscaling on bursty service | Overload or cost spikes → HPA | CONFIG | k8s |
| INF-017 | Single AZ deployment | AZ outage = downtime → multi-AZ | CONFIG | SRE |
| INF-018 | DNS TTLs too high for failover | Slow failover → lower TTL on switched records | CONFIG | ops |
| INF-019 | Startup probes missing on slow-boot apps | Kill loop before ready → probes | CONFIG | k8s |
| INF-020 | Logs shipped from containers as files only | Lost on evict → stdout/log agent | CONFIG | ops |
| INF-021 | `.dockerignore` missing (build context bloat + leaks) | Slow builds + secret copies → ignore | CONFIG | docker |
| INF-022 | apt/apk upgrade at container build | Non-reproducible layers → pin versions | CONFIG | docker |
| INF-023 | ENTRYPOINT shell form (PID1 problems) | Signals not delivered → exec form | L0 | docker |
| INF-024 | No init process reaping zombies in containers | PID table fills → tini/dumb-init | CONFIG | docker |
| INF-025 | Config baked into image instead of injected | Rebuild-per-env → env/configmaps | CONFIG | 12factor |

## 12. CI/CD, git & supply chain

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| CI-001 | GitHub Action pinned by mutable tag | Supply-chain hijack (tj-actions-style) → SHA pin | SHIPPED SP203 | zizmor research |
| CI-002 | Workflow with `pull_request_target` + checkout of PR head | Script injection from forks → avoid combo | CONFIG | GH docs |
| CI-003 | Secrets echoed in build logs | Leak in CI history → mask + omit | SHIPPED SP204 | CWE-532 |
| CI-004 | `continue-on-error: true` on security jobs | False green → remove | L0 | CI hygiene |
| CI-005 | Unpinned third-party actions in critical path | Compromise risk → pin + audit | SHIPPED SP203 | supply chain |
| CI-006 | Deploy keys/tokens with write-all repo scope | Blast radius → least scope | CONFIG | GH |
| CI-007 | No branch protection on default branch | Direct pushes bypass review → protection | CONFIG | Scorecard |
| CI-008 | Lockfiles not committed | Unreproducible builds → commit | DEP | packaging |
| CI-009 | Post-install scripts enabled in CI installs | Arbitrary code at install → `--ignore-scripts` | CONFIG | npm |
| CI-010 | Force-push shared branches | History loss → policy | MANUAL | git |
| CI-011 | Secrets committed then "deleted" in next commit | Still in history → rotate + purge | SHIPPED SP001-3 | gitleaks |
| CI-012 | CI green required but tests skipped silently | False confidence → fail on skip drift | MANUAL | testing |
| CI-013 | Release artifacts built from forks without provenance | Trust gap → sigstore/attestations | DEP | SLSA |
| CI-014 | Migrations auto-applied on app boot in prod | Surprise schema drift → explicit migration step | L1 | DB ops |
| CI-015 | Cron workflows without concurrency guard | Overlapping runs corrupt state → concurrency groups | L0 | GH Actions |

## 13. Data integrity & correctness

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| DAT-001 | Money math in binary floats | Cent drift → integer/decimal | L1 | classic |
| DAT-002 | Currency conversions without explicit rate timestamp | Audit ambiguity → store rate+time | L1 | fintech |
| DAT-003 | IDs as floats in JSON parsers (64-bit overflow) | Silent ID corruption → strings | L1 | JS classic |
| DAT-004 | Encoding assumed UTF-8 without declaration | Mojibake/loss → explicit charset | L1 | i18n |
| DAT-005 | Collation-sensitive uniqueness not enforced | Case-variant duplicates → CITEXT/normalize | CONFIG | DB |
| DAT-006 | Time stored without timezone | DST ambiguity → tz-aware | CONFIG | PG |
| DAT-007 | Validation schema evolved without backfill | Old rows violate new rules → migration | MANUAL | data |
| DAT-008 | Soft-delete rows included in unique constraints | Conflicts on recreate → partial index | CONFIG | DB |
| DAT-009 | Enum-like status stored as free text | Invalid states appear → CHECK/enum | L1 | DB |
| DAT-010 | Bulk update without dry-run/backup | Mass corruption → staged rollout | MANUAL | ops |
| DAT-011 | Input trusted after client normalization only | Bypass via raw requests → server normalization | DATAFLOW | security |
| DAT-012 | Aggregations over soft-deleted/filtered rows inconsistently | Wrong KPIs → single filter source | DATAFLOW | analytics |

## 14. AI/LLM-specific engineering

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| AI-001 | Unmetered public LLM endpoint | Bill DoS → auth + rate limits | SHIPPED SP501 | cost |
| AI-002 | Prompts containing user data sent to vendors | Privacy/exfiltration → redact/DPAs | DATAFLOW | policy |
| AI-003 | Model output rendered as HTML/markdown unsanitized | XSS from generated content → sanitize | L1 | CWE-79 |
| AI-004 | Tool/function-calling schema accepts arbitrary paths | Agent path traversal → allowlist | L1 | MCP sec |
| AI-005 | Agent credentials over-scoped (root keys for one task) | Blast radius → per-task creds | CONFIG | MCP sec |
| AI-006 | Unbounded agent loops (no step/token budget) | Runaway cost/infinite loops → budgets | L1 | agents |
| AI-007 | Embedding corpus re-embedded per query | 100x waste → cache vectors at upsert | RUNTIME | RAG perf |
| AI-008 | RAG retrieval without k/top-k bounds | Cost + noise → cap k | L1 | RAG |
| AI-009 | Hallucinated API/library names unverified | Runtime breakage → verify symbols compile | RUNTIME | pilotai-style |
| AI-010 | Generated code merged without regression tests | Quiet regressions → require tests in loop | MANUAL | process |
| AI-011 | Prompt-injectable system prompts from untrusted content | Instruction hijack → isolate channels | DATAFLOW | OWASP LLM |
| AI-012 | LLM decisions recorded without input trace | Unauditable → log prompts/outputs | MANUAL | audit |
| AI-013 | Fallback to eval/exec for "flexible" parsing | RCE → structured parsing | SHIPPED SP101 | CWE-95 |
| AI-014 | Vector store without access filters | Cross-tenant retrieval → tenant-scoped search | DATAFLOW | RAG sec |
| AI-015 | Model version unpinned in API calls | Silent behavior drift → pin + eval | L0 | MLOps |

## References

- SQL anti-patterns: [Stack Overflow: most common SQL anti-patterns](https://stackoverflow.com/questions/346659/what-are-the-most-common-sql-anti-patterns), [SO: database mistakes by application developers](https://stackoverflow.com/questions/621884/database-development-mistakes-made-by-application-developers), [SQL Anti-Patterns You Should Avoid](https://datamethods.substack.com/p/sql-anti-patterns-you-should-avoid), [3 common SQL mistakes that silently kill performance](https://levelup.gitconnected.com/3-common-sql-mistakes-that-silently-kill-performance-731880bac026), [Common SQL mistakes developers make](https://lackofimagination.org/2023/12/common-sql-mistakes-developers-make/)
- PostgreSQL/MySQL: [PostgreSQL mistakes you're probably making](https://levelup.gitconnected.com/postgresql-mistakes-youre-probably-making-and-how-to-fix-them-544ade3ed69c), [PostgreSQL query anti-patterns](https://mydba.dev/blog/postgres-query-anti-patterns), [Rookie Postgres mistakes (Reddit)](https://www.reddit.com/r/PostgreSQL/comments/fn7g7n/how_to_avoid_some_common_rookie_mistakes_in/), [Top 10 MySQL mistakes (SitePoint)](https://www.sitepoint.com/mysql-mistakes-php-developers/), [MySQL performance pitfalls (Releem)](https://releem.com/blog/mysql-performance-optimization-pitfalls)
- Async Python: [Async Python: mistakes I see every team make](https://levelup.gitconnected.com/async-python-the-mistakes-i-see-every-team-make-4462a40a7c53), [Asyncio mistakes that burned me](https://python.plainenglish.io/asyncio-mistakes-that-burned-me-and-how-i-fixed-them-3f4359e67a47), [Reddit r/Python: 5 common asyncio errors](https://www.reddit.com/r/Python/comments/10isqfj/5_common_asyncio_errors_and_how_to_avoid_them/), [Async-SIG best practices](https://discuss.python.org/t/asyncio-best-practices/12576)
- Kubernetes: [Misconfigurations make up 59% of k8s security incidents (Altoros)](https://www.altoros.com/blog/misconfigurations-make-up-59-of-kubernetes-security-incidents/), [Red Hat: most common k8s security issues](https://www.redhat.com/en/blog/most-common-kubernetes-security-issues-and-concerns-to-address), [Ten most common k8s security misconfigurations (Picus)](https://www.picussecurity.com/resource/blog/the-ten-most-common-kubernetes-security-misconfigurations-how-to-address-them), [Defending k8s clusters against network misconfigurations (arXiv)](https://arxiv.org/html/2506.21134v1)
- AI-code security context: [Veracode GenAI code security research](https://www.veracode.com/blog/genai-code-security-research/), [SecurityScan.ai on securing AI-generated code](https://securityscan.ai/securing-ai-generated-code/), CodeQL changelog (query counts), Semgrep rules licensing (see docs/research.md in this repository).
- Framework and language references: React docs (hooks/effects), Node.js docs (event loop, streams), Redis docs, Django/Flask/FastAPI security checklists, OWASP ASVS v4, OWASP Top 10, MITRE CWE corpus, Google SRE book, AWS Well-Architected Framework.

## 15. Vibe coding & AI-agent engineering

Grounding: an Escape.tech scan of 5,600 vibe-coded apps found 2,000+ vulnerabilities and 400+ exposed secrets ([ox.security](https://www.ox.security/blog/vibe-coding-security/)); the Cloud Security Alliance confirmed 74 AI-linked CVEs through March 2026 and reports 62% of AI-generated solutions contain design flaws ([CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_ai_codegen_vulnerability_debt_20260406-csa-styled.pdf), [Georgia Tech](https://news.research.gatech.edu/2026/04/13/bad-vibes-ai-generated-code-vulnerable-researchers-warn)); Wiz found 20% of vibe-coded apps seriously flawed ([Kaspersky summary](https://www.kaspersky.com/blog/vibe-coding-2025-risks/54584/)).

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| VB-001 | Plaintext API keys shipped in vibe-coded apps | 400+ secrets found in 5,600-app scan → scan + rotate | SHIPPED SP001-3/SP003 | Escape.tech |
| VB-002 | Auth "working" only as UI gating | 75% of scanned apps had exploitable gaps → server checks | SHIPPED SP108 | community scan |
| VB-003 | Agent invents package names (slopsquatting bait) | Typosquat installs malware → verify deps exist | DEP | CSA note |
| VB-004 | Hallucinated SDK methods pass review but crash at runtime | Broken prod paths → compile/smoke gates | RUNTIME | GT research |
| VB-005 | Generated config exposes admin dashboards by default | No-auth admin on public URL → bind + auth | CONFIG | Wiz |
| VB-006 | Debug mode left on because the template had it | Verbose errors/debugger RCE → production flags | SHIPPED SP201 | classic |
| VB-007 | "It works on the demo" — no tests ever written | Regressions ship silently → test requirement in loop | MANUAL | process |
| VB-008 | CORS set to permissive to make the demo call work | Any-site reads → exact origins | SHIPPED SP107 | Escape.tech |
| VB-009 | Database URL with credentials pasted into client env | Full DB in browser → server-only | SHIPPED SP403/SP503 | Wiz |
| VB-010 | Agent loops retrying failed builds burning tokens/cost | Runaway spend → budgets + stop conditions | L1 | cost |
| VB-011 | Accept-all file upload added for convenience | Malicious payload storage → validate | L1 | Escape.tech |
| VB-012 | Generated SQL works but is injection-vulnerable | SQLi class of AI-linked CVEs → parameterize | SHIPPED SP103/SP118 | GT research |
| VB-013 | Command injection via "flexible" shell features | Critical class in AI-linked CVEs → argv | SHIPPED SP102 | GT research |
| VB-014 | Agent deletes/rewrites guardrails to make tests pass | Weakened security silently → review diffs of policy files | MANUAL | process |
| VB-015 | Secrets committed while iterating with the agent | Permanent history leak → pre-commit scan | SHIPPED SP001-3 | gitleaks-class |
| VB-016 | No rate limiting anywhere on new AI-first endpoints | Abuse + bill shock → throttling | SHIPPED SP402/SP501 | cost |
| VB-017 | Generated code calls internal services from public handlers | SSRF surface → allowlists | SHIPPED SP109/SP124 | CWE-918 |
| VB-018 | Migration files generated but never reviewed/applied deliberately | Schema drift → migration gate | MANUAL | DB ops |
| VB-019 | Copy-pasted Stack-overflow-style license headers stripped | License contamination → attribution check | MANUAL | legal |
| VB-020 | Agent-generated regexes with catastrophic backtracking | ReDoS on user input → rewrite | SHIPPED SP114 | CWE-1333 |
| VB-021 | Env vars read client-side only (config illusion) | Silent feature breakage in prod → runtime config | L1 | config |
| VB-022 | One giant handler doing auth+logic+IO | Untestable risk blob → layering | MANUAL | arch |
| VB-023 | Generated API lacks pagination from day one | Table growth = outage → paginate now | SHIPPED SP302/SP305 | scale |
| VB-024 | Timeouts absent because agent never waited long | Hangs under real latency → timeouts | SHIPPED SP304 | SRE |
| VB-025 | Secrets echoed into LLM prompts for "debugging" | Secrets in vendor logs → redact | DATAFLOW | policy |
| VB-026 | Prompt/agent code trusted with filesystem write everywhere | Blast radius → scoped workspaces | CONFIG | MCP sec |
| VB-027 | Generated tests assert on implementation not behavior | Green but meaningless → behavior tests | MANUAL | process |
| VB-028 | Accepting agent's claim "security handled" without evidence | Trust gap → verify with independent scan | MANUAL | ShipProof thesis |
| VB-029 | Dependency versions pasted from stale training data | Known-CVE versions installed → SCA gate | DEP | CSA note |
| VB-030 | Multiple agents editing same module without merge discipline | Conflicting invariants → small PRs | MANUAL | process |
| VB-031 | Error swallowing to keep agent loop unblocked | Silent corruption → explicit failure | MANUAL | SRE |
| VB-032 | Feature flags hardcoded true to "unblock" demo | Dead flags hide risk → flag hygiene | L0 | config |
| VB-033 | Generated IaC with public buckets/ports by default | Cloud exposure → policy-as-code | CONFIG | Wiz |
| VB-034 | No rollback path for vibe-shipped deploys | Incident length → revert drill | MANUAL | SRE |
| VB-035 | Agent code assumes happy-path responses (no 4xx/5xx handling) | Crashes on real-world responses → error paths | L1 | reliability |

## 16. Go

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| GO-001 | Goroutine started per request without lifecycle bound | Leaks under load → errgroup/context | L1 | 100 Go Mistakes |
| GO-002 | Blocking send on unbuffered channel with no receiver | Goroutine leak/deadlock → select+ctx | L1 | Go docs |
| GO-003 | `for range` channel without ctx cancellation | Never exits → ctx ranges | L1 | Go docs |
| GO-004 | Loop variable captured in goroutine pre-1.22 semantics | All see last value → per-iteration copy (or 1.22+) | L1 | Go 1.22 notes |
| GO-005 | Write to nil map | Panic on first write → make() | L1 | spec |
| GO-006 | Ignoring returned error (`_ =` or bare call) | Silent failures → handle or comment why | L1 | errcheck |
| GO-007 | `defer` inside loop | Resource held until function end → refactor scope | L1 | 100 Go Mistakes |
| GO-008 | HTTP response body not closed (or closed before read) | FD/goroutine leak | SHIPPED SP315 | net/http |
| GO-009 | `err == nil` checked but typed nil interface returned | "nil but not nil" → return error explicitly | L1 | Go FAQ |
| GO-010 | Mutex copied by value (struct with sync fields passed around) | Broken locking → pointer/mutex guard | L1 | go vet |
| GO-011 | `time.After` in hot loop | Timer leak per iteration → Ticker/NewTimer+Stop | L1 | perf |
| GO-012 | Unbounded goroutine fan-out | Resource exhaustion → worker pool | SHIPPED SP306 | Go patterns |
| GO-013 | `context.Background()` used in request path | No cancellation/trace → derive from request ctx | L1 | Go blogs |
| GO-014 | Slice aliasing after append capacity growth | Hidden shared buffers → copy when sharing | L1 | spec |
| GO-015 | String concatenation in hot loop | Quadratic → strings.Builder | L1 | perf |
| GO-016 | Map iteration order assumed stable | Random by design → sort keys | L1 | spec |
| GO-017 | Shadowed `err` in nested scopes | Errors lost → rename/receive | L1 | go vet shadow |
| GO-018 | Closing over loop `wg` misuse (Add inside goroutine) | WaitGroup races → Add before go | L1 | sync docs |

## 17. Rust

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| RS-001 | `unwrap()`/`expect()` in service paths | Panic kills request/task → propagate Results | L1 | tzutoo/medium |
| RS-002 | Arithmetic overflow relying on debug panics | Release silently wraps → checked/saturating | L1 | corrode.dev |
| RS-003 | `unsafe` blocks used "C-style" to dodge borrow rules | Soundness holes → isolate + document | L1 | users.rust-lang |
| RS-004 | `.clone()` sprinkled to appease the borrow checker | CPU/alloc waste → borrows/refs | L1 | reintech |
| RS-005 | Slice indexing with unvalidated user index | Panic on out-of-bounds → get() | L1 | bad-habits |
| RS-006 | `panic = abort` combined with catch_unwind assumptions | Process dies on panic → review policy | CONFIG | cargo docs |
| RS-007 | Blocking IO inside async fn (tokio) | Executor starvation → spawn_blocking | L1 | tokio docs |
| RS-008 | Holding std MutexGuard across .await | Deadlock risk → scope guards | L1 | tokio |
| RS-009 | `unwrap_or_default()` masking real errors | Silent wrong behavior → explicit match | L1 | practice |
| RS-010 | Large `move` closures copying big structures | Memory blowup → references/Arc | L1 | perf |
| RS-011 | Ignoring `Result` with `let _ =` | Errors dropped → handle | L1 | clippy |
| RS-012 | Building unbounded channels | OOM under burst → bounded | L1 | tokio |
| RS-013 | `String` vs `&str` misuse in APIs | needless clones/allocs → &str params | L1 | clippy |
| RS-014 | Tests only on happy path because errors are typed | Error paths untested → table tests on Err | MANUAL | practice |
| RS-015 | Feature flags altering API silently | Surprise breakage → documented semantics | MANUAL | cargo |

## 18. Java / JVM

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| JV-001 | `==` on boxed types/strings | Identity vs equality bugs → equals | L0 | JLS |
| JV-002 | SimpleDateFormat shared statically | Thread corruption → java.time/ThreadLocal | L1 | classic |
| JV-003 | Streams/Connections not closed on exception | Resource leak → try-with-resources | L1 | effective java |
| JV-004 | Catching generic Exception to silence | Swallows everything → narrow types | L0 | Sonar-class |
| JV-005 | String concat in loops | Quadratic → StringBuilder | L1 | perf |
| JV-006 | HashMap mutated during iteration | ConcurrentModificationException → concurrent maps | L1 | JDK |
| JV-007 | equals without hashCode | Broken hashing collections → implement both | L1 | effective java |
| JV-008 | `Optional.get()` without check | NoSuchElementException → orElse/ifPresent | L1 | API notes |
| JV-009 | New thread per request (no pool) | Resource exhaustion → executors | L1 | classic |
| JV-010 | Unbounded core pool / unbounded LinkedBlockingQueue | Task pile-up → bounded queues + policy | L1 | JDK |
| JV-011 | Double-checked locking without volatile | Broken publishing → holder/volatile | L1 | JMM |
| JV-012 | Timezone-default Date formatting | Wrong hours across regions → ZonedDateTime | L1 | java.time |
| JV-013 | `System.currentTimeMillis` for durations | Clock skew/monotonic issues → nanoTime | L1 | classic |
| JV-014 | Reflection-heavy hot paths | CPU + JIT degradation → caches | RUNTIME | perf |
| JV-015 | Static mutable state in webapps (WAR classloaders) | Leaks across redeploys → instances | L1 | app-servers |

## 19. C# / .NET

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| CS-001 | `.Result`/`.Wait()` on async in context | Classic deadlock → async all the way | L1 | Stephen Cleary |
| CS-002 | `async void` outside event handlers | Unobservable exceptions → Task | L1 | MSDN |
| CS-003 | Missing `ConfigureAwait(false)` in libraries | Context capture overhead/deadlock | L1 | MSDN |
| CS-004 | Fire-and-forget tasks without exception observation | Silent failures → store/await | L1 | TPL |
| CS-005 | `DateTime.Now` for measurement | Skew → Stopwatch/UtcNow | L1 | classic |
| CS-006 | Disposables not disposed (no using) | Handles leak → using/Dispose | L1 | Roslyn |
| CS-007 | CancellationToken ignored in long ops | Unstoppable work → pass tokens | L1 | TPL |
| CS-008 | Locks held across awaits | Deadlocks → SemaphoreSlim + scope | L1 | practice |
| CS-009 | String concatenation in hot loops | GC pressure → StringBuilder | L1 | perf |
| CS-010 | `ToList()` everywhere mid-LINQ | N enumerations materialized → compose first | L1 | LINQ |
| CS-011 | HttpContext accessed after response/_background | Null/object-disposed → capture needed data | L1 | ASP.NET |
| CS-012 | Sync IO in ASP.NET (classic pipeline) | Thread starvation → async IO | L1 | ASP.NET |

## 20. PHP / Ruby / other ecosystems

| ID | Failure mode | Why it matters → fix | Detection | Refs |
| --- | --- | --- | --- | --- |
| PHP-001 | `unserialize` on user input | Object injection RCE | SHIPPED SP113 | CWE-502 |
| PHP-002 | String interpolation into SQL/HTML without escaping | SQLi/XSS → prepared statements/escape | L0 | OWASP PHP |
| PHP-003 | `==` loose comparison (0 == "string") | Auth bypass class → `===` | L0 | PHP docs |
| PHP-004 | `extract($_GET)`/register_globals-style patterns | Variable injection → explicit input | L0 | classic |
| PHP-005 | `$_FILES` trusted by extension only | Malicious uploads → magic-byte checks | L1 | OWASP |
| PHP-006 | session autostart with default cookie flags | Theft → secure flags | CONFIG | php.ini |
| RB-001 | `eval` in DSL/config handling | RCE → safe parsing | SHIPPED SP101 | CWE-95 |
| RB-002 | `send_file` with user path | Traversal → allowlist | L1 | Rails |
| RB-003 | Mass assignment without strong params | Privilege escalation → permit lists | L1 | Rails |
| RB-004 | N+1 in ActiveRecord loops | Query storms → includes | SHIPPED SP307-class | Rails |
| RB-005 | `rescue => nil` swallowing | Silent failures → handle | L0 | practice |
| SEC-CC-001 | C: `strcpy`/`sprintf`/`gets` family | Buffer overflows → bounded APIs | L0 | CWE-120 |
| SEC-CC-002 | C: format string from user | Info leak/write → constants | L0 | CWE-134 |
| SEC-CC-003 | C++: dangling pointers/refs after container growth | UB → stable iterators/refs | DATAFLOW | core |
| SEC-CC-004 | Swift/Kotlin: force unwraps (`!`/`!!`) in app code | Crashes → safe handling | L1 | idioms |

## 21. Recommended datasets (Hugging Face and public)

For building evaluation corpora aligned with the catalog categories. Always re-license-check per dataset and never redistribute restricted corpora inside ShipProof.

| Dataset | What it contains | Fit |
| --- | --- | --- |
| [DiverseVul (paper 2304.00409)](https://huggingface.co/papers/2304.00409) | 18,945 vulnerable functions (150 CWEs) + 330k benign, from fix commits in 933 C/C++ projects | Recall corpus for C/C++ rules; CWE diversity |
| [CIRCL/vulnerability-cwe-patch](https://huggingface.co/datasets/CIRCL/vulnerability-cwe-patch) | Structured real-world vulnerabilities enriched with CWE ids and patch refs | Maps CVE↔CWE↔fix to mine new L0/L1 patterns |
| [HF Repo2RLEnv cve_patches pipeline](https://github.com/huggingface/Repo2RLEnv/blob/main/docs/pipelines/cve_patches.md) | CVE/GHSA/PYSEC advisories linked to fix commits | Python/JS CVE fix-commit mining (our core languages) |
| OWASP Benchmark | Java SAST ground-truth suite | Java-adapter evaluation only |
| NIST SARD / Juliet | Multi-language synthetic weaknesses | Coverage smoke tests (language-filtered) |
| OSV.dev + GitHub GHSA feeds (API) | Live advisories per ecosystem | Continuous regression ingestion |
