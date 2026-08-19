# Draft: The failure modes of AI-written code (launch article)

> Status: owner draft for the ShipProof launch (Show HN / dev.to / Reddit).
> Every failure mode below maps to a shipped detector you can run today:
> `npx github:kingggg5/shipproof check`. Keep the article honest — only claim
> what the catalog actually proves (pattern L0 / structural L1 evidence).

---

AI coding agents have a specific signature: they write code that *looks*
production-ready. The imports resolve, the types fit, the happy path passes.
What slips through is everything a reviewer cannot see on a screenshot — and
everything a demo never exercises.

This is a field guide to the failure modes we kept finding in AI-written
repositories, written while building [ShipProof](https://github.com/kingggg5/shipproof),
a free, MIT-licensed, offline scanner with 200 deterministic detectors that checks
for exactly these classes before you ship. Every item below is a detector you can run in seconds:

```bash
npx github:kingggg5/shipproof check
```

## 1. Secrets with confidence

Agents love completing patterns. Ask for a Stripe integration and you get a
working one — sometimes with a test key committed "so it runs" (`SP003`), an
insecure fallback like `os.getenv("SECRET_" + "KEY", "dev-secret")` so the app
never crashes (`SP004`), or a Supabase `service_role` key pasted into a
`NEXT_PUBLIC_` variable (`SP403`, `SP503`) where it ships to every browser.

Across cloud ecosystems, agents paste Google Cloud service account JSONs (`SP005`),
GitHub Personal Access Tokens (`SP006`), AWS session keys (`SP007`), Slack bot tokens (`SP008`),
OpenAI keys (`SP010`), and vector database credentials like Pinecone/Qdrant (`SP509`).

**The tell:** credentials that exist so the demo works.
**The proof after the fix:** rotate the key, then grep the build artifact.

## 2. Injection the linter won't catch

TypeScript and Python both type-check fine while concatenating SQL
(`SP103`, `SP128` territory) or compiling strings into code — `eval`,
`exec`, `new Function(...)` (`SP101`, `SP117`), timer strings
(`setTimeout("run('"+name+"')")`, `SP118`), and deserialization of
attacker-shaped payloads: `pickle`, `yaml.load`, `node-serialize`
(`SP106`, `SP120`).

In web applications, agents routinely reach for template strings in Server-Side
Template Injection (`render_template_string(f"Hello {user}")`, `SP137`),
dynamic DOM rendering in React via `dangerouslySetInnerHTML` (`SP116`),
Vue `v-html` bindings without sanitization (`SP415`), and Angular
`DomSanitizer.bypassSecurityTrustHtml` calls (`SP125`).

**The tell:** "it builds the query dynamically for flexibility."
**The proof:** submit a quote, a semicolon, or a serialized object and watch
it be treated as data, not code.

## 3. Doors without locks

The route exists, the logic is correct, the authorization is missing. Admin
routes without an auth dependency (`SP108`), Next.js Server Actions exported without
session validation (`SP420`), Express apps without helmet (`SP401`), auth endpoints
without rate limiting (`SP402`), cookie sessions without CSRF protection (`SP407`, `SP417`),
Next.js configs without a CSP header (`SP408`), and Django settings with
`ALLOWED_HOSTS = ['*']` (`SP405`).

Individually each looks like a config choice. Together they are a burglar's
floor plan.

**The tell:** security that was "going to be added later."
**The proof:** a non-admin token against the admin route returns 403, not 200.

## 4. The server that fetches what it is told

Two variants, both common: SSRF — the agent writes `fetch(req.query.url)` or
`requests.get(user_url)` so your server dutifully dials internal networks and
cloud metadata (`SP109`, `SP124`) — and open redirects that lend your domain
to phishers (`SP121`, `SP130`).

**The tell:** a URL parameter that reaches a network call.
**The proof:** an internal address is rejected before the request leaves.

## 5. Crypto that is right-shaped and wrong

`Math.random()` for session tokens (`SP122`), hardcoded initialization
vectors (`SP123`), TLS verification switched off to make a staging call work
(`SP104`), string equality comparison on signatures vulnerable to timing attacks (`SP138`),
insecure temporary files created with `tempfile.mktemp()` (`SP139`), and JWTs
accepted without signature checks (`SP105`). All of it compiles. None of it protects.

**The tell:** crypto primitives chosen for brevity.
**The proof:** encrypt the same message twice; IVs and ciphertexts differ.

## 6. Scale bugs that only fire when you succeed

This class is invisible at demo scale and fatal in production: Redis `KEYS *`
on the event loop (`SP301`), `SELECT *` without bounds (`SP302`), unbounded
pagination (`SP305`), `Promise.all` over user-sized arrays (`SP306`), N+1
queries in loops (`SP307`), non-singleton database clients in serverless
(`SP313`), unindexed queries with `ORDER BY RAND()` (`SP323`) or leading wildcards (`SP322`),
and HTTP calls without timeouts that hold DB transactions open (`SP304`, `SP316`, `SP317`).

Our favorite, because it is pure AI era: retry loops with no stop condition
(`SP318`). The agent "improves reliability" and installs a retry storm that
turns a partner's 30-second blip into your outage.

**The tell:** code that assumes the happy path stays happy under load.
**The proof:** a load test — and ShipProof also generates a deterministic k6
starter from your reviewed capacity assumptions, because capacity arithmetic
is not a load test.

## 7. Multi-language signatures: how AI fails across stacks

AI agents produce characteristic failure modes that depend on the runtime semantics
of each programming language:

### Go (Golang)
- **Response body leak:** Forgetting `defer resp.Body.Close()` (`SP315`), exhausting socket file descriptors.
- **Ignored error returns:** Discarding errors with `_, _ = fn()` (`SP136`), hiding network and I/O failures.
- **Unbounded Goroutines:** Spawning `go func()` without `context.Context` cancellation (`SP309`), leaking background routines.
- **Channel deadlocks:** Sending to unbuffered channels without an active consumer (`SP332`).
- **Missing server timeouts:** Initializing `http.Server{}` without `ReadTimeout` or `WriteTimeout` (`SP131`), leaving servers vulnerable to Slowloris connection exhaustion.

### Python
- **Sync in Async:** Calling synchronous blocking libraries (`requests.get`, `time.sleep`) inside `async def` routes (`SP303`, `SP317`), stalling the asyncio event loop.
- **Garbage-collected tasks:** Calling `asyncio.create_task()` without saving a reference (`SP335`), allowing Python's GC to cancel background jobs mid-execution.
- **Stripped authorization:** Using `assert user.is_admin` for access control (`SP134`), which gets completely stripped when Python runs under `-O` optimization flags.
- **Uncapped FastAPI models:** Disabling Pydantic response filtering with `response_model=None` (`SP409`), leaking internal database fields.

### TypeScript / JavaScript & Node.js
- **Serverless connection storms:** Creating `new PrismaClient()` or `new Pool()` inside serverless route handlers (`SP313`), exhausting database connection pools under concurrency.
- **Event listener leaks:** Attaching `.on('data')` inside request handlers on long-lived emitters (`SP311`), creating memory leaks.
- **Piping without error listeners:** Using `readStream.pipe(writeStream)` without error event handlers (`SP336`), crashing the Node.js process on client disconnects.
- **Synchronous CPU crypto:** Calling `bcrypt.hashSync()` in web request threads (`SP339`), freezing the single-threaded event loop for 200ms per request.

### PHP
- **Type juggling authentication:** Using loose equality `==` to compare password hashes or tokens (`SP127`), enabling authentication bypasses.
- **Superglobal injection:** Interpolating `$_GET` or `$_POST` directly into SQL queries (`SP128`) or echoing them into HTML without escaping (`SP129`).
- **Object injection:** Deserializing untrusted input with `unserialize()` (`SP113`), enabling remote code execution.

### C# / .NET & ASP.NET
- **Sync-over-async thread starvation:** Calling `.Result` or `.GetAwaiter().GetResult()` on asynchronous tasks (`SP132`), blocking CLR ThreadPool worker threads.
- **Debug in configuration:** Shipping `debug="true"` in `web.config` (`SP133`) or calling `UseDeveloperExceptionPage` unconditionally in production (`SP418`).

### Java / Kotlin & Spring Boot
- **Exposed Actuator endpoints:** Exposing `/actuator/env` or `/actuator/heapdump` publicly without authentication (`SP416`), leaking environment secrets.
- **Binary deserialization:** Using `ObjectInputStream.readObject()` on untrusted input streams (`SP168`), enabling gadget chain RCE.

### Ruby on Rails
- **Disabled CSRF verification:** Calling `skip_before_action :verify_authenticity_token` globally in `ApplicationController` (`SP417`).
- **Unsafe deserialization:** Parsing payloads with `Marshal.load` or `YAML.load` (`SP106`).

### C / C++
- **Unbounded buffer copies:** Using legacy `strcpy`, `strcat`, or `gets` without bounds checking (`SP135`), creating memory corruption vulnerabilities.
- **Overly permissive permissions:** Creating files with world-writable permissions `0666` or `0777` (`SP169`).

## 8. The bill: modern AI & cloud payments

An unmetered LLM route is a Stripe webhook with the signature check removed,
pointed at your credit card (`SP501`). One `while True` agent loop in a public
endpoint is a DOS you pay for.

Mutating payment gateway calls (Stripe, Square, PayPal) without an `idempotency_key`
(`SP504`) turn network retries into duplicate customer charges. Insecure Stripe
webhooks that pass parsed JSON bodies instead of raw unparsed buffers (`SP502`)
or omit timestamp tolerance checks (`SP510`) allow forged payment events or replay attacks.

AI applications also introduce prompt injection via raw string interpolation (`SP505`),
unconstrained agent tool execution (`SP508`), unvalidated tool function calling (`SP506`),
and dangerous REPL execution tools like LangChain `PythonREPLTool` (`SP514`).

**The tell:** AI spend or payment gateway calls with no rate limit, idempotency, or signature verification.
**The proof:** 50 rapid requests; 49 are told "no."

## 9. The forgotten defaults

Debug mode on in production (`SP201`), raw errors sent to clients (`SP406`),
floating `FROM latest` base images (`SP202`), unpinned GitHub Actions
(`SP203`), running container processes as root (`SP205`), mounting the host Docker
socket into containers (`SP222`), and credential-bearing log lines (`SP204`).
Each is one line. Each has ended companies.

## What this is not

ShipProof is deliberately honest about evidence. Every finding is labeled with
a proof level: **L0** (pattern match) or **L1** (structural — Python AST,
whole-file analysis, or an inspected artifact). It does not claim data-flow,
taint, or runtime proof it cannot perform, and it never executes your code.
When you need deeper analysis it routes you to CodeQL, Semgrep, OSV-Scanner,
Gitleaks, and k6 instead of pretending to replace them.

That honesty is the product. In a world where agents generate ten thousand
lines before lunch, the scarce resource is not generation — it is proof that
what was generated should ship. [Try it on your repo](https://github.com/kingggg5/shipproof);
it runs in seconds, offline, and tells you exactly which of these failure
modes already live in your codebase.
