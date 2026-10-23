# Transport and cookie precision cohort — 2026-10-23

Status: implemented and locally verified; no release or independent certification.

## Contract and promotion decisions

Keep the default scan offline, read-only and dependency-free. Never evaluate
submitted code or open network connections. Reuse bounded lexical parsing (512
tokens per argument/object); unresolved aliases, spreads and overwritten bindings
stay silent. New signatures are structural L1 **advisory**, never blocking at any
severity/proof floor. Preserve existing IDs, severities, exit codes and corpus
thresholds. Every new rule needs at least 3 positive, 5 negative and 2 adversarial
cases, exercised through the real file walker, plus redaction and gate tests.

- Promote the explicit cookie-flag portion of **DOTNET-W1-09** into existing
  **SP056/SP084**, not duplicate IDs. Require a typed ASP.NET Core cookie/response/
  context parameter and direct `Append` with a sensitive literal name and an
  inline `CookieOptions` initializer explicitly setting HttpOnly/Secure false.
  Method and typed block-lambda parameters are supported; expression bodies are unresolved.
  Missing properties, ordinary preferences, unknown types and policy middleware
  remain outside this narrow signature. External cookie policy can override local
  options; no final browser header or exploit is inferred.
- **SP686**: imported Node TLS/HTTPS construction explicitly selects a legacy
  protocol floor. Do not infer a successful TLS 1.0/1.1 handshake: OpenSSL policy,
  peer negotiation and deployment can still prohibit it. Conflicting version
  options, explicit protocol masks and unknown context overrides stay unresolved.
- **SP687**: imported `ws` server explicitly disables its payload limit, including
  bounded decimal integers whose documented signed-32-bit conversion is nonpositive.
  An omitted option has a finite default and must stay silent. External transport
  limits and trusted workloads need review; do not claim demonstrated denial of service.

No new JWT key-size opt-out rule: generating a weak key already overlaps SP640;
the opt-out alone does not prove a weak signing key. No new Dart trust-root rule:
an empty trust store is not disabled certificate verification. Source/flow-based
Dart navigation and upload candidates remain research-only.

## Primary evidence

Context7 resolution was attempted for Node.js, ws and ASP.NET Core but returned a
monthly quota error. The following owning documentation/source was read directly:

- [Node TLS](https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions) and
  [HTTPS](https://nodejs.org/api/https.html#httpsrequesturl-options-callback):
  protocol range options, incompatible secureProtocol, OpenSSL/security context boundaries.
- [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996.html): TLS 1.0/1.1 deprecation;
  not a claim that a locally configured protocol was negotiated.
- [ws API](https://github.com/websockets/ws/blob/master/doc/ws.md) and
  [receiver implementation](https://github.com/websockets/ws/blob/master/lib/receiver.js):
  default 100 MiB, zero disables the limit, signed-32-bit coercion and positive-cap checks.
  [RFC 6455 section 10.4](https://www.rfc-editor.org/rfc/rfc6455.html#section-10.4)
  separately establishes the need for bounded frames and reassembled messages.
- [CookieOptions](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions?view=aspnetcore-10.0),
  [Append overload](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.iresponsecookies.append?view=aspnetcore-10.0),
  [cookie policy](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-10.0#cookie-policy-middleware):
  explicit flags and middleware override boundary, not authentication inference from a name.

Original detectors and fixtures only; no third-party detector pack or source copied.

## Budget and verification

The existing 500,000 packed / 1,870,000 unpacked byte ceilings remain fixed.
Exclude the maintainer launch-article draft and field-validation plan from npm;
retain their sources and public links. Scanner runtime, user guidance and required package assets
must remain present. Test full suite, package smoke, all MCP tools, rule assurance,
self-scan and unchanged paired-corpus precision. Record actual results below.

## Executed evidence

The original authoring generator supplies **125 cases** across two new IDs and
two C# extensions: 28 positives, 81 negatives/unresolved counterparts and 16
adversarial cases. All run through the real repository walker. Additional checks
cover suffix routing, oversized expressions, malformed lexical contexts, typed
parameter scope, raw/interpolated C# strings, advisory gates, inline ignores,
line-move fingerprints, secret-safe fix context and Python/Node result parity.
These directed fixtures are not an independently measured real-world false-positive rate.

Bounded runtime probes used Node **24.22.1**, ws **8.22.0**, .NET **8.0.29** and
**10.0.12**. No listener or external request was opened. A four-byte WebSocket
frame carrying two payload bytes was accepted with zero/overflowed limits and
rejected with an effective one-byte cap. In particular 4,294,967,296 became zero;
4,294,967,297 became one and still rejected the frame. The default server cap was
104,857,600. TLS context construction accepted legacy floors and rejected a
conflicting secureProtocol/minVersion pair; no handshake was tested.
DefaultHttpContext cookies omitted both flags for false and emitted both for true;
typed block lambdas and explicit empty constructors preserved that behavior.
The ws package was installed only in ignored test scratch space with lifecycle
scripts disabled; it is not a scanner or development dependency.

Existing paired-corpus replay retained **30 packages / 867 files** on each leg:
originals 130 application findings and 54 high/critical signature locations;
remediated copies 72 application findings, **0 high/critical**, 16 gate medium
findings, no blocked packages or budget violations. Original vulnerable evidence,
thresholds, labels, source pins and remediation recipes are unchanged. This corpus
does not establish representative precision for all new C# or transport signatures.

The unchanged `typescript-config` benchmark (1,000 files, 512,000 bytes, one
warm-up, three samples, one worker; Windows 11/Python 3.12.10) remained below the
8-second / 256-MiB budget with no findings. Before: [2.1265, 2.0628, 2.1576] s;
after: [2.1145, 2.1246, 2.0809] s. Median 2.1265 → 2.1145 s; p95 2.1576 →
2.1246 s. This small difference does **not** establish a speed improvement or
measure new C# workload throughput. Baseline: f8cb7bc6e9f2edd39be13362854c67a2db15d10d.
Both fixtures have SHA-256 `916704d070452dda42c16598eb8a235314cf630c7a7770b4ff2fc41f5ddd6705`.

Final local verification:

| Check | Result |
| --- | --- |
| `npm run check` | Pass: 908 Python tests (3 Windows symlink privilege skips), 2 demo tests, Node suites, manifest and isolated package smoke |
| Python coverage | 86% overall; new cookie helper 95%, shared JS configuration helper 96%; unchanged 80% floor |
| MCP SDK 1.32.1 / Node 24.22.1 | All five tools, including new snippets, passed with Zod 3.25.76 and 4.6.7 from source and fresh packed consumers; zero peer skips |
| Self-scan high gate | Exit 0, 479 selected files, 0 application / 32 intentional test findings, complete selected-file coverage |
| Rule assurance | 656/656 complete, no partial/uncontracted/metadata debt; 104 realistic-negative contracts, 552 near-miss-only, 419 high/critical realistic-negative debt unchanged |
| Package | 109 files, 485,592 packed / 1,868,410 unpacked bytes; original ceilings unchanged |
| Catalog / freshness | All 5,000 candidate identities preserved; derived duplicate references refreshed. Transport, TS, Node and PHP/native generators current |

Root dependencies were restored from the lockfile after the MCP matrix. There are
no new production or development dependencies. Tests and semantic review were
performed in the primary task; a separate helper handled mechanical catalog/docs
updates. This is not an independent security assessment. Remote CI results are
recorded on the pull request, not inferred from local passes.

## Next evidence, not automatic promotion

Label revision-pinned ASP.NET applications and Node TLS/ws services before any
blocking promotion. DOTNET-W1-09's authentication policy delegates still need
receiver/version semantics; Dart WebView navigation, upload paths and process
arguments need source-to-sink flow. JWT key opt-outs and unsafe-named SQL methods
must not become stand-alone vulnerability claims. Expand those boundaries only
with both vulnerable and genuinely remediated counterparts.
