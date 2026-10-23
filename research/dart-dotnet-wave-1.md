# Dart and C#/.NET Wave 1 — research candidates and scoped promotions

Date: 2026-09-16 · Status: staged promotion · New executable rule IDs: **0** · Existing-rule extensions: **6**

This is the first 20-item slice of the larger promotion program. Fourteen records
remain research-only and are not `SPxxx` findings. Six high-signal cases extend
existing rules with dedicated positive/negative walker tests; they preserve the
existing rule IDs, severities, gates, and fingerprints. Existing coverage wins
over a duplicate candidate.

Primary references used for the initial review include [Dart static analysis](https://dart.dev/tools/dart-analyze), [Dart null safety](https://dart.dev/null-safety), [Dart `HttpOverrides`](https://api.dart.dev/dart-io/HttpOverrides-class.html), [Flutter networking](https://docs.flutter.dev/data-and-backend/networking), [webview_flutter](https://pub.dev/packages/webview_flutter), [.NET security analysis](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings), [ASP.NET Core authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction), [CA2100 parameterized SQL](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2100), [ASP.NET Core file uploads](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/file-uploads), and [ASP.NET Core data protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction).

## Promotion protocol

Each candidate needs:

1. A source-specific trigger and an explicit sink or unsafe state.
2. Three positive, five realistic-negative, and two adversarial cases for a pilot detector.
3. A test that runs through the repository walker with the correct suffix/manifest.
4. A duplicate comparison against existing `SP001–SP665` findings and native analyzer evidence.
5. A reviewed precision sample before severity or gate eligibility changes.

## Dart / Flutter

| ID | Candidate | Risk / mapping | Detection boundary | Route |
| --- | --- | --- | --- | --- |
| DART-W1-01 | `Random()` used for token, OTP, reset code, nonce, or key | CWE-338 | Require security-sensitive name plus `Random().nextInt/nextDouble`; allow UI/game/simulation randomness | Extend existing SP624 only after pairs |
| DART-W1-02 | `badCertificateCallback` accepts every certificate | CWE-295 | Require callback returning true or unconditional acceptance in `HttpClient`/`HttpOverrides`; test hostname-scoped pinning as safe | Pattern pilot |
| DART-W1-03 | `HttpOverrides.createHttpClient` disables TLS verification | CWE-295 | Require override plus `badCertificateCallback` or `SecurityContext(withTrustedRoots: false)`; do not flag ordinary overrides | Structural pilot |
| DART-W1-04 | WebView unrestricted JavaScript with untrusted navigation | CWE-79/CWE-939 | Require `JavaScriptMode.unrestricted` and a request/user-derived navigation path in the same controller flow | Structural; likely advisory |
| DART-W1-05 | WebView navigation has no host allowlist | CWE-601 | Only for controllers that load request/deep-link URLs; static first-party URLs stay silent | Structural |
| DART-W1-06 | Credential/token stored in `SharedPreferences` | CWE-922 | Require security-sensitive key plus `setString`; allow harmless preferences and encrypted-storage wrappers | Pattern pilot; advisory |
| DART-W1-07 | Authenticated request sent to literal `http://` endpoint | CWE-319 | Require an auth header/token/cookie in the same request construction; localhost/test fixtures are excluded | Pattern pilot |
| DART-W1-08 | `Process.run`/`Process.start` receives request or file input | CWE-78 | Require Dart `dart:io` binding and tainted argument flow; static command constants stay silent | Structural/data-flow |
| DART-W1-09 | File read/write path built from user input without containment | CWE-22 | Require request/deep-link input and a file sink; `path.normalize` alone is not a sanitizer | Structural/data-flow |
| DART-W1-10 | External URL launched from unvalidated user/deep-link input | CWE-601 | Require `url_launcher` call plus user/deep-link source; approved host allowlists are safe | Structural; advisory first |

## C# / .NET / ASP.NET Core

| ID | Candidate | Risk / mapping | Detection boundary | Route |
| --- | --- | --- | --- | --- |
| DOTNET-W1-01 | `Process.Start` receives request/form/query input | CWE-78 | Require a process sink and request-derived argument; fixed executable/argv stays silent | Structural/data-flow |
| DOTNET-W1-02 | `FromSqlRaw`/`ExecuteSqlRaw` receives interpolated SQL | CWE-89 | Require interpolation/concatenation inside EF Core raw SQL APIs; parameterized overloads are safe | Pattern + structural |
| DOTNET-W1-03 | `PhysicalFile`/`File` response path derives from request input | CWE-22 | Require a file-return sink and path derived from route/query/form data; fixed asset paths stay silent | Structural/data-flow |
| DOTNET-W1-04 | `IFormFile` saved with client filename or unrestricted destination | CWE-434/CWE-22 | Require `FileName`/`Name` reaching a filesystem sink; randomized basename and containment guard are safe | Structural/data-flow |
| DOTNET-W1-05 | `IHtmlHelper.Raw`/`Html.Raw` receives request-derived content | CWE-79 | Require raw HTML sink plus request/model input; trusted constant templates stay silent | Pattern + structural |
| DOTNET-W1-06 | Redirect target derives from request input without local allowlist | CWE-601 | Cover `Redirect`, `RedirectPermanent`, and Results redirects; `LocalRedirect` is safer but still needs validation context | Structural |
| DOTNET-W1-07 | `HttpClient`/`HttpRequestMessage` target derives from request input | CWE-918 | Require outbound request sink plus untrusted URL source; configured service URLs stay silent | Structural/data-flow |
| DOTNET-W1-08 | XML reader enables DTD/external resolution for untrusted XML | CWE-611 | Require `XmlReaderSettings.DtdProcessing = Parse` or external resolver plus untrusted source; safe `Prohibit`/`Ignore` stays silent | Pattern + structural |
| DOTNET-W1-09 | Cookie security explicitly weakened | CWE-614/CWE-1275 | Require `SecurePolicy.Never`, `HttpOnly = false`, or `SameSite=None` without Secure in cookie configuration; test legitimate cross-site flows | Pattern/config |
| DOTNET-W1-10 | Authorization policy is bypassed by endpoint metadata | CWE-862 | Require visible `[AllowAnonymous]` or `AllowAnonymous()` on sensitive route/controller, but preserve existing SP454 semantics and deduplicate before promotion | Extend existing SP454; no new duplicate |

## Wave disposition

- **Immediate executable candidate:** DART-W1-01 can extend SP624 after a contract pair proves Dart syntax and no false positives.
- **Structural candidates:** DART-W1-02/03/04/05/08/09 and DOTNET-W1-01/03/04/06/07/08 need source/flow context; broad regex is not acceptable.
- **Existing-rule extensions:** DOTNET-W1-02/05/09/10 should first be compared with SP103, SP454 and the current C# rules; new IDs are not justified if the engine can gain a precise ecosystem variant.
- **No candidate is blocking:** severity and gate eligibility remain unchanged until the promotion gate and representative labels pass.

This wave intentionally adds research records instead of noisy findings. The next promotion slice should implement DART-W1-01 plus one C# structural rule, then measure before selecting the next pair.

## First promotion slice status (2026-09-16)

- DART-W1-01 is implemented as a scoped extension of existing `SP624` rather than a duplicate rule ID. It recognizes security-sensitive Dart names assigned from `Random().nextInt/nextDouble` while keeping UI-animation randomness silent.
- DART-W1-02 is implemented as a scoped extension of existing `SP104`. It recognizes Dart `badCertificateCallback` callbacks that accept every certificate while keeping pinned-certificate callbacks silent.
- DOTNET-W1-02 is implemented as a scoped extension of existing `SP103`. It recognizes interpolated C# `FromSqlRaw`/`ExecuteSqlRaw`-style calls while keeping parameterized raw SQL silent.
- DOTNET-W1-03 is implemented as a scoped extension of existing `SP110`. It recognizes request-derived `Path.Combine` inputs while keeping static asset paths silent.
- DOTNET-W1-07 is implemented as a scoped extension of existing `SP109`. It recognizes `HttpClient` methods that receive `Request.Query/Form/Headers` values while keeping configured service URLs silent.
- DOTNET-W1-06 is implemented as a scoped extension of existing `SP121`. It recognizes `Redirect(Request.Query/Form/Headers)` while keeping fixed local redirect targets silent.
- All six extensions have walker-facing positive/negative tests and regenerated pattern contracts. Severity, gate eligibility, and rule count are unchanged. The remaining 14 records stay research-only until structural evidence exists.

## Wave 2 scoped extensions (2026-09-16)

- `SP104` now also recognizes C# `ServerCertificateCustomValidationCallback` unconditional acceptance and Dart `SecurityContext(withTrustedRoots: false)`; pinned callbacks and trusted roots stay silent.
- `SP109` now recognizes C# `HttpRequestMessage` targets built directly from `Request.Query/Form/Headers`; configured service URLs stay silent.
- `SP121` now recognizes C# `RedirectPermanent`, `RedirectPreserveMethod`, and `Results.Redirect` request targets; constant local destinations stay silent.

These are extensions of existing root causes, not duplicate IDs. They are covered
by walker-facing regression tests and remain subject to the same precision and
representative-repository gate as the research catalog.

## Current disposition update (2026-10-23)

DOTNET-W1-09 is now **partially implemented** under existing SP056/SP084: a typed
ASP.NET Core parameter, direct Append, sensitive literal cookie name and inline
CookieOptions with explicit HttpOnly/Secure false. These C# signatures are advisory
because middleware can alter the final header. CookieSecurePolicy/SameSite and
general authentication option delegates remain unimplemented; see the
[contract and validation](transport-cookie-cohort-2026-10.md).

The historical Wave 2 statement about `SecurityContext(withTrustedRoots: false)`
is superseded: an empty trust store does not disable certificate verification and
the current SP104 does not report it alone. SP670 likewise now requires combined
DTD parsing and external resolution with direct reader consumption, not either
option by itself. Remaining source-to-sink proposals still require flow evidence.
