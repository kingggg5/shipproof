# Promotion wave C — Dart and C#/.NET scoped coverage

Date: 2026-09-16 · Status: existing-rule extensions · New IDs: **0**

This wave increases Dart and C#/.NET coverage without creating duplicate rule
IDs. The existing root-cause contracts remain stable and every new syntax shape
has a safe counterpart in the walker tests.

| Existing rule | Added syntax | Safe boundary |
| --- | --- | --- |
| SP104 | C# `ServerCertificateCustomValidationCallback` accepting every certificate; Dart `SecurityContext(withTrustedRoots: false)` | Pinned callbacks and `withTrustedRoots: true` stay silent. |
| SP109 | C# `new HttpRequestMessage(..., Request.Query/Form/Headers)` | Configured service URLs stay silent. |
| SP121 | C# `RedirectPermanent`, `RedirectPreserveMethod`, and `Results.Redirect` request targets | Constant local paths stay silent. |

The extensions are medium-scope implementation changes to already-tested root
causes; they do not change severity, blocking eligibility, fingerprints, or the
5,000-candidate research catalog. See [Wave 1](dart-dotnet-wave-1.md) for the
source boundary and [Wave B](promotion-wave-b.md) for the latest new-ID
promotions.

Current correction (2026-10-23): the historical Dart trust-root entry above is not
the current detector contract. An empty trust store is not a TLS verification
bypass; SP104 now requires an explicit acceptance opt-out. See the updated
[Wave 1 disposition](dart-dotnet-wave-1.md#current-disposition-update-2026-10-23).
