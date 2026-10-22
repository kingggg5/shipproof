# PHP2Shell integration — verified 2026-10-22

Upstream disclosure: **2026-10-21**. This is the event requested by the user as a
one-to-three-day-old PHP issue, not a hypothetical application `eval` rule.

## Primary-source record

| Source | Supported claim | Boundary |
| --- | --- | --- |
| [PHP security announcement](https://www.php.net/archive/2026.php#2026-10-21-5) | Branch fixes are 8.2.35, 8.3.36, 8.4.27 and 8.5.12; vendor backports exist | Do not compare all branches against a single minimum or assume every vendor binary lacks fixes |
| [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | CVE-2026-109618 concerns request/OOM cleanup memory corruption | Not demonstrated by an application keyword; no exploit test or PHP execution is performed |
| [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | CVE-2026-109619 concerns stale state retained across worker requests | Actual runtime patch provenance, SAPI and attack path are not inferred from repository text |
| [Cloudflare coordinated-response note](https://blog.cloudflare.com/php-vulnerabilities-waf-protection) | Describes affected PHP history and coordinated protections | WAF protection is not recorded as a patched PHP binary |
| [Docker reference](https://docs.docker.com/reference/dockerfile/), [multi-stage builds](https://docs.docker.com/build/building/multi-stage/) | Stage inheritance, final default stage, continuations and escape directives | A nondefault build target and dynamic arguments are not resolved offline |
| [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html) | Vulnerable-component taxonomy for the declared-version check | The scanner does not claim to detect native use-after-free from PHP source syntax |

Context7 resolved PHP and returned general source/API material rather than the new
advisory, so release facts were verified directly against PHP/GHSA. Later Context7
requests hit the monthly quota; original official pages remained the authority.
No third-party detector, exploit, payload or restricted rule pack was copied.

## Executable contract

`SP683` is medium/high-confidence **declared-version evidence**, always advisory.
The upstream vulnerabilities are critical; local proof is not deployment proof.
It reads exact upstream-style pins in `.php-version`, a single PHP entry in
`.tool-versions`, or a final static official PHP FPM/Apache image (including stage
aliases). Unused build stages do not become the default runtime. No process,
container, PHP binary, registry lookup or network request is needed for the rule.

Exact branch cutoffs and a deliberately bounded set of known EOL branches are
stored in `php_advisories.py`. Unknown branches, prereleases, vendor versions,
floating tags, unresolved digests, custom registries, multiple/fallback version
entries, Docker heredocs and dynamic build arguments remain **unknown**, not fixed.
CLI-only image pins are intentionally excluded from this web-runtime signature.

Composer `require.php`, `config.platform.php` and lockfile constraints describe
resolution/compatibility rather than the deployed interpreter. They do not emit
this finding. Changing INI settings does not remove a version advisory: partial
exposure reduction is not a complete patch. Vendor-fixed builds should be reviewed
against vendor evidence; a suppression requires a reason under the existing policy.

## Verification and remaining risk

Original positive/negative/adversarial cases are generated alongside the SP668 and
SP670 corrections by `scripts/build_release_012_contracts.py`. They execute through
the real walker and cover all branch boundaries, vendor strings, fixed versions,
source/doc/Composer look-alikes, inheritance, comments, continuation data, ignored
parser directives, stage overrides, CLI/JSON/SARIF parity and non-blocking gates.

No exploitation, live scanning or deployed PHP validation was performed. This
dated snapshot must be reviewed on subsequent upstream changes. The source
completeness ledger is not an attestation that deployed binaries are patched.
Release gate outcomes are recorded separately in `release-0.12.0-report.md`.
