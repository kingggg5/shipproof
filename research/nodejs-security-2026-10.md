# Node.js security update: ShipProof impact review

Reviewed **22 October 2026**. This is read-only research, not an exploitation
test, an independent vulnerability confirmation, or a new executable rule.

Follow-up: the user subsequently authorized the Node 24.22.1 installation and
declaration advisories. See the [installation, MCP and rule verification](node-runtime-validation.md).
The observations below retain the original research context.

## Result

The latest reviewed security baseline is **22.23.4 / 24.22.1 / 26.12.1**, released
21 October. The local runtime reports **24.15.0**, below the patched 24.x baseline.
Use a maintained patched runtime; no machine-wide runtime was changed here.
The vendor does not give complete introduced-version ranges, so this observation
does not prove that every listed issue affects 24.15.0.
[Official bulletin](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
[22.23.4](https://nodejs.org/en/blog/release/v22.23.4),
[24.22.1](https://nodejs.org/en/blog/release/v24.22.1),
[26.12.1](https://nodejs.org/en/blog/release/v26.12.1).

## Vendor-reported issues

Affected lines below follow the bulletin, not inferred semver ranges.

| CVE | Bulletin severity | Lines | Area |
| --- | --- | --- | --- |
| CVE-2026-105482 | High | 22/24/26 | DNS names with embedded zero bytes |
| CVE-2026-105483 | High | 24/26 | TLS identity checks for Unicode digit addresses |
| CVE-2026-106069 | High | 22/24/26 | Ambiguous IP spellings during TLS identity checks |
| CVE-2026-111497 | High | 22/24/26 | Memory corruption in Brotli decoding; vendor reports RCE potential |
| CVE-2026-105481 | Medium | 22/24/26 | HTTP connection reuse and premature response data |
| CVE-2026-106072 | Medium* | 22/24/26 | Certificate name/address interpretation mismatch |
| CVE-2026-106074 | Medium | 22/24/26 | Randomness cache reuse in snapshots/SEA |
| CVE-2026-106070 | Low | 26 | ZIP data retained after a rejected header |
| CVE-2026-106071 | Low | 26 | Filesystem permission wildcard matching |
| CVE-2026-106073 | Low | 22/24/26 | Permission checks around synchronous canonical-path resolution |

Source: [Node.js security bulletin](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).

*The release notes group CVE-2026-106072 with a High TLS entry, unlike the
bulletin's Medium heading. Also, 26.12.1's notable changes omit 106071 while the
bulletin includes it. Retain these discrepancies; do not invent a CVSS score or
resolve the disagreement without further vendor evidence.
[24.x notes](https://nodejs.org/en/blog/release/v24.22.1),
[26.x notes](https://nodejs.org/en/blog/release/v26.12.1).

## What the ShipProof code establishes

A direct-call inventory covered the ten first-party JavaScript files in `bin/`,
`lib/`, and `scripts/run-action.mjs`:

- No direct DNS resolver, HTTP/TLS client, Brotli decoder, randomUUID/randomInt,
  startup snapshot, or SEA calls were found in that scope. The default CLI runs
  local Python checks. The optional MCP server explicitly uses stdio, not a
  network listener: [MCP implementation](../lib/mcp-server.mjs).
- There are ten `realpathSync.native` call sites, including repository confinement
  in [safe-path](../lib/safe-path.mjs), executable resolution in
  [executable](../lib/executable.mjs), and Action path validation in
  [run-action](../scripts/run-action.mjs). These warrant a patched Node runtime.
  ShipProof's containment logic also compares resolved paths against the approved
  root; it does not enable or depend on Node's Permission Model as its sandbox.
- No Permission Model flags were found in those entry points or workflows. The
  advisory's title alone does not establish a bypass of ShipProof's separate
  confinement checks. This is a limited reachability assessment, not proof of
  non-exploitability. Node internals, optional SDK internals, external analyzers,
  other host applications, and deployment-specific flags remain outside it.
  Node also documents that its Permission Model is not a sandbox for malicious
  code: [permission constraints](https://nodejs.org/api/permissions.html#permission-model).

## Recommended follow-up, not silently implemented

1. Upgrade operator/deployment runtimes within their maintained release line and
   rerun CLI, packed-consumer, MCP peer, and path-confinement tests. An npm lockfile
   update does not patch the Node executable.
2. Record resolved patch versions in CI evidence. Current setup steps specify
   majors 20/22/24 without an explicit `check-latest` setting; that alone is not
   evidence of which patch ran. Keep compatibility testing separate from the
   runtime used to publish or execute production gates.
3. Plan to retire Node 20 as a deployment recommendation: its official EOL was
   **30 April 2026**. Changing supported engines/compatibility CI is a separate
   reviewed compatibility decision, not part of this research.
   [Official release schedule](https://github.com/nodejs/Release/blob/main/schedule.json).
4. If promoting a new scanner advisory, inspect exact runtime declarations and
   supported branch fixes. Do not label every `fetch`, TLS, or Brotli call as a
   vulnerability. Require version-specific positive/negative/adversarial tests,
   deployment/backport uncertainty, dated sources, and advisory-only evidence
   until independently reviewed. No such rule was added in this change.
