"""Original TS/.NET/Dart contracts and reviewed counterpart scenarios."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402


def case(path: str, source: str, **extra: object) -> dict:
    return {"path": path, "source": source, **extra}


def records() -> list[dict]:
    images = "dangerouslyAllowSVG:true,contentDispositionType:'inline',contentSecurityPolicy:''"
    svg = "export default {images:{" + images + "}};"
    kestrel = "using Microsoft.AspNetCore.Server.Kestrel.Core;\nvoid Configure(KestrelServerOptions options) {\n options.Limits.MaxRequestBodySize = null;\n}"
    dart = "import 'package:http/http.dart' as http;\nFuture<void> send(String bearer) async {\n await http.get(Uri.parse('http://service.example.org/items'), headers: {'Authorization': bearer});\n}"
    hook = "import {useState} from 'react';\nexport default function Page() { const [score] = useState(1); return <span>{score}</span>; }"
    rows = [
        {
            "rule_id": "SP688",
            "sources": [
                {
                    "url": "https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowsvg",
                    "claim": "Next recommends a restrictive image CSP and attachment disposition when serving SVG; enabling SVG alone does not establish missing protections.",
                },
                {
                    "url": "https://github.com/vercel/next.js/blob/canary/packages/next/src/server/image-optimizer.ts",
                    "claim": "The image response uses the configured CSP and disposition values. Empty CSP is not evidence of a restrictive policy; deployment may still add controls.",
                },
            ],
            "positive": [
                case("next.config.ts", svg),
                case("next.config.js", svg.replace("export default", "module.exports =")),
                case(
                    "next.config.mjs",
                    "const config = {images:{" + images + "}}; export default config;",
                ),
                case(
                    "next.config.ts",
                    svg.replace(
                        "contentSecurityPolicy:''",
                        "contentSecurityPolicy:'script-src none',contentSecurityPolicy:''",
                    ),
                ),
            ],
            "negative": [
                case("next.config.ts", svg.replace(images, item))
                for item in (
                    "dangerouslyAllowSVG:true",
                    images.replace("true", "false"),
                    images.replace("'inline'", "'attachment'"),
                    images.replace(
                        "contentSecurityPolicy:''",
                        "contentSecurityPolicy:\"script-src 'none'; sandbox;\"",
                    ),
                    images.replace(",contentSecurityPolicy:''", ""),
                    images.replace("contentSecurityPolicy:''", "contentSecurityPolicy:policy"),
                    images + ",unoptimized:true",
                    images + ",loader:'custom'",
                    images + ",loaderFile:'./image-loader.ts'",
                    images + ",contentDispositionType:'attachment'",
                    images + ",...hardened",
                )
            ]
            + [
                case("settings.ts", svg),
                case("next.config.ts", svg.replace("{images", "{output:'export',images")),
                case(
                    "next.config.ts", "const unused = {images:{" + images + "}}; export default {};"
                ),
                case("next.config.cts", svg),
            ],
            "adversarial": [
                case(
                    "next.config.ts",
                    "/* " + svg + " */",
                    expected=False,
                    rationale="Export-shaped comment text cannot configure the optimizer or clear its response policy.",
                ),
                case(
                    "next.config.ts",
                    svg.replace("contentSecurityPolicy:''", "['contentSecurityPolicy']:''"),
                    expected=False,
                    rationale="Computed property identity stays unresolved rather than overriding known protective options.",
                ),
                case(
                    "next.config.ts",
                    svg.replace(",", ",\n"),
                    expected=True,
                    rationale="Multiline literal configuration preserves all three explicitly unsafe header choices.",
                ),
            ],
        },
        {
            "rule_id": "SP689",
            "sources": [
                {
                    "url": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.server.kestrel.core.kestrelserverlimits.maxrequestbodysize?view=aspnetcore-10.0",
                    "claim": "Kestrel's nullable body-size property disables this limit when null; a finite default and independent per-request or proxy limits must be distinguished.",
                },
                {
                    "url": "https://cwe.mitre.org/data/definitions/400.html",
                    "claim": "Resource-consumption limits are a CWE-400 control, but an absent local cap alone does not prove endpoint reachability or exploitable exhaustion.",
                },
            ],
            "positive": [
                case("Server.cs", kestrel),
                case(
                    "Server.cs",
                    kestrel.replace(
                        "void Configure(KestrelServerOptions options)",
                        "var configure = (KestrelServerOptions options) =>",
                    )
                    + ";",
                ),
                case(
                    "Server.cs",
                    kestrel.replace(
                        "using Microsoft.AspNetCore.Server.Kestrel.Core;\n", ""
                    ).replace(
                        "KestrelServerOptions options",
                        "global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions options",
                    ),
                ),
                case(
                    "Server.cs",
                    kestrel.replace(
                        "options.Limits.MaxRequestBodySize = null;",
                        "options.Limits.MaxRequestBodySize = 4096; options.Limits.MaxRequestBodySize = null;",
                    ),
                ),
            ],
            "negative": [
                case(
                    "Server.cs", kestrel.replace("options.Limits.MaxRequestBodySize = null;", item)
                )
                for item in (
                    "options.Limits.MaxRequestBodySize = 4096;",
                    "",
                    "options.Limits.MaxRequestBodySize = configuredLimit;",
                    "options.Limits.MaxRequestBodySize = null; options.Limits.MaxRequestBodySize = 4096;",
                    "if (development) options.Limits.MaxRequestBodySize = null;",
                    "Customize(options); options.Limits.MaxRequestBodySize = null;",
                    "options.Limits.MaxRequestBodySize = null; Register(options);",
                )
            ]
            + [
                case(
                    "Server.cs",
                    kestrel.replace(
                        "using Microsoft.AspNetCore.Server.Kestrel.Core;", "using Project.Server;"
                    ),
                ),
                case("Server.cs", "class KestrelServerOptions {}\n" + kestrel),
                case("Server.cs", "using KestrelServerOptions = Project.Options;\n" + kestrel),
                case(
                    "Server.cs", kestrel.replace("KestrelServerOptions options", "dynamic options")
                ),
            ],
            "adversarial": [
                case(
                    "Server.cs",
                    "/*\n" + kestrel + "*/",
                    expected=False,
                    rationale="A comment cannot bind server options or disable a request-processing resource limit.",
                ),
                case(
                    "Server.cs",
                    kestrel.replace("= null", "= /* deliberately unbounded */ null"),
                    expected=True,
                    rationale="A comment inside the actual null assignment must not hide the explicit local limit opt-out.",
                ),
                case(
                    "Server.cs",
                    kestrel.replace(" options.Limits", "}\nvoid Other() { options.Limits"),
                    expected=False,
                    rationale="An options parameter from another method does not establish the type of a similarly named field.",
                ),
            ],
        },
        {
            "rule_id": "SP170",
            "sources": [
                {
                    "url": "https://pub.dev/documentation/http/latest/http/get.html",
                    "claim": "The package:http convenience API accepts a URI and header map; no TLS is inferred from a plain HTTP URI.",
                },
                {
                    "url": "https://www.rfc-editor.org/rfc/rfc6750.html#section-5.3",
                    "claim": "Bearer credentials require transport protection. A header declaration supports a local concern, not proof of the value or the deployed transport.",
                },
            ],
            "positive": [
                case("client.dart", dart),
                case("client.dart", dart.replace("http.get", "http.post")),
                case("client.dart", dart.replace("http://", "HTTP://")),
                case(
                    "client.dart",
                    dart.replace(" as http", " as remote").replace("http.get", "remote.put"),
                ),
                case(
                    "client.dart",
                    dart.replace("'Authorization': bearer", "'authorization': 'Bearer $bearer'"),
                ),
                case("client.dart", dart.replace("Uri.parse('", "Uri.parse(r'")),
            ],
            "negative": [
                case("client.dart", dart.replace("http://service.example.org", url))
                for url in (
                    "https://service.example.org",
                    "http://localhost",
                    "http://127.0.0.1",
                    "http://[::1]",
                    "http://10.0.0.1",
                    "http://node.local",
                    "http://internal",
                    "http://$host",
                    "http://service.example.org:99999",
                )
            ]
            + [
                case(
                    "client.dart",
                    dart.replace("'Authorization': bearer", "'Accept': 'application/json'"),
                ),
                case("client.dart", dart.replace("'Authorization': bearer", "'Authorization': ''")),
                case(
                    "client.dart",
                    dart.replace(
                        "'Authorization': bearer", "'Authorization': bearer, 'authorization': ''"
                    ),
                ),
                case(
                    "client.dart",
                    dart.replace("headers: {'Authorization': bearer}", "headers: reviewedHeaders"),
                ),
                case("client.dart", dart.replace("'package:http/http.dart'", "'local_http.dart'")),
                case("client.dart", dart.replace("String bearer", "String bearer, dynamic http")),
                case("client.dart", "class Uri {}\n" + dart),
                case("client.dart", "void runWithClient() {}\n" + dart),
                case("client.dart", "const documentation = 'http://api.example.org/help';"),
                case(
                    "client.dart",
                    dart.replace(
                        "http.get(Uri.parse('http://service.example.org/items')", "http.get(target"
                    ),
                ),
            ],
            "adversarial": [
                case(
                    "client.dart",
                    "/* outer /* inner */\n" + dart + "*/",
                    expected=False,
                    rationale="Dart block comments nest, so a source-like request after an inner closing marker is still comment data.",
                ),
                case(
                    "client.dart",
                    'final documentation = r"""' + dart + '""";',
                    expected=False,
                    rationale="A multiline raw string is a single data literal; its embedded imports and calls are not executed.",
                ),
                case(
                    "client.dart",
                    dart.replace("http.get(", "http.\nget(\n"),
                    expected=True,
                    rationale="Whitespace must not remove the direct binding between package:http, the URI and its Authorization header.",
                ),
                case(
                    "client.dart",
                    dart.replace(
                        "{'Authorization': bearer}", "{'Authorization': bearer, ...safeHeaders}"
                    ),
                    expected=False,
                    rationale="A spread may replace the header, so this bounded rule cannot establish the effective authentication map.",
                ),
            ],
        },
        {
            "rule_id": "SP596",
            "blocking_eligible": True,
            "sources": [
                {
                    "url": "https://nextjs.org/docs/app/api-reference/directives/use-client",
                    "claim": "Next requires a client entry boundary, not a directive in every transitive client component.",
                },
                {
                    "url": "https://react.dev/reference/rsc/use-client",
                    "claim": "The directive belongs to React Server Components and follows the module import graph; ordinary client-rendered React does not need it.",
                },
            ],
            "positive": [
                case("app/page.tsx", hook),
                case("src/app/settings/layout.tsx", hook),
                case(
                    "app/page.tsx",
                    hook.replace("{useState}", "{useState as state}").replace(
                        "= useState(", "= state("
                    ),
                ),
            ],
            "negative": [
                case("app/page.tsx", "'use client';\n" + hook),
                case("app/components/Counter.tsx", hook),
                case("src/widgets/Page.tsx", hook),
                case("app/page.tsx", hook, frameworks=["react"]),
                case("app/page.tsx", hook, frameworks=None),
                case("app/page.tsx", hook.replace("'react'", "'./state'")),
                case("app/page.tsx", hook.replace("{useState}", "{type useState}")),
                case(
                    "app/page.tsx",
                    hook.replace("function Page()", "function Page(useState: Factory)"),
                ),
            ],
            "adversarial": [
                case(
                    "app/page.tsx",
                    "/* 'use client' is discussed here */\n" + hook,
                    expected=True,
                    rationale="A comment mentioning a directive is not a module boundary and must not hide a genuine server-entry hook call.",
                ),
                case(
                    "app/page.tsx",
                    "/*\n" + hook + "*/",
                    expected=False,
                    rationale="An import and hook-shaped example inside a comment do not establish executable React usage.",
                ),
                case(
                    "app/page.tsx",
                    "const example = " + json.dumps(hook) + ";",
                    expected=False,
                    rationale="Source-shaped quoted text is documentation data, not an exported Next entry component or imported React hook.",
                ),
            ],
        },
    ]
    for flag, rule_id, value in (
        ("HttpOnly", "SP056", "false"),
        ("SecurePolicy", "SP084", "CookieSecurePolicy.None"),
    ):
        cookie = f"using Microsoft.AspNetCore.Authentication.Cookies;\nusing Microsoft.AspNetCore.Http;\nvoid Configure(CookieAuthenticationOptions options) {{ options.Cookie.{flag} = {value}; }}"
        safe = "true" if flag == "HttpOnly" else "CookieSecurePolicy.Always"
        rows.append(
            {
                "rule_id": rule_id,
                "sources": [
                    {
                        "url": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.cookieauthenticationoptions.cookie?view=aspnetcore-10.0",
                        "claim": "Authentication cookies expose an actual CookieBuilder policy; defaults differ from explicit insecure overrides.",
                    },
                    {
                        "url": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookiesecurepolicy?view=aspnetcore-10.0",
                        "claim": "None, not Never, disables Secure. SameAsRequest and Always are distinct policies and must not be conflated.",
                    },
                ],
                "positive": [
                    case("Auth.cs", cookie),
                    case(
                        "Auth.cs",
                        cookie.replace(
                            "void Configure(CookieAuthenticationOptions options)",
                            "var configure = (CookieAuthenticationOptions options) =>",
                        )
                        + ";",
                    ),
                    case(
                        "Auth.cs",
                        cookie.replace(
                            "CookieAuthenticationOptions options",
                            "global::Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions options",
                        ),
                    ),
                ],
                "negative": [
                    case("Auth.cs", cookie.replace(value + ";", replacement + ";"))
                    for replacement in (
                        safe,
                        "reviewedPolicy",
                        "CookieSecurePolicy.SameAsRequest",
                        "CookieSecurePolicy.Never",
                    )
                ]
                + [
                    case(
                        "Auth.cs",
                        cookie.replace(
                            "using Microsoft.AspNetCore.Authentication.Cookies;",
                            "using Project.Authentication;",
                        ),
                    ),
                    case(
                        "Auth.cs",
                        cookie.replace(
                            "CookieAuthenticationOptions options", "CustomOptions options"
                        ),
                    ),
                    case(
                        "Auth.cs",
                        cookie.replace("options.Cookie.", "if (localDevelopment) options.Cookie."),
                    ),
                    case(
                        "Auth.cs",
                        cookie.replace(value + ";", value + f"; options.Cookie.{flag} = {safe};"),
                    ),
                ],
                "adversarial": [
                    case(
                        "Auth.cs",
                        "using CookieAuthenticationOptions = Project.Options;\n" + cookie,
                        expected=False,
                        rationale="A custom type alias cannot establish ASP.NET's authentication-cookie policy semantics.",
                    ),
                    case(
                        "Auth.cs",
                        cookie.replace("= " + value, "= /* explicit override */ " + value),
                        expected=True,
                        rationale="An inline comment inside the actual configuration assignment does not change its unsafe literal value.",
                    ),
                ],
            }
        )
    for row in rows:
        rule = find_rule(row["rule_id"])
        row.update(
            expected_severity=rule.severity,
            expected_confidence=rule.confidence,
            false_positive_analysis=RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        )
        row.setdefault("blocking_eligible", False)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    manifest = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["rules"] = [
        row for row in payload["rules"] if row["rule_id"] not in {"SP688", "SP689"}
    ] + [row for row in authored if row["rule_id"] in {"SP688", "SP689"}]
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for path, data in (
        (manifest, payload),
        (ROOT / "tests/field_cohort_cases.json", {"schema_version": 1, "rules": authored}),
    ):
        rendered = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            if path.read_text(encoding="utf-8") != rendered:
                return 1
        else:
            path.write_bytes(rendered.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
