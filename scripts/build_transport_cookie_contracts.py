"""Original transport-limit contracts. No application code or dependency is executed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/rule_cases_v2.json"
PROMOTED = ROOT / "tests/rule_cases_promoted.json"
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402


def case(source: str, **extra: object) -> dict:
    return {"path": "transport.ts", "source": source, **extra}


def records() -> list[dict]:
    tls = "import {createSecureContext as context} from 'node:tls';\ncontext({minVersion:'TLSv1'});"
    ws = "import {WebSocketServer as Server} from 'ws';\nnew Server({noServer:true,maxPayload:0});"
    rows = [
        {
            "rule_id": "SP686",
            "sources": [
                {
                    "url": "https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions",
                    "claim": "Node documents literal protocol floors/methods and conflicting options; OpenSSL security policy can still reject legacy handshakes.",
                },
                {
                    "url": "https://www.rfc-editor.org/rfc/rfc8996.html",
                    "claim": "TLS 1.0 and 1.1 are deprecated. This does not prove that a configured protocol was actually negotiated.",
                },
            ],
            "positive": [
                case(tls),
                case(tls.replace("TLSv1'", "TLSv1.1'")),
                case(
                    "const tls = require('tls');\ntls.createServer({minVersion:'TLSv1',maxVersion:'TLSv1.2'});"
                ),
                case(
                    "import https from 'node:https';\nhttps.request({hostname:'example.invalid',minVersion:'TLSv1.1'});"
                ),
                case(
                    "import * as tls from 'tls';\ntls.connect({port:443,secureProtocol:'TLSv1_1_client_method'});"
                ),
                case(tls.replace("minVersion:'TLSv1'", "minVersion:'TLSv1.2',minVersion:'TLSv1'")),
            ],
            "negative": [
                case(tls.replace("minVersion:'TLSv1'", options))
                for options in (
                    "minVersion:'TLSv1.2'",
                    "minVersion:'TLSv1.3'",
                    "",
                    "minVersion:config.minimum",
                    "minVersion:'TLSv1',maxVersion:'invalid'",
                    "minVersion:'TLSv1.1',maxVersion:'TLSv1'",
                    "minVersion:'TLSv1',maxVersion:config.maximum",
                    "secureProtocol:'TLS_method'",
                    "secureProtocol:'TLSv1_method',minVersion:'TLSv1.2'",
                    "minVersion:'TLSv1',secureProtocol:'TLSv1_2_method'",
                    "minVersion:'TLSv1',secureOptions:flags",
                    "minVersion:'TLSv1',secureContext:hardened",
                    "minVersion:'TLSv1',agent:customAgent",
                    "minVersion:'TLSv1',createConnection:connector",
                    "minVersion:'TLSv1',minVersion:'TLSv1.2'",
                    "metadata:{minVersion:'TLSv1'}",
                )
            ]
            + [
                case(tls.replace("'node:tls'", "'./tls'")),
                case(tls.replace("import {", "import type {")),
                case(tls.replace("context({", "function f(context: Factory) { context({") + "}"),
                case(tls.replace("context({", "context = hardened; context({")),
                case(tls.replace("context({", "const alias = context; alias({")),
                case("import http from 'node:http';\nhttp.createServer({minVersion:'TLSv1'});"),
                case("import tls from 'tls';\ntls.connect(port,host,{minVersion:'TLSv1'});"),
            ],
            "adversarial": [
                case(
                    tls.replace("minVersion:'TLSv1'", "minVersion:'TLSv1',...options"),
                    expected=False,
                    rationale="A spread can change the effective TLS configuration; this rule does not execute or infer its value.",
                ),
                case(
                    tls.replace("minVersion:'TLSv1'", "['minVersion']:'TLSv1'"),
                    expected=False,
                    rationale="Computed properties are outside the literal-options contract even when this isolated example looks simple.",
                ),
                case(
                    "const example = " + json.dumps(tls) + ";",
                    expected=False,
                    rationale="Source-shaped string data must not establish runtime imports or a TLS configuration.",
                ),
                case(
                    tls.replace("context({", "context(\n{\n").replace(
                        "TLSv1'", "TLSv1' /* comment */"
                    ),
                    expected=True,
                    rationale="Whitespace and an inline comment do not change the explicit imported protocol selection.",
                ),
            ],
        },
        {
            "rule_id": "SP687",
            "sources": [
                {
                    "url": "https://github.com/websockets/ws/blob/master/doc/ws.md",
                    "claim": "WebSocketServer defaults to a finite 100 MiB payload cap; zero disables it, and numeric values undergo signed-32-bit coercion.",
                },
                {
                    "url": "https://github.com/websockets/ws/blob/master/lib/receiver.js",
                    "claim": "The receiver converts maxPayload with bitwise OR zero and enforces the cap only when positive, including decompressed message size.",
                },
                {
                    "url": "https://www.rfc-editor.org/rfc/rfc6455.html#section-10.4",
                    "claim": "The WebSocket standard calls for protecting implementation resource limits and bounding frame and reassembled-message sizes; application-level consumption is not a substitute for every transport bound.",
                },
            ],
            "positive": [
                case(ws.replace("maxPayload:0", "maxPayload:" + value))
                for value in ("0", "2147483648", "4294967295", "4294967296", "9007199254740991")
            ]
            + [
                case(
                    "const {WebSocketServer: Server} = require('ws');\nnew Server({port:8080,maxPayload:0});"
                ),
                case(
                    "import WebSocket from 'ws';\nnew WebSocket.Server({noServer:true,maxPayload:0});"
                ),
                case(ws.replace("maxPayload:0", "maxPayload:4096,maxPayload:0")),
            ],
            "negative": [
                case(ws.replace("maxPayload:0", value))
                for value in (
                    "maxPayload:65536",
                    "maxPayload:104857600",
                    "maxPayload:2147483647",
                    "maxPayload:4294967297",
                    "maxPayload:9007199254740992",
                    "maxPayload:0.5",
                    "maxPayload:limits.message",
                    "maxPayload:'0'",
                    "maxPayload:-1",
                    "",
                    "maxPayload:0,maxPayload:65536",
                    "maxPayload:0,...options",
                    "metadata:{maxPayload:0}",
                )
            ]
            + [
                case(ws.replace("'ws'", "'./ws'")),
                case(ws.replace("import {", "import type {")),
                case(ws.replace("new Server", "Server")),
                case(ws.replace("new Server", "function open(Server: Factory) { new Server") + "}"),
                case(ws.replace("new Server", "const alias = Server; new alias")),
                case(
                    "import WebSocket from 'ws';\nnew WebSocket('wss://example.invalid',{maxPayload:0});"
                ),
                case(
                    "const Server = require('ws').WebSocketServer;\nnew Server({noServer:true,maxPayload:0});"
                ),
            ],
            "adversarial": [
                case(
                    "/*\n" + ws + "\n*/",
                    expected=False,
                    rationale="A full source example in a comment does not create a server or disable a message cap.",
                ),
                case(
                    ws.replace("maxPayload:0", "maxPayload:0,[setting]:65536"),
                    expected=False,
                    rationale="A computed key might override the bound; the configuration is deliberately unresolved.",
                ),
                case(
                    ws.replace("maxPayload:0", "maxPayload:" + "9" * 5000),
                    expected=False,
                    rationale="Huge numeric tokens must remain bounded and must not reach unbounded integer conversion.",
                ),
                case(
                    ws.replace("maxPayload:0", "maxPayload:\n4294967296"),
                    expected=True,
                    rationale="A plausible four-GiB setting wraps to zero; line breaks must not hide the ineffective resource bound.",
                ),
            ],
        },
    ]
    for row in rows:
        rule = find_rule(row["rule_id"])
        row.update(
            expected_severity=rule.severity,
            expected_confidence=rule.confidence,
            blocking_eligible=False,
            false_positive_analysis=RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        )
    return rows


def cookie_records() -> list[dict]:
    rows = []
    for flag, rule_id in (("HttpOnly", "SP056"), ("Secure", "SP084")):
        source = f'using Microsoft.AspNetCore.Http;\nvoid SetCookie(IResponseCookies cookies, string value) {{\n cookies.Append("session", value, new CookieOptions {{ {flag} = false }});\n}}'

        def cookie_case(text: str, **extra: object) -> dict:
            return {"path": "cookies-transport.cs", "source": text, **extra}

        rows.append(
            {
                "rule_id": rule_id,
                "positive": [
                    cookie_case(source),
                    cookie_case(
                        source.replace("IResponseCookies", "HttpResponse").replace(
                            "cookies.Append", "cookies.Cookies.Append"
                        )
                    ),
                    cookie_case(
                        source.replace("IResponseCookies", "HttpContext").replace(
                            "cookies.Append", "cookies.Response.Cookies.Append"
                        )
                    ),
                    cookie_case(
                        source.replace("using Microsoft.AspNetCore.Http;\n", "")
                        .replace(
                            "IResponseCookies", "global::Microsoft.AspNetCore.Http.IResponseCookies"
                        )
                        .replace(
                            "new CookieOptions",
                            "new global::Microsoft.AspNetCore.Http.CookieOptions",
                        )
                    ),
                ],
                "negative": [
                    cookie_case(source.replace(f"{flag} = false", replacement))
                    for replacement in (
                        f"{flag} = true",
                        "",
                        f"{flag} = deploymentFlag",
                        f"{flag} = false, {flag} = true",
                        f'{flag} = false, Extensions = {{ "Secure", "HttpOnly" }}',
                    )
                ]
                + [
                    cookie_case(source.replace('"session"', '"theme"')),
                    cookie_case(source.replace('"session"', "cookieName")),
                    cookie_case(
                        source.replace("using Microsoft.AspNetCore.Http;", "using Project.Http;")
                    ),
                    cookie_case(source.replace("IResponseCookies", "CustomCookies")),
                    cookie_case(source.replace("IResponseCookies", "global::IResponseCookies")),
                    cookie_case("class CookieOptions {}\n" + source),
                    cookie_case("using CookieOptions = Project.Options;\n" + source),
                    cookie_case(
                        source.replace(" cookies.Append", " Customize(cookies);\n cookies.Append")
                    ),
                    cookie_case(
                        source.replace(
                            " cookies.Append", " cookies = safeCookies;\n cookies.Append"
                        )
                    ),
                    cookie_case(
                        source.replace(
                            " cookies.Append", " var CookiePolicyOptions = policy;\n cookies.Append"
                        )
                    ),
                    cookie_case(source.replace("cookies.Append", "other.cookies.Append")),
                    cookie_case(
                        source.replace(
                            "IResponseCookies cookies,", "IResponseCookies unused,"
                        ).replace("cookies.Append", "cookies.Append")
                    ),
                ],
                "adversarial": [
                    cookie_case(
                        "/*\n" + source + "\n*/",
                        expected=False,
                        rationale="A commented example cannot establish a typed cookie receiver or live Append call.",
                    ),
                    cookie_case(
                        source.replace("cookies.Append", "cookies.\nAppend").replace(
                            "= false", "= /* explicit opt-out */ false"
                        ),
                        expected=True,
                        rationale="Multiline member access and comments do not remove the explicitly disabled cookie protection.",
                    ),
                    cookie_case(
                        source.replace('"session"', '"se\\u0073sion"'),
                        expected=False,
                        rationale="Escaped cookie names are unresolved rather than assumed to match the narrow literal-name set.",
                    ),
                    cookie_case(
                        source.replace(" cookies.Append", "}\nvoid Other() { cookies.Append"),
                        expected=False,
                        rationale="A typed parameter in one method must not establish the identity of a similarly named field in a different method.",
                    ),
                ],
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload["rules"] = [
        row for row in payload["rules"] if row["rule_id"] not in {"SP686", "SP687"}
    ] + records()
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    promoted = json.loads(PROMOTED.read_text(encoding="utf-8"))
    additions = {row["rule_id"]: row for row in cookie_records()}
    for row in promoted["rules"]:
        if row["rule_id"] not in additions:
            continue
        for polarity in ("positive", "negative", "adversarial"):
            row["cases"][polarity] = [
                case for case in row["cases"][polarity] if case["path"] != "cookies-transport.cs"
            ] + additions[row["rule_id"]][polarity]
        row["false_positive_analysis"] = RULE_EXPLANATIONS[row["rule_id"]]["false_positive"]
        row["cases"]["false_positive_analysis"] = row["false_positive_analysis"]
        source = {
            "url": "https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.cookieoptions?view=aspnetcore-10.0",
            "claim": "CookieOptions controls explicit HttpOnly and Secure flags; a typed Append establishes only local intent, while middleware can change the final response.",
        }
        row["sources"] = [item for item in row["sources"] if item["url"] != source["url"]] + [
            source
        ]
    promoted_text = json.dumps(promoted, ensure_ascii=False, indent=2) + "\n"
    for path, content in ((MANIFEST, rendered), (PROMOTED, promoted_text)):
        if args.check:
            if path.read_text(encoding="utf-8") != content:
                return 1
        else:
            path.write_bytes(content.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
