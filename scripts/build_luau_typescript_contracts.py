"""Authored remote-boundary and TypeScript API contracts; not runtime data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {"SP690", "SP691", "SP692"}


def case(path: str, source: str, **extra: object) -> dict:
    return {"path": path, "source": source, **extra}


def remote(sink: str, *, invoke: bool = False, typed: bool = False) -> str:
    kind = "RemoteFunction" if invoke else "RemoteEvent"
    params = "player: Player, data: any" if typed else "player, data"
    callback = "OnServerInvoke = function" if invoke else "OnServerEvent:Connect(function"
    ending = "end" if invoke else "end)"
    return f'local remote = Instance.new("{kind}")\nremote.{callback}({params})\n{sink}\n{ending}\n'


def records() -> list[dict]:
    rows = []
    for rule_id, sink, cwe in (
        ("SP690", "require(data)", "829"),
        ("SP691", "data:Destroy()", "862"),
    ):
        direct = remote(sink)
        safe_sink = (
            "require(script.ServerActions)" if rule_id == "SP690" else "player.Character:Destroy()"
        )
        positives = [
            direct,
            "local function register()\n" + direct + "end\n",
            remote(sink, typed=True),
            remote("return " + sink, invoke=True, typed=True),
            direct.replace("remote", "adminRemote").replace(
                "\n" + sink, "\n-- inspect boundary\n" + sink + ";"
            ),
            direct.replace("local remote =", "local remote: RemoteEvent =").replace(
                "remote.OnServer",
                'remote.Name = "Actions"\nremote.Parent = game.ReplicatedStorage\nremote.OnServer',
            ),
        ]
        negatives = [
            remote("return " + sink, invoke=True).rstrip() + " and safeHandler\n",
            direct.replace('Instance.new("RemoteEvent")', 'Instance.new("RemoteEvent") == other'),
            direct.partition("\n")[2] + direct.partition("\n")[0] + "\n",
            direct.replace("\nremote.", "\nend\nremote.").replace(
                "local remote", "function factory()\nlocal remote"
            ),
            remote(safe_sink),
            remote("if not allowed(player, data) then return end\n" + sink),
            remote("data = serverOwnedValue\n" + sink),
            direct.replace('Instance.new("RemoteEvent")', "customRemote"),
            direct.replace('Instance.new("RemoteEvent")', 'Instance.new("BindableEvent")'),
            direct.replace("OnServerEvent", "OnClientEvent"),
            direct.replace(sink, sink.replace("data", "player")),
            direct.replace("player, data", "player, data, extra"),
            direct.replace("player, data", "player: Player, data: {id: number}"),
            "local alias = remote\n" + direct,
            direct.replace("remote.OnServer", "remote = customRemote\nremote.OnServer"),
            direct.replace("remote.OnServer", "container.remote.OnServer"),
            direct.replace('Instance.new("RemoteEvent")', 'Instance.new("RemoteEvent").Custom'),
            remote("return " + sink, invoke=True).replace("OnServerInvoke", "OnClientInvoke"),
            direct + "remote.OnServerEvent:Connect(function(player, data) print(data) end)\n",
        ]
        adversarial = [
            (
                "local sample = `outer {`inner " + direct + "`} tail`\n",
                "Nested interpolated strings must remain opaque; callback-shaped text inside them is not a callback registration.",
            ),
            ("--[=[\n" + direct + "]=]\n", "A long comment cannot register a remote callback."),
            (
                "local sample = [==[\n" + direct + "]==]\n",
                "A long literal is data, not executable callback code.",
            ),
            (
                "local Instance = factories\n" + direct,
                "A local Instance factory cannot establish Roblox engine identity.",
            ),
            (
                direct.replace("player, data", "player, player"),
                "Duplicate parameter names invalidate client provenance.",
            ),
            (
                "setfenv(1, customEnvironment)\n" + direct,
                "A modified global environment leaves builtin identity unresolved.",
            ),
        ]
        if rule_id == "SP690":
            adversarial.extend(
                [
                    (
                        "local unused, require = nil, customLoader\n" + direct,
                        "A multi-local declaration shadows the native module loader.",
                    ),
                    (
                        "for require in loaders do\n" + direct + "end",
                        "A loop binding is not the Roblox builtin require.",
                    ),
                ]
            )
        rows.append(
            {
                "rule_id": rule_id,
                "sources": [
                    {
                        "url": "https://create.roblox.com/docs/scripting/security/client-server-boundary",
                        "claim": "Roblox warns against client-selected module execution and arbitrary instance deletion through remotes; server validation is required.",
                    },
                    {
                        "url": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                        "claim": "Maps the local trust/authorization boundary, not demonstrated runtime exploitability.",
                    },
                ],
                "positive": [case("Server.server.luau", source) for source in positives],
                "negative": [case("Server.server.luau", source) for source in negatives],
                "adversarial": [
                    case("Server.server.luau", source, expected=False, rationale=why)
                    for source, why in adversarial
                ],
            }
        )

    sign = "import {sign} from 'jsonwebtoken';\nsign(payload, key, {algorithm:'RS256',allowInsecureKeySizes:true});\n"
    rows.append(
        {
            "rule_id": "SP692",
            "sources": [
                {
                    "url": "https://github.com/auth0/node-jsonwebtoken",
                    "claim": "RSA signing normally requires 2048-bit modulus; allowInsecureKeySizes explicitly disables the size safeguard.",
                },
                {
                    "url": "https://cwe.mitre.org/data/definitions/326.html",
                    "claim": "Inadequate key strength can weaken cryptographic protection; this signature proves an opt-out, not the actual key size.",
                },
            ],
            "positive": [
                case("sign.ts", source)
                for source in (
                    sign,
                    sign.replace("{sign}", "{sign as issue}")
                    .replace("\nsign(", "\nissue(")
                    .replace("RS256", "PS256"),
                    sign.replace(
                        "import {sign} from 'jsonwebtoken'",
                        "const {sign} = require('jsonwebtoken')",
                    ),
                    sign.replace("{algorithm", "{\nalgorithm").replace("true}", "true}, callback"),
                )
            ],
            "negative": [
                case("sign.ts", source)
                for source in (
                    sign.replace("true", "false"),
                    sign.replace(",allowInsecureKeySizes:true", ""),
                    sign.replace("RS256", "HS256"),
                    sign.replace("RS256", "ES256"),
                    sign.replace("algorithm:'RS256',", ""),
                    sign.replace("true}", "true,allowInsecureKeySizes:false}"),
                    sign.replace("true}", "true,...hardened}"),
                    sign.replace("true}", "true,header:{alg:'HS256'}}"),
                    sign.replace("true}", "true,header:customHeader}"),
                    sign.replace("'jsonwebtoken'", "'./jwt-policy'"),
                    sign.replace("import {sign}", "import type {sign}"),
                    sign.replace("\nsign(", "\nsign = issueSafely;\nsign("),
                )
            ],
            "adversarial": [
                case(
                    "sign.ts",
                    "/* " + sign + " */",
                    expected=False,
                    rationale="Commented examples cannot invoke signing.",
                ),
                case(
                    "sign.ts",
                    sign.replace("\nsign(", "\nfunction issue(sign: Signer) { return sign(") + "}",
                    expected=False,
                    rationale="A parameter shadows the imported function.",
                ),
                case(
                    "sign.ts",
                    sign.replace("allowInsecureKeySizes:", "['allowInsecureKeySizes']:"),
                    expected=False,
                    rationale="Computed option keys stay unresolved rather than being treated as a proven signing configuration.",
                ),
                case(
                    "sign.ts",
                    sign.replace("'RS256'", "'PS512'").replace(
                        "true}", "false,allowInsecureKeySizes:true}"
                    ),
                    expected=True,
                    rationale="The final literal setting wins for a supported RSA/PSS signing algorithm.",
                ),
            ],
        }
    )

    evaluate = remote("loadstring(data)()", typed=True)
    rows.append(
        {
            "rule_id": "SP672",
            "positive": [
                case("eval.luau", source)
                for source in (
                    evaluate,
                    remote("return loadstring(data)()", invoke=True, typed=True),
                    remote("loadstring(data)();", invoke=True).replace(
                        "function(player, data)", "function(player, data): any"
                    ),
                )
            ],
            "negative": [
                case("eval.luau", source)
                for source in (
                    remote("loadstring(data)", typed=True),
                    remote(
                        "if not allowed(player) then return end\nloadstring(data)()", invoke=True
                    ),
                    evaluate.replace("data: any", "data: (string | number)"),
                    evaluate.replace("loadstring(data)()", "loadstring('return 1')()"),
                    evaluate.replace("OnServerEvent", "OnClientEvent"),
                )
            ],
            "adversarial": [
                case(
                    "eval.luau",
                    "local x, loadstring = nil, localCompiler\n" + evaluate,
                    expected=False,
                    rationale="Multiple local declarations can shadow the compiler.",
                ),
                case(
                    "eval.luau",
                    "for loadstring in compilers do\n" + evaluate + "end",
                    expected=False,
                    rationale="The loop parameter is not the global evaluator.",
                ),
            ],
        }
    )
    invalid_key = sign.replace("allowInsecureKeySizes", "allowInvalidAsymmetricKeyTypes")
    rows.append(
        {
            "rule_id": "SP676",
            "positive": [
                case("issue.ts", source)
                for source in (
                    invalid_key,
                    invalid_key.replace("RS256", "ES256"),
                    invalid_key.replace("true}", "true}, callback"),
                )
            ],
            "negative": [
                case("issue.ts", source)
                for source in (
                    invalid_key.replace("true", "false"),
                    invalid_key.replace("RS256", "HS256"),
                    invalid_key.replace("algorithm:'RS256',", ""),
                    invalid_key.replace("true}", "true,header:{alg:'HS256'}}"),
                    invalid_key.replace("true}", "true,...strictOptions}"),
                )
            ],
            "adversarial": [
                case(
                    "issue.ts",
                    "// " + invalid_key.replace("\n", " "),
                    expected=False,
                    rationale="Comment text must not become a signing call.",
                ),
                case(
                    "issue.ts",
                    invalid_key.replace("'jsonwebtoken'", "'./local-jwt'"),
                    expected=False,
                    rationale="A custom module does not establish jsonwebtoken option semantics.",
                ),
            ],
        }
    )
    http = "import {createServer} from 'node:http';\ncreateServer({httpValidation:'insecure'}, handler);\n"
    rows.append(
        {
            "rule_id": "SP679",
            "positive": [
                case("server.ts", source)
                for source in (
                    http,
                    http.replace("node:http", "node:https"),
                    http.replace("createServer", "request").replace(
                        "({", "('https://api.example.org',{"
                    ),
                )
            ],
            "negative": [
                case("server.ts", source)
                for source in (
                    http.replace("insecure", "strict"),
                    http.replace("insecure", "relaxed"),
                    http.replace("httpValidation:'insecure'", ""),
                    http.replace("httpValidation:'insecure'", "httpValidation:mode"),
                    http.replace("'insecure'}", "'insecure',insecureHTTPParser:true}"),
                    http.replace("'insecure'}", "'insecure',httpValidation:'strict'}"),
                    http.replace("'insecure'}", "'insecure',...strictOptions}"),
                    http.replace("node:http", "./http"),
                )
            ],
            "adversarial": [
                case(
                    "server.ts",
                    "/* " + http + " */",
                    expected=False,
                    rationale="An HTTP option in a comment does not configure a server.",
                ),
                case(
                    "server.ts",
                    http.replace(
                        "\ncreateServer(",
                        "\nfunction build(createServer: Factory) { return createServer(",
                    )
                    + "}",
                    expected=False,
                    rationale="A local factory parameter shadows the imported HTTP constructor.",
                ),
            ],
        }
    )
    for row in rows:
        rule = find_rule(row["rule_id"])
        row.update(
            expected_severity=rule.severity,
            expected_confidence=rule.confidence,
            blocking_eligible=False,
            false_positive_analysis=RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    manifest = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in NEW_IDS] + [
        row for row in authored if row["rule_id"] in NEW_IDS
    ]
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for path, data in (
        (manifest, payload),
        (ROOT / "tests/luau_typescript_cases.json", {"schema_version": 1, "rules": authored}),
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
