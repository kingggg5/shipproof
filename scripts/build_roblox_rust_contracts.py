"""Generate the authored Roblox/Rust cohort's v2 cases; never runs in scans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "rule_cases_v2.json"


def case(path: str, source: str, **extra: object) -> dict:
    return {"path": path, "source": source, **extra}


def records() -> list[dict]:
    remote = 'local http = game:GetService("HttpService")\n'
    execute = 'loadstring(http:GetAsync("https://modules.invalid/script"))()\n'
    event = "remote.OnServerEvent:Connect(function(player, code)\nloadstring(code)()\nend)\n"
    zero = "fn main() { let _value = unsafe { std::mem::zeroed::<&u32>() }; }\n"
    fixtures = [
        {
            "rule_id": "SP671",
            "expected_severity": "medium",
            "expected_confidence": "medium",
            "blocking_eligible": False,
            "sources": [
                {
                    "url": "https://create.roblox.com/docs/reference/engine/globals/LuaGlobals#loadstring",
                    "claim": "Roblox loadstring compiles source; immediately invoking the returned function executes it, subject to server loadstring permissions.",
                },
                {
                    "url": "https://cwe.mitre.org/data/definitions/494.html",
                    "claim": "CWE-494 describes executing downloaded code without establishing the integrity of the received executable content.",
                },
            ],
            "false_positive_analysis": "Requires a single direct local game:GetService HttpService binding, exactly one use, and loadstring(GetAsync(single argument)) followed by an empty invocation. Trusted remote loaders can be intentional, so the rule stays advisory. JSON data, compilation without execution, aliases, multiple uses, local loadstring bindings, strings and comments are excluded. HTTP/loadstring platform permissions and reachability remain unknown.",
            "positive": [
                case("Server.server.luau", remote + execute),
                case(
                    "Loader.lua",
                    remote.replace("http", "transport") + execute.replace("http:", "transport:"),
                ),
                case("Bootstrap.luau", remote + "loadstring(\n http:GetAsync(endpoint)\n)()\n"),
            ],
            "negative": [
                case(
                    "Data.luau",
                    remote + "local data = http:JSONDecode(http:GetAsync(endpoint))\nprint(data)\n",
                ),
                case(
                    "Compile.luau",
                    remote + "local compiled = loadstring(http:GetAsync(endpoint))\n",
                ),
                case("Constant.luau", "local fn = loadstring('return 1')\nprint(fn())\n"),
                case("Example.lua", "--[=[\n" + remote + execute + "]=]\nreturn {}\n"),
                case(
                    "Example.luau",
                    "local example = [=[\n" + remote + execute + "]=]\nreturn example\n",
                ),
                case("Foreign.txt", remote + execute),
                case(
                    "ComputedService.luau", remote.replace('"HttpService"', "serviceName") + execute
                ),
            ],
            "adversarial": [
                case(
                    "Shadow.lua",
                    "local loadstring = function(code) return function() end end\n"
                    + remote
                    + execute,
                    expected=False,
                    rationale="A local loadstring function is a different binding from the Roblox builtin; its spelling must not establish remote execution.",
                ),
                case(
                    "String.luau",
                    remote + "local example = 'loadstring(http:GetAsync(endpoint))()'\n",
                    expected=False,
                    rationale="Executable-looking content inside a quoted literal is data and must not turn an example into a code-execution finding.",
                ),
                case(
                    "ShadowParam.luau",
                    remote + "function run(loadstring)\n" + execute + "end\n",
                    expected=False,
                    rationale="A function parameter shadows the builtin loadstring. The bounded detector conservatively declines the ambiguous binding.",
                ),
                case(
                    "MethodShadow.luau",
                    remote + "function Loader:run(loadstring)\n" + execute + "end\n",
                    expected=False,
                    rationale="A method parameter shadows the global evaluator just as a standalone function parameter does; method syntax must not bypass binding checks.",
                ),
            ],
        },
        {
            "rule_id": "SP672",
            "expected_severity": "medium",
            "expected_confidence": "medium",
            "blocking_eligible": False,
            "sources": [
                {
                    "url": "https://create.roblox.com/docs/scripting/security/client-server-boundary",
                    "claim": "RemoteEvent handlers must validate client-supplied data; the first callback parameter identifies the player and later parameters come from the client.",
                },
                {
                    "url": "https://cwe.mitre.org/data/definitions/94.html",
                    "claim": "CWE-94 covers treating externally supplied data as executable source and crossing an application's code-execution boundary.",
                },
            ],
            "false_positive_analysis": "Only an OnServerEvent Connect callback with two untyped parameters and an entire body of loadstring(secondParameter)() is recognized. The source is a client data argument, not the implicit Player. Guarded or complex handlers, fixed commands, aliases, comments, long strings, field methods and shadowed builtins stay silent. The local signature cannot prove Roblox deployment or LoadStringEnabled, and is advisory.",
            "positive": [
                case("Remote.server.luau", event),
                case(
                    "Admin.lua", event.replace("remote", "adminRemote").replace("code", "payload")
                ),
                case(
                    "Events.luau", event.replace("\nloadstring", "\n-- incoming source\nloadstring")
                ),
            ],
            "negative": [
                case(
                    "Actions.luau",
                    "remote.OnServerEvent:Connect(function(player, action)\nhandlers[action](player)\nend)\n",
                ),
                case(
                    "Guard.luau",
                    "remote.OnServerEvent:Connect(function(player, code)\nif not allowed(player) then return end\nloadstring(code)()\nend)\n",
                ),
                case(
                    "Player.luau",
                    "remote.OnServerEvent:Connect(function(player, code)\nloadstring(player)()\nend)\n",
                ),
                case(
                    "Constant.luau",
                    "remote.OnServerEvent:Connect(function(player, code)\nloadstring('return 1')()\nend)\n",
                ),
                case("Note.lua", "--[==[\n" + event + "]==]\nreturn {}\n"),
                case("Foreign.rs", event),
            ],
            "adversarial": [
                case(
                    "Typed.luau",
                    event.replace("player, code", "player: Player, code: string"),
                    expected=False,
                    rationale="Typed parameters require additional Luau syntax handling. They are a documented unsupported shape rather than inferred data-flow evidence.",
                ),
                case(
                    "Reassigned.lua",
                    event.replace("\nloadstring", "\ncode = 'return 1'\nloadstring"),
                    expected=False,
                    rationale="A safe overwrite before the sink invalidates direct client provenance; a later matching spelling must not bypass assignment analysis.",
                ),
                case(
                    "Quoted.lua",
                    "local example = [=[\n" + event + "]=]\n",
                    expected=False,
                    rationale="Long-bracket literals can contain callback-shaped text. The lexer must exclude the entire literal before matching server handlers.",
                ),
            ],
        },
        {
            "rule_id": "SP673",
            "expected_severity": "medium",
            "expected_confidence": "high",
            "blocking_eligible": False,
            "sources": [
                {
                    "url": "https://doc.rust-lang.org/std/mem/fn.zeroed.html",
                    "claim": "The Rust standard library documents that all-zero reference values are invalid and that constructing them with mem::zeroed causes undefined behavior.",
                },
                {
                    "url": "https://cwe.mitre.org/data/definitions/665.html",
                    "claim": "CWE-665 classifies improper initialization; this rule narrows that class to explicitly zero-initialized Rust references.",
                },
            ],
            "false_positive_analysis": "Requires a fully qualified std/core mem::zeroed turbofish whose type begins with a reference, followed by a direct empty call. Raw pointers, integers, Option references, MaybeUninit storage, shadowed modules, documentation strings and nested block comments are excluded. Aliases, inferred types and complex nested generic types remain unsupported. This is local invalid-state evidence, not an exploitability claim.",
            "positive": [
                case("main.rs", zero),
                case("lib.rs", zero.replace("std::", "core::").replace("&u32", "&mut i64")),
                case(
                    "ffi.rs",
                    "unsafe fn init<'a>() { let value = std::mem::zeroed::<&'a str>(); }\n",
                ),
            ],
            "negative": [
                case("ptr.rs", zero.replace("&u32", "*const u32")),
                case("int.rs", zero.replace("&u32", "u32")),
                case("option.rs", zero.replace("&u32", "Option<&u32>")),
                case("storage.rs", "let storage = std::mem::MaybeUninit::<&u32>::zeroed();\n"),
                case("borrow.rs", "fn main() { let value = 7; let reference: &i32 = &value; }\n"),
                case("example.rs", 'let example = r###"std::mem::zeroed::<&u32>()"###;\n'),
            ],
            "adversarial": [
                case(
                    "comments.rs",
                    "/* outer /* inner */ " + zero + " */\n",
                    expected=False,
                    rationale="Rust block comments nest; signatures inside the outer comment after an inner close must remain non-executable text.",
                ),
                case(
                    "shadow.rs",
                    "mod std { pub mod mem {} }\n" + zero,
                    expected=False,
                    rationale="A local std module makes this relative path ambiguous. The detector must not infer standard-library identity from the spelling alone.",
                ),
                case(
                    "foreign.rs",
                    zero.replace("std::", "custom::std::"),
                    expected=False,
                    rationale="A longer module path ending with std is not the standard library path; suffix matching would invent the wrong function identity.",
                ),
            ],
        },
    ]
    return fixtures


def build() -> str:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    owned = {record["rule_id"] for record in records()}
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in owned] + records()
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = build()
    if args.check:
        if MANIFEST.read_text(encoding="utf-8") != rendered:
            print("stale Roblox/Rust v2 contracts")
            return 1
    else:
        MANIFEST.write_text(rendered, encoding="utf-8")
    print("Roblox/Rust contracts current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
