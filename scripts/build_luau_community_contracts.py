"""Original Luau contracts grounded in community leads and owning API semantics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {f"SP{n}" for n in range(708, 714)}


def records():
    rows = []

    def add(rule_id, sources, positive, negative, adversarial):
        rule = find_rule(rule_id)
        rows.append(
            {
                "rule_id": rule_id,
                "expected_severity": rule.severity,
                "expected_confidence": rule.confidence,
                "blocking_eligible": False,
                "false_positive_analysis": RULE_EXPLANATIONS[rule_id]["false_positive"],
                "sources": [{"url": url, "claim": claim} for url, claim in sources]
                + [
                    {
                        "url": f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html",
                        "claim": "Maps the local API/state boundary; not a deployed exploitation or recall assertion.",
                    }
                ],
                "positive": [{"path": "module.luau", "source": source} for source in positive],
                "negative": [{"path": "module.luau", "source": source} for source in negative],
                "adversarial": [
                    {
                        "path": "module.luau",
                        "source": source,
                        "expected": expected,
                        "rationale": why,
                    }
                    for source, expected, why in adversarial
                ],
            }
        )

    bounds = "local value=math.clamp(input,10,2)"
    add(
        "SP708",
        [
            (
                "https://raw.githubusercontent.com/luau-lang/luau/master/VM/src/lmathlib.cpp",
                "The native math implementations require ordered limits; equality is valid and reversed random limits produce an empty interval.",
            ),
            (
                "https://www.reddit.com/r/robloxgamedev/comments/zc7up9/",
                "2022 discovery lead: reversed negative random limits cause an interval error. Owning source, not comments, establishes the rule.",
            ),
            (
                "https://devforum.roblox.com/t/playermodulecameramoduletransparencycontroller-invalid-argument-3-to-clamp/1131588",
                "2021 discovery lead: reversed clamp limits break a camera path; runtime source confirms the API boundary.",
            ),
        ],
        [
            bounds,
            "return math.random(10,2)",
            "return math.random(-3,-8)",
            "return math.clamp(value,-1,-8)",
            "return math.clamp(0,5,4)",
            "return math.random(2,1)",
        ],
        [
            bounds.replace("10,2", "2,10"),
            bounds.replace("10,2", "2,2"),
            "return math.random(1,1)",
            "return math.random(-8,-3)",
            bounds.replace("10,2", "low,high"),
            bounds.replace("10,2", "10.5,2.5"),
            bounds.replace("math.clamp", "custom.clamp"),
            "local math=customMath\n" + bounds,
            "return math.random(9007199254740991,2)",
            "local random=math.random\nreturn random(10,2)",
        ],
        [
            (
                "-- " + bounds,
                False,
                "A commented invalid-range example cannot invoke a native numeric API.",
            ),
            (
                "local text=[=[" + bounds + "]=]",
                False,
                "A long literal is data and cannot establish an invalid numeric invocation.",
            ),
            (
                "local function f(math) " + bounds + " end",
                False,
                "A function parameter shadows the native math table and invalidates API identity.",
            ),
            (
                "math.clamp=customClamp\n" + bounds,
                False,
                "A changed library member must not be presumed to use the native bounds contract.",
            ),
            (
                bounds.replace("10,2", "10,-- bound\n2"),
                True,
                "An intervening comment does not change the order of literal integer bounds.",
            ),
        ],
    )

    nil_use = "for _,value in ipairs(table.sort(items)) do consume(value) end"
    add(
        "SP709",
        [
            (
                "https://raw.githubusercontent.com/luau-lang/luau/master/VM/src/ltablib.cpp",
                "Native sort, insert and clear mutate in place and return no table; clone/freeze return table values.",
            ),
            (
                "https://stackoverflow.com/questions/57064238/calling-table-sort-returns-nil",
                "Historical discovery lead about in-place sorting. Current Luau implementation confirms which return values are supported.",
            ),
        ],
        [
            nil_use,
            "return pairs(table.clear(items))",
            "return ipairs(table.insert(items,value))",
            "return table.sort(items)[1]",
            "return #table.clear(items)",
            "for _,value in table.sort(items) do consume(value) end",
        ],
        [
            "table.sort(items)\nfor _,value in ipairs(items) do consume(value) end",
            "return ipairs(table.clone(items))",
            "return pairs(table.freeze(items))",
            "return table.remove(items)",
            "return table.sort(items)",
            "local table=customTable\n" + nil_use,
            "local ipairs=customIterator\n" + nil_use,
            "return custom.sort(items)[1]",
            "local sorted=sortCopy(items)\nreturn ipairs(sorted)",
        ],
        [
            (
                "--[=[" + nil_use + "]=]",
                False,
                "A long comment cannot consume a table-mutator return value at runtime.",
            ),
            (
                "local text=`" + nil_use + "`",
                False,
                "An interpolated-string literal remains opaque to executable API signatures.",
            ),
            (
                "local function run(table) " + nil_use + " end",
                False,
                "A shadowing library parameter does not establish a nil-returning native mutator.",
            ),
            (
                "setfenv(1,environment)\n" + nil_use,
                False,
                "A modified environment makes native table and iterator identity unresolved.",
            ),
        ],
    )

    frozen = "local config=table.freeze({enabled=true})\nconfig.enabled=false"
    add(
        "SP710",
        [
            (
                "https://luau.org/library/#table-library",
                "Freezing prevents top-level changes, does not recursively freeze nested children, and cloning returns a mutable shallow copy.",
            ),
            (
                "https://rfcs.luau.org/function-table-clone.html",
                "The clone RFC distinguishes a mutable copy from the original frozen table; shared nested values are not deep copies.",
            ),
        ],
        [
            frozen,
            "table.freeze({enabled=true}).enabled=false",
            "table.freeze({})['value']=1",
            "local state=table.freeze({value=1});state['value']=2",
            "local config=table.freeze({});config.value=2",
        ],
        [
            "local config=table.freeze({enabled=true})\nreturn config.enabled",
            "local config=table.clone(table.freeze({enabled=true}))\nconfig.enabled=false",
            "local config=table.freeze({nested={}})\nconfig.nested.value=2",
            "table.freeze({nested={}}).nested.value=2",
            "local config={enabled=true}\nconfig.enabled=false",
            frozen.replace("table.freeze", "custom.freeze"),
            frozen.replace("\nconfig.", "\nshare(config)\nconfig."),
            frozen.replace("\nconfig.", "\nconfig=mutable\nconfig."),
            "local config=table.freeze({}) and mutable\nconfig.value=1",
            "local function factory() local config=table.freeze({}) end\nconfig.value=1",
        ],
        [
            (
                "local text=[==[" + frozen + "]==]",
                False,
                "Quoted frozen-table examples cannot freeze or modify an actual local value.",
            ),
            (
                "local table=customTable\n" + frozen,
                False,
                "A custom table library need not return an immutable value from its freeze method.",
            ),
            (
                "do local config=table.freeze({}) end\nconfig.value=2",
                False,
                "A closed lexical region cannot establish the later receiver's frozen binding.",
            ),
            (
                "table.freeze=copyTable\n" + frozen,
                False,
                "Reassigning the freeze member makes the native immutability contract unresolved.",
            ),
        ],
    )

    schedule = "task.spawn(print('ready'))"
    add(
        "SP711",
        [
            (
                "https://create.roblox.com/docs/reference/engine/libraries/task",
                "Spawn/defer/delay take a function or thread; task.wait returns elapsed time rather than a callback.",
            ),
            (
                "https://luau.org/library/#global-functions",
                "The standard print function does not return a callable value to be used as a scheduler callback.",
            ),
            (
                "https://www.reddit.com/r/robloxgamedev/comments/1vcool6/this_is_probably_really_inefficient_in_some_way/",
                "2026 scheduling discussion is a discovery lead; its generic resume-function comment is not adopted as API truth.",
            ),
        ],
        [
            schedule,
            "task.defer(warn('ready'))",
            "task.delay(1,print('ready'))",
            "task.spawn(task.wait(1))",
            "task.delay(2,task.wait())",
            "task.defer(print('ready'),argument)",
        ],
        [
            "task.spawn(print)",
            "task.spawn(function() print('ready') end)",
            "task.delay(1,function() warn('ready') end)",
            "task.spawn(callback)",
            "task.spawn(coroutine.create(callback))",
            "task.spawn(factory())",
            "local task=customScheduler\n" + schedule,
            "local print=callableFactory\n" + schedule,
            "task.wait(1)",
            "print('ready')",
        ],
        [
            (
                "-- " + schedule,
                False,
                "An example in a line comment does not call or schedule any function.",
            ),
            (
                "local text=[=[" + schedule + "]=]",
                False,
                "A long string literal must not be interpreted as a scheduler invocation.",
            ),
            (
                "local function f(task) " + schedule + " end",
                False,
                "A local scheduler parameter may accept values outside the native API contract.",
            ),
            (
                "task.spawn=customSpawn\n" + schedule,
                False,
                "A reassigned scheduler method must not establish native callback requirements.",
            ),
        ],
    )

    store = "game:GetService('DataStoreService'):GetDataStore('Profiles')"
    update = store + ":UpdateAsync(key,function(old) task.wait(1); return old end)"
    add(
        "SP712",
        [
            (
                "https://raw.githubusercontent.com/Roblox/creator-docs/main/content/en-us/reference/engine/classes/GlobalDataStore.yaml",
                "The owning GlobalDataStore reference explicitly forbids yielding in UpdateAsync transforms, including task.wait calls.",
            ),
            (
                "https://devforum.roblox.com/t/how-to-properly-utilize-updateasync/1133216",
                "2021 discussion points to transform-yield failures; owning API documentation confirms the restriction.",
            ),
        ],
        [
            update,
            update.replace("task.wait(1)", "wait(1)"),
            "local store="
            + store
            + "\nstore:UpdateAsync(key,function(old) task.wait();return old end)",
            "local service=game:GetService('DataStoreService')\nlocal store=service:GetDataStore('Profiles')\nstore:UpdateAsync(key,function(old) task.wait(1);return old end)",
            update.replace("old)", "old: any)"),
            update.replace("task.wait(1);", "task.wait(1)"),
        ],
        [
            update.replace("task.wait(1); ", ""),
            "task.wait(1);" + update.replace("task.wait(1); ", ""),
            update.replace("task.wait(1);", "task.spawn(function() task.wait(1) end);"),
            "customStore:UpdateAsync(key,function(old) task.wait(1);return old end)",
            update.replace("UpdateAsync", "SetAsync"),
            "local game=customGame\n" + update,
            "local task=customTask\n" + update,
            update.replace("'Profiles'", "storeName"),
            "local store="
            + store
            + "\nshare(store)\nstore:UpdateAsync(key,function(old) task.wait(1);return old end)",
            "local function make() local store="
            + store
            + " end\nstore:UpdateAsync(key,function(old) task.wait(1);return old end)",
        ],
        [
            (
                "--[=[" + update + "]=]",
                False,
                "A commented transform cannot invoke UpdateAsync or perform a yielding wait.",
            ),
            (
                "local text=[=[" + update + "]=]",
                False,
                "A transform signature inside a literal is data, not an executable callback.",
            ),
            (
                "getfenv(0)\n" + update,
                False,
                "An environment-dependent script does not establish native wait or store identity.",
            ),
            (
                update.replace("function(old)", "function(old) if allowed then").replace(
                    "; return old end)", " end; return old end)"
                ),
                False,
                "Conditional or nested callback control flow remains outside the flat direct-yield signature.",
            ),
        ],
    )

    signal = "game:GetService('Players').PlayerAdded:Wait(5)"
    add(
        "SP713",
        [
            (
                "https://create.roblox.com/docs/reference/engine/datatypes/RBXScriptSignal",
                "The native signal Wait API takes no timeout parameter; custom signal libraries may define a different contract.",
            ),
            (
                "https://devforum.roblox.com/t/what-is-better-repeat-until-or-eventwait/1990098",
                "2022 discussion warns against assuming a timeout on native signal waits; owning reference confirms its signature.",
            ),
        ],
        [
            signal,
            signal.replace("Players", "RunService").replace("PlayerAdded", "Heartbeat"),
            "Instance.new('BindableEvent').Event:Wait(3)",
            "local players=game:GetService('Players')\nplayers.PlayerAdded:Wait(5)",
            "local event=Instance.new('RemoteEvent')\nevent.OnServerEvent:Wait(5)",
        ],
        [
            signal.replace("(5)", "()"),
            "customSignal:Wait(5)",
            "local event=Signal.new();event:Wait(5)",
            signal.replace("(5)", "(timeout)"),
            signal.replace("(5)", "(0)"),
            signal.replace("(5)", "(5.5)"),
            "local game=customGame\n" + signal,
            "Instance.new('Folder').CustomSignal:Wait(5)",
            "game:GetService('BindableEvent').Event:Wait(5)",
            "local players=game:GetService('Players') and proxy\nplayers.PlayerAdded:Wait(5)",
        ],
        [
            (
                "-- " + signal,
                False,
                "A commented wait call cannot create a thread or an unsupported deadline.",
            ),
            (
                "local text=[==[" + signal + "]==]",
                False,
                "A signal-wait example in a long literal has no native scheduling effect.",
            ),
            (
                "local function f(Instance) Instance.new('BindableEvent').Event:Wait(5) end",
                False,
                "A shadowed Instance factory cannot establish a native RBXScriptSignal receiver.",
            ),
            (
                "local function make() local players=game:GetService('Players') end\nplayers.PlayerAdded:Wait(5)",
                False,
                "A receiver declared in a closed region cannot prove the later signal's native identity.",
            ),
        ],
    )

    remove = (
        "local remote=Instance.new('RemoteEvent')\nremote.OnServerEvent:Connect(function(player,key) "
        + store
        + ":RemoveAsync(key) end)"
    )
    increment = (
        "local remote=Instance.new('RemoteEvent')\nremote.OnServerEvent:Connect(function(player,key,amount) "
        + store
        + ":IncrementAsync(key,amount) end)"
    )
    add(
        "SP707",
        [
            (
                "https://create.roblox.com/docs/reference/engine/classes/GlobalDataStore",
                "Remove and increment mutate the record selected by a key; source matching does not prove authorization or a successful write.",
            ),
            (
                "https://create.roblox.com/docs/scripting/security/client-server-boundary",
                "Server-side authorization and validation are required before using client-selected persistent record data.",
            ),
        ],
        [
            remove,
            increment,
            remove.replace("player,key", "actor: Player, key: string"),
            increment.replace("function(player,key,amount)", "function(player,key,amount: number)"),
            remove.replace("'", '"'),
            increment.replace("'", '"'),
        ],
        [
            remove.replace("RemoveAsync(key)", "RemoveAsync(tostring(player.UserId))"),
            increment.replace(
                "IncrementAsync(key,amount)", "IncrementAsync(tostring(player.UserId),amount)"
            ),
            remove.replace(
                "function(player,key) ",
                "function(player,key) if not authorized(player,key) then return end ",
            ),
            increment.replace("IncrementAsync(key,amount)", "IncrementAsync(key,serverAmount)"),
            remove.replace("Instance.new('RemoteEvent')", "customRemote"),
            remove.replace("OnServerEvent", "OnClientEvent"),
        ],
        [
            (
                "--[=[" + remove + "]=]",
                False,
                "A long comment cannot register a destructive persistent-record operation.",
            ),
            (
                "local game=customGame\n" + increment,
                False,
                "A game-like custom object does not establish native persistent-data semantics.",
            ),
        ],
    )
    return rows


def augment_persistence(rows):
    extra = next(row for row in records() if row["rule_id"] == "SP707")
    for row in rows:
        if row["rule_id"] == "SP707":
            for kind in ("positive", "negative", "adversarial"):
                row[kind].extend(extra[kind])
            known = {source["url"] for source in row["sources"]}
            row["sources"].extend(
                source for source in extra["sources"] if source["url"] not in known
            )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    target = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in NEW_IDS] + [
        row for row in authored if row["rule_id"] in NEW_IDS
    ]
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for path, data in (
        (target, payload),
        (ROOT / "tests/luau_community_cases.json", {"schema_version": 1, "rules": authored}),
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
