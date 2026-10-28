"""Original multi-category API contracts; generation is maintainer-only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {f"SP{number}" for number in range(693, 699)}


def records():
    rows = []

    def add(rule_id, path, url, claim, positives, negatives, adversarial):
        rule = find_rule(rule_id)
        rows.append(
            {
                "rule_id": rule_id,
                "expected_severity": rule.severity,
                "expected_confidence": rule.confidence,
                "blocking_eligible": rule_id not in NEW_IDS,
                "sources": [
                    {"url": url, "claim": claim},
                    {
                        "url": f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html",
                        "claim": "Classifies the local failure boundary; this mapping does not establish deployed exposure or exploitability.",
                    },
                ],
                "false_positive_analysis": RULE_EXPLANATIONS[rule_id]["false_positive"],
                "positive": [{"path": path, "source": source} for source in positives],
                "negative": [{"path": path, "source": source} for source in negatives],
                "adversarial": [
                    {"path": path, "source": source, "expected": expected, "rationale": rationale}
                    for source, expected, rationale in adversarial
                ],
            }
        )

    http = "import {createServer} from 'node:http';\ncreateServer({requestTimeout:0, headersTimeout:0}, handler);\n"
    add(
        "SP693",
        "server.ts",
        "https://nodejs.org/api/http.html#serverrequesttimeout",
        "The receive deadlines can be explicitly disabled with zero; other ingress controls and exposure remain unknown.",
        [
            http,
            http.replace("node:http", "node:https"),
            http.replace("{createServer}", "{createServer as serve}").replace(
                "\ncreateServer", "\nserve"
            ),
            http.replace(
                "import {createServer} from 'node:http'",
                "const {createServer} = require('node:http')",
            ),
        ],
        [
            http.replace("requestTimeout:0", "requestTimeout:30000"),
            http.replace("headersTimeout:0", "headersTimeout:5000"),
            http.replace("requestTimeout:0, headersTimeout:0", ""),
            http.replace("headersTimeout:0", "headersTimeout:deadline"),
            http.replace("headersTimeout:0", "headersTimeout:0,...bounded"),
            http.replace("headersTimeout:0", "headersTimeout:0,headersTimeout:5000"),
            http.replace("node:http", "./transport"),
            http.replace("createServer", "request"),
            http.replace("import {", "import type {"),
        ],
        [
            (
                "/* " + http + " */",
                False,
                "A commented example cannot configure a live HTTP server.",
            ),
            (
                http.replace(
                    "\ncreateServer",
                    "\nfunction build(createServer: Factory) { return createServer",
                )
                + "}",
                False,
                "A parameter shadows the native HTTP factory and its option semantics.",
            ),
            (
                http.replace("headersTimeout:", "['headersTimeout']:"),
                False,
                "Computed property identity and override order remain unresolved.",
            ),
        ],
    )

    race = "async function wait() { await Promise.race([]); }\n"
    add(
        "SP694",
        "wait.ts",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/race",
        "An empty Promise.race cannot settle; a direct await does not progress through it.",
        [
            race,
            race.replace("[]", "[ /* no participants */ ]"),
            "export const run = async () => { await Promise.race(\n[]\n); };",
        ],
        [
            race.replace("[]", "[Promise.resolve(1)]"),
            race.replace("race", "all"),
            race.replace("[]", "entries"),
            race.replace("await ", "const never = "),
            race.replace("Promise.race([])", "Promise.race([]).timeout(1000)"),
            race.replace("Promise.race([])", "local.Promise.race([])"),
            "import Promise from 'bluebird';\n" + race,
            "const Promise = custom;\n" + race,
        ],
        [
            (
                "// " + race,
                False,
                "Code-shaped comments must remain data rather than awaited races.",
            ),
            (
                race.replace("wait()", "wait(Promise: Scheduler)"),
                False,
                "An explicitly shadowed scheduler is not the native Promise class.",
            ),
            (
                race.replace("[]", "[,,,]"),
                False,
                "A sparse array yields undefined participants and is not an empty iterable.",
            ),
        ],
    )
    dart_race = "import 'dart:async';\nvoid main() async { await Future.any([]); }\n"
    dart_cases = {
        "positive": [
            dart_race,
            dart_race.replace("'dart:async';", "'dart:async' as tasks;").replace(
                "Future.any", "tasks.Future.any"
            ),
            dart_race.replace("[]", "const []"),
        ],
        "negative": [
            dart_race.replace("[]", "[Future.value(1)]"),
            dart_race.replace("any", "wait"),
            dart_race.replace("await ", "final never = "),
            dart_race.replace(
                "Future.any([])", "Future.any([]).timeout(const Duration(seconds: 1))"
            ),
            dart_race.replace("dart:async", "custom.dart"),
            dart_race.replace("void main()", "void main(Future)"),
            dart_race.replace("void main()", "import 'custom.dart';\nvoid main()"),
        ],
        "adversarial": [
            (
                "/* " + dart_race + " */",
                False,
                "Comment contents do not create a native asynchronous wait.",
            ),
            (
                dart_race.replace("void main()", "class Future {}\nvoid main()"),
                False,
                "A local Future type is not the imported standard library class.",
            ),
        ],
    }
    for kind in ("positive", "negative"):
        rows[-1][kind].extend({"path": "wait.dart", "source": value} for value in dart_cases[kind])
    rows[-1]["adversarial"].extend(
        {"path": "wait.dart", "source": value, "expected": expected, "rationale": why}
        for value, expected, why in dart_cases["adversarial"]
    )
    rows[-1]["sources"].append(
        {
            "url": "https://api.dart.dev/dart-async/Future/any.html",
            "claim": "Dart Future.any never completes when its iterable is empty; runtime type identity and wrappers require separate resolution.",
        }
    )

    sorting = "const sorted = [3,1,2].sort((a,b) => a > b);\n"
    add(
        "SP695",
        "sort.ts",
        "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort#sorting_with_non-well-formed_comparator",
        "Comparators must provide consistent signed ordering results; boolean comparators can yield engine-dependent or unintended order.",
        [
            sorting,
            sorting.replace("sort", "toSorted").replace("a > b", "a < b"),
            sorting.replace("(a,b)", "(a: number,b: number)").replace(
                "a > b", "{ return a >= b; }"
            ),
        ],
        [
            sorting.replace("a > b", "a - b"),
            sorting.replace("a > b", "b - a"),
            sorting.replace("a > b", "a > b ? 1 : a < b ? -1 : 0"),
            sorting.replace("[3,1,2]", "custom"),
            sorting.replace("[3,1,2]", "[]"),
            sorting.replace("[3,1,2]", "[1]"),
            sorting.replace("[3,1,2]", "[...items]"),
            sorting.replace("(a,b) => a > b", "compare"),
            sorting.replace("sort((a,b) => a > b)", "sort[(a,b) => a > b]"),
        ],
        [
            (
                "/* " + sorting + " */",
                False,
                "Comparator-looking prose is not a native array operation.",
            ),
            (
                sorting.replace("[3,1,2]", "matrix[3,1,2]"),
                False,
                "An indexed custom receiver is not an array literal despite its closing bracket.",
            ),
            (
                "Array.prototype.sort = custom;\n" + sorting,
                False,
                "Visible prototype replacement makes native sort semantics unresolved.",
            ),
        ],
    )

    xml = "using System.Xml;\nvar reader = XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, MaxCharactersFromEntities = 0 });\n"
    add(
        "SP696",
        "reader.cs",
        "https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.maxcharactersfromentities",
        "Zero removes the entity expansion cap; external resolver restrictions do not bound internal entity expansion.",
        [
            xml,
            xml.replace("0 }", "0L, XmlResolver = null }"),
            xml.replace("using System.Xml;\n", "")
            .replace("XmlReader.Create", "System.Xml.XmlReader.Create")
            .replace("new XmlReaderSettings", "new System.Xml.XmlReaderSettings")
            .replace("= DtdProcessing.Parse", "= System.Xml.DtdProcessing.Parse"),
        ],
        [
            xml.replace("= 0", "= 128"),
            xml.replace("DtdProcessing.Parse", "DtdProcessing.Prohibit"),
            xml.replace(", MaxCharactersFromEntities = 0", ""),
            xml.replace("0 }", "0, MaxCharactersInDocument = 1024 }"),
            xml.replace("0 }", "limit }"),
            xml.replace("using System.Xml;", "using Custom.Xml;"),
            xml.replace("XmlReader.Create", "CustomReader.Create"),
            xml.replace("0 }", "0, ConformanceLevel = ConformanceLevel.Fragment }"),
            xml.replace("0 }", "0, MaxCharactersFromEntities = 100 }"),
        ],
        [
            (
                "/* " + xml + " */",
                False,
                "XML configuration in a comment cannot change parser bounds.",
            ),
            (
                "class XmlReader {}\n" + xml,
                False,
                "A local reader type prevents native framework identity from being inferred.",
            ),
            (
                xml.replace("new XmlReaderSettings", "new OtherSettings"),
                False,
                "A settings-shaped custom object is not a native XmlReaderSettings instance.",
            ),
        ],
    )

    listener = "import logging.config\nlogging.config.listen(9030, verify=None).start()\n"
    add(
        "SP697",
        "listener.py",
        "https://docs.python.org/3/library/logging.config.html#logging.config.listen",
        "The standard logging listener accepts configuration on localhost; verification should authenticate bytes before object construction/evaluation.",
        [
            listener,
            listener.replace(
                "import logging.config", "from logging.config import listen as serve"
            ).replace("logging.config.listen", "serve"),
            listener.replace("import logging.config", "import logging.config as config").replace(
                "logging.config.listen(9030, verify=None)", "config.listen(0, None)"
            ),
        ],
        [
            listener.replace("None", "verify_signature"),
            listener.replace(".start()", ""),
            listener.replace("9030", "configured_port"),
            listener.replace("9030", "-1"),
            listener.replace("9030", "True"),
            listener.replace("logging.config", "custom.config"),
            listener.replace("verify=None", "**options"),
            listener.replace("verify=None", "verify=None, port=1"),
            "import logging.config\nlogging.config.__dict__.update({'listen': safe})\nlogging.config.listen(9030,verify=None).start()",
        ],
        [
            (
                "# " + listener.replace("\n", "\n# "),
                False,
                "Commented listener examples cannot open a configuration channel.",
            ),
            (
                listener.replace(
                    "logging.config.listen",
                    "logging.config.listen = safe_listener\nlogging.config.listen",
                ),
                False,
                "Overwriting the listener invalidates the imported function identity.",
            ),
            (
                "import local as logging\n" + listener,
                False,
                "A conflicting import leaves the logging namespace unresolved.",
            ),
        ],
    )

    compression = "import {gzipSync} from 'node:zlib';\nasync function encode(data: Uint8Array) { return await gzipSync(data); }\n"
    add(
        "SP698",
        "compression.ts",
        "https://nodejs.org/api/zlib.html",
        "Synchronous compression executes on the calling thread before returning a value; await does not offload that work.",
        [
            compression,
            compression.replace("{gzipSync}", "{gzipSync as encodeNow}").replace(
                "await gzipSync", "await encodeNow"
            ),
            compression.replace(
                "import {gzipSync} from 'node:zlib'", "const zlib = require('node:zlib')"
            ).replace("await gzipSync", "await zlib.brotliCompressSync"),
        ],
        [
            compression.replace("await ", ""),
            compression.replace("gzipSync", "gzip"),
            compression.replace("node:zlib", "./compression"),
            compression.replace("import {", "import type {"),
            compression.replace("await gzipSync(data)", "await runInWorker(data)"),
            compression.replace("await gzipSync(data)", "await Promise.resolve(gzipSync(data))"),
        ],
        [
            (
                "/* " + compression + " */",
                False,
                "Commented compression examples cannot block the calling thread.",
            ),
            (
                compression.replace(
                    "encode(data: Uint8Array)", "encode(data: Uint8Array, gzipSync: Compressor)"
                ),
                False,
                "A local compressor parameter has unknown synchronous semantics.",
            ),
            (
                compression.replace("gzipSync(data)", "gzipSync(...inputs)"),
                False,
                "Spread arguments leave overload and invocation validity unresolved.",
            ),
        ],
    )

    task = "import asyncio\nasync def work():\n    await asyncio.sleep(0)\nasync def launch():\n    asyncio.create_task(work())\n"
    add(
        "SP346",
        "tasks.py",
        "https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task",
        "Background tasks need retained references; awaiting, returning or owning the task is distinct from a discarded expression.",
        [
            task,
            task.replace("import asyncio", "import asyncio as tasks").replace("asyncio.", "tasks."),
            task.replace("import asyncio", "from asyncio import create_task as spawn, sleep")
            .replace("asyncio.create_task", "spawn")
            .replace("asyncio.sleep", "sleep"),
        ],
        [
            task.replace("    asyncio.create_task", "    await asyncio.create_task"),
            task.replace("    asyncio.create_task", "    return asyncio.create_task"),
            task.replace("    asyncio.create_task", "    task = asyncio.create_task"),
            task.replace("asyncio.create_task(work())", "tasks.add(asyncio.create_task(work()))"),
            task.replace("import asyncio", "import custom as asyncio"),
            task.replace("launch():", "launch(asyncio):"),
            task.replace(
                "asyncio.create_task(work())", "asyncio.create_task(work(), eager_start=True)"
            ),
            task + "loop.set_task_factory(factory)\n",
        ],
        [
            (
                "# " + task.replace("\n", "\n# "),
                False,
                "A quoted/commented call cannot construct or schedule a native task, so it cannot establish a discarded live-task reference.",
            ),
            (
                task.replace("import asyncio", "import asyncio\nimport custom as asyncio"),
                False,
                "Multiple imports with the same binding invalidate native identity; the later module may provide a different task-ownership contract.",
            ),
            (
                task.replace("asyncio.create_task(work())", "asyncio.create_task(None)"),
                False,
                "A literal invalid coroutine argument raises before a background task is constructed; it is not evidence that a task reference was lost.",
            ),
        ],
    )

    go = 'package pool\nimport "database/sql"\nfunc configure(db *sql.DB) {\n db.SetMaxOpenConns(0)\n}\n'
    add(
        "SP375",
        "pool.go",
        "https://pkg.go.dev/database/sql#DB.SetMaxIdleConns",
        "Zero idle retention is separate from zero/unlimited open connections.",
        [go, go.replace("(0)", "( 0 )"), go.replace("db.SetMax", "// configure\n db.SetMax")],
        [
            go.replace("SetMaxOpenConns", "SetMaxIdleConns"),
            go.replace("(0)", "(25)"),
            go.replace("db.SetMaxOpenConns(0)", "db.SetMaxOpenConns(25)\n db.SetMaxIdleConns(0)"),
            go.replace("db.SetMaxOpenConns(0)", "db.SetMaxOpenConns(25)\n db.SetMaxIdleConns(5)"),
            go.replace("db.SetMaxOpenConns(0)", "db.SetMaxIdleConns(-1)"),
        ],
        [
            (
                go.replace("db.SetMax", "// db.SetMax"),
                False,
                "A comment describing an open cap is not executable configuration.",
            ),
            (
                go.replace("SetMaxOpenConns", "SetMaxIdleConns"),
                False,
                "Disabling idle retention must not be conflated with unlimited open connections.",
            ),
        ],
    )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    manifest = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    owned = NEW_IDS | {"SP346"}
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in owned] + [
        row for row in authored if row["rule_id"] in NEW_IDS
    ]
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for path, data in (
        (manifest, payload),
        (ROOT / "tests/broad_quality_cases.json", {"schema_version": 1, "rules": authored}),
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
