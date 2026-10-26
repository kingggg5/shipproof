"""Original stream/completion/persistence contracts; maintainer generation only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {"SP707"}


def records():
    rows = []

    def add(rule_id, path, sources, positive, negative, adversarial):
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
                        "claim": "Taxonomy for the local ownership/authorization boundary, not proof of deployment or successful exploitation.",
                    }
                ],
                "positive": [{"path": path, "source": source} for source in positive],
                "negative": [{"path": path, "source": source} for source in negative],
                "adversarial": [
                    {"path": path, "source": source, "expected": expected, "rationale": why}
                    for source, expected, why in adversarial
                ],
            }
        )

    stream = "import {createReadStream,createWriteStream} from 'node:fs';\ncreateReadStream(input).pipe(createWriteStream(output));\n"
    add(
        "SP336",
        "stream.ts",
        [
            (
                "https://nodejs.org/api/stream.html#readablepipedestination-options",
                "Pipe does not own source errors or close the destination when a readable fails; native stream identity and error ownership are separate from a pipe spelling.",
            )
        ],
        [
            stream,
            stream.replace(
                "{createReadStream,createWriteStream}",
                "{createReadStream as read,createWriteStream as write}",
            )
            .replace("\ncreateReadStream", "\nread")
            .replace(".pipe(createWriteStream", ".pipe(write"),
            "const fs = require('node:fs');\nfs.createReadStream(input).pipe(fs.createWriteStream(output));",
            stream.replace("));", ")).on('error',report);"),
            stream.replace(".pipe(", "\n  .pipe(\n").replace("output));", "output)\n  );"),
        ],
        [
            stream.replace(
                "createReadStream(input).pipe", "createReadStream(input).on('error',report).pipe"
            ),
            stream.replace(
                "createReadStream(input).pipe", "createReadStream(input).once('error',report).pipe"
            ),
            "import {pipeline} from 'node:stream/promises';\nimport {createReadStream,createWriteStream} from 'node:fs';\nawait pipeline(createReadStream(input),createWriteStream(output));",
            stream.replace("from 'node:fs'", "from './streams'"),
            stream.replace("import {", "import type {"),
            stream.replace("createReadStream(input)", "createReadStream(input,{fs:customFs})"),
            stream.replace("createWriteStream(output)", "createWriteStream(output,{fs:customFs})"),
            stream.replace(".pipe(createWriteStream(output))", ".pipe(customDestination)"),
            stream.replace(
                "createWriteStream(output)",
                "createWriteStream(output).on('pipe',source=>source.on('error',report))",
            ),
            "import {createReadStream,createWriteStream} from 'node:fs';\nconst source=createReadStream(input); source.on('error',report); source.pipe(createWriteStream(output));",
            stream.replace("createReadStream(input)", "createReadStream(null)"),
            stream.replace("createReadStream(input)", "createReadStream(-1)"),
            stream.replace("createReadStream(input)", "createReadStream(void 0)"),
            stream.replace(
                "{createReadStream,createWriteStream}",
                "{createReadStream,createWriteStream,ReadStream}",
            ).replace(
                "\ncreateReadStream", "\nReadStream['prototype'].pipe=customPipe;\ncreateReadStream"
            ),
            stream.replace("createWriteStream(output)", "createWriteStream(0)"),
        ],
        [
            (
                "/* " + stream + " */",
                False,
                "A commented constructor/pipe example cannot create a native stream or establish actual source error ownership.",
            ),
            (
                stream + "Object.getPrototypeOf(instance).on=customOn;",
                False,
                "Visible prototype modification leaves standard event ownership unresolved, so missing-handler evidence cannot be established.",
            ),
            (
                stream.replace(
                    "\ncreateReadStream", "\nfunction copy(createReadStream) { createReadStream"
                )
                + "}",
                False,
                "A parameter with the factory spelling shadows the imported native factory and cannot establish native stream identity.",
            ),
            (
                stream + "createReadStream=customFactory;",
                False,
                "A reassigned factory does not establish native filesystem stream behavior or the standard pipe error-ownership contract.",
            ),
        ],
    )

    read = "import {readFile} from 'node:fs';\nasync function load(path) { return await readFile(path,(error,data)=>{report(error,data);}); }"
    write = "import {writeFile} from 'node:fs';\nasync function save(path,data) { await writeFile(path,data,(error)=>{report(error);}); }"
    add(
        "SP703",
        "callback.ts",
        [
            (
                "https://nodejs.org/api/fs.html#fsreadfilepath-options-callback",
                "Callback file APIs do not return the Promise for completion; the fs/promises API supplies the awaited result.",
            )
        ],
        [
            read,
            write,
            read.replace("(error,data)=>{report(error,data);}", "error=>report(error)"),
            write.replace("(error)=>", "async (error)=>"),
            read.replace("path,(error", "path,'utf8',(error"),
            write.replace("path,data,(error", "path,data,{encoding:'utf8'},(error"),
            read.replace("{readFile}", "{readFile as read}").replace(
                "await readFile", "await read"
            ),
            read.replace("import {readFile} from 'node:fs';", "const fs=require('fs');").replace(
                "await readFile", "await fs.readFile"
            ),
        ],
        [
            read.replace("node:fs", "node:fs/promises").replace(
                ",(error,data)=>{report(error,data);}", ""
            ),
            write.replace("node:fs", "node:fs/promises").replace(",(error)=>{report(error);}", ""),
            read.replace("return await readFile", "return readFile"),
            write.replace("await writeFile", "writeFile"),
            read.replace("node:fs", "./filesystem"),
            read.replace("import {", "import type {"),
            read.replace("(error,data)=>{report(error,data);}", "callback"),
            read.replace("path,(error", "...inputs,(error"),
            read.replace(
                "await readFile(path,(error,data)=>{report(error,data);})",
                "await new Promise((resolve,reject)=>readFile(path,(error,data)=>error?reject(error):resolve(data)))",
            ),
            "import fs from 'node:fs'; async function load(path) { return await fs.promises.readFile(path); }",
        ],
        [
            (
                "/* " + read + " */",
                False,
                "An API signature inside a comment cannot start asynchronous file I/O.",
            ),
            (
                read.replace("load(path)", "load(path,readFile)"),
                False,
                "A shadowing function parameter invalidates imported callback API identity.",
            ),
            (
                write + "writeFile=customWriter;",
                False,
                "A changed imported binding cannot establish the callback completion contract.",
            ),
        ],
    )

    drop = "BEGIN;\nDROP INDEX CONCURRENTLY account_lookup;\nCOMMIT;"
    rebuild = "BEGIN;\nREINDEX INDEX CONCURRENTLY account_lookup;\nCOMMIT;"
    add(
        "SP705",
        "index.sql",
        [
            (
                "https://www.postgresql.org/docs/18/sql-dropindex.html",
                "PostgreSQL concurrent DROP INDEX cannot execute in a transaction block; ordinary DROP INDEX can.",
            ),
            (
                "https://www.postgresql.org/docs/18/sql-reindex.html",
                "PostgreSQL concurrent REINDEX cannot execute in a transaction block; other REINDEX restrictions depend on the object type.",
            ),
        ],
        [
            drop,
            rebuild,
            rebuild.replace("REINDEX INDEX", "REINDEX TABLE"),
            drop.replace("BEGIN", "START TRANSACTION").replace(
                "CONCURRENTLY ", "CONCURRENTLY IF EXISTS "
            ),
            rebuild.replace("BEGIN;", "BEGIN; COMMIT AND CHAIN;"),
            "CREATE TEMP TABLE sample(id integer);\nBEGIN; CREATE INDEX CONCURRENTLY sample_idx ON sample(id); COMMIT;",
        ],
        [
            drop.replace("BEGIN;", ""),
            rebuild.replace("BEGIN;", ""),
            drop.replace("CONCURRENTLY ", ""),
            rebuild.replace("CONCURRENTLY ", ""),
            drop.replace("BEGIN;", "BEGIN; COMMIT;"),
            rebuild.replace("BEGIN;", "BEGIN; ROLLBACK;"),
            rebuild.replace("REINDEX INDEX CONCURRENTLY", "REINDEX (CONCURRENTLY false) INDEX"),
            "DO $$ BEGIN PERFORM 1; END $$;\nDROP INDEX CONCURRENTLY account_lookup;",
        ],
        [
            (
                "SELECT $example$" + drop + "$example$;",
                False,
                "Transaction and DDL text inside a dollar literal are data, not commands.",
            ),
            (
                "/* outer /* nested " + rebuild + " */ comment */",
                False,
                "Nested comments cannot start a transaction or rebuild a persistent index.",
            ),
            (
                drop.replace("DROP INDEX", "DROP /* gap */ INDEX"),
                True,
                "A comment between keywords does not remove the concurrent transaction restriction.",
            ),
        ],
    )

    sink = "game:GetService('DataStoreService'):GetDataStore('Profiles'):SetAsync(key,value)"
    remote = (
        "local remote=Instance.new('RemoteEvent')\nremote.OnServerEvent:Connect(function(player,key,value)\n"
        + sink
        + "\nend)"
    )
    invoke = (
        remote.replace("RemoteEvent", "RemoteFunction")
        .replace("OnServerEvent:Connect(function", "OnServerInvoke=function")
        .replace("\nend)", "\nend")
    )
    add(
        "SP707",
        "store.server.luau",
        [
            (
                "https://create.roblox.com/docs/scripting/security/client-server-boundary",
                "Remote arguments that affect persistent player data require server-side validation and authorization; successful data corruption is not implied by a source match.",
            ),
            (
                "https://create.roblox.com/docs/cloud-services/data-stores",
                "Server code obtains a native DataStore and SetAsync takes the key and value; the API can fail and is not invoked by this scanner.",
            ),
        ],
        [
            remote,
            invoke,
            remote.replace("player,key,value", "actor: Player, key: string, value: any"),
            remote.replace("key,value", "recordKey,recordValue").replace(
                "(player,recordKey,recordValue)", "(actor,recordKey,recordValue)"
            ),
            remote.replace("'", '"'),
            remote.replace("\n" + sink, "\n-- direct write\n" + sink + ";"),
        ],
        [
            remote.replace("SetAsync(key,value)", "SetAsync(tostring(player.UserId),value)"),
            remote.replace("SetAsync(key,value)", "SetAsync(key,serverValue)"),
            remote.replace("\n" + sink, "\nif not authorized(player,key) then return end\n" + sink),
            remote.replace("\n" + sink, "\nlocal key=serverKey\n" + sink),
            remote.replace("Instance.new('RemoteEvent')", "customRemote"),
            remote.replace("Instance.new('RemoteEvent')", "Instance.new('BindableEvent')"),
            remote.replace("OnServerEvent", "OnClientEvent"),
            remote.replace("DataStoreService", "CustomStoreService"),
            remote.replace("SetAsync", "UpdateAsync"),
            remote.replace("GetDataStore('Profiles')", "GetDataStore(storeName)"),
            remote.replace("player,key,value", "player,key,value,options"),
            remote.replace("player,key,value", "player,key,key"),
            remote.replace("'Profiles'", "'" + "x" * 33 + "'"),
            remote.replace(sink, "pcall(function() " + sink + " end)"),
            remote + "\nremote.OnServerEvent:Connect(function(player,key,value) audit(value) end)",
        ],
        [
            (
                "--[=[" + remote + "]=]",
                False,
                "A long Luau comment cannot register a remote or issue a persistent write.",
            ),
            (
                "local sample=[==[" + remote + "]==]",
                False,
                "A long literal contains data, not a native server callback or DataStore call.",
            ),
            (
                "local game=customGame\n" + remote,
                False,
                "A shadowed game name cannot prove native DataStoreService identity.",
            ),
            (
                "local Instance=customFactory\n" + remote,
                False,
                "An Instance-like custom factory does not establish a native Roblox remote.",
            ),
            (
                "setfenv(1,customEnvironment)\n" + remote,
                False,
                "A modified environment leaves the game and Instance globals unresolved.",
            ),
            (
                remote.replace("remote.OnServer", "remote=customRemote\nremote.OnServer"),
                False,
                "Reassignment invalidates the locally constructed remote receiver.",
            ),
        ],
    )
    return rows


def augment_existing_contracts(rows):
    """Add syntax variants to their existing ID's canonical v2 contract."""
    extensions = {row["rule_id"]: row for row in records() if row["rule_id"] in {"SP703", "SP705"}}
    for row in rows:
        extension = extensions.get(row["rule_id"])
        if extension is not None:
            for kind in ("positive", "negative", "adversarial"):
                row[kind].extend(extension[kind])
            known = {source["url"] for source in row["sources"]}
            row["sources"].extend(
                source for source in extension["sources"] if source["url"] not in known
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
        (ROOT / "tests/io_ownership_cases.json", {"schema_version": 1, "rules": authored}),
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
