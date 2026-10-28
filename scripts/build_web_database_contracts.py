"""Original Node/React/PostgreSQL contracts; maintainer generation only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {f"SP{number}" for number in range(702, 707)}
RETIRED_IDS = {"SP325", "SP334", "SP359", "SP363", "SP423"}


def records():
    rows = []

    def add(rule_id, path, url, claim, positive, negative, adversarial):
        rule = find_rule(rule_id)
        rows.append(
            {
                "rule_id": rule_id,
                "expected_severity": rule.severity,
                "expected_confidence": rule.confidence,
                "blocking_eligible": False,
                "false_positive_analysis": RULE_EXPLANATIONS[rule_id]["false_positive"],
                "sources": [
                    {"url": url, "claim": claim},
                    {
                        "url": f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[-1]}.html",
                        "claim": "Taxonomy for the local API/configuration boundary, not execution or exploitability evidence.",
                    },
                ],
                "positive": [{"path": path, "source": source} for source in positive],
                "negative": [{"path": path, "source": source} for source in negative],
                "adversarial": [
                    {"path": path, "source": source, "expected": expected, "rationale": why}
                    for source, expected, why in adversarial
                ],
            }
        )

    effect = "import {useEffect} from 'react';\nexport function useRefresh() { useEffect(async () => { await refresh(); }, []); }\n"
    add(
        "SP702",
        "effect.tsx",
        "https://react.dev/reference/react/useEffect",
        "Effect setup may return cleanup or nothing; an async function returns a Promise. Missing dependencies alone do not establish an infinite loop.",
        [
            effect,
            effect.replace("useEffect", "useLayoutEffect"),
            effect.replace("useEffect", "useInsertionEffect"),
            effect.replace("{useEffect}", "{useEffect as setup}").replace(" useEffect(", " setup("),
            effect.replace("async () =>", "async function setup()"),
            effect.replace("{useEffect}", "* as React").replace(" useEffect(", " React.useEffect("),
        ],
        [
            effect.replace("async () => { await refresh(); }", "() => { void refresh(); }"),
            effect.replace(
                "async () => { await refresh(); }",
                "() => { async function run() { await refresh(); } void run(); return cancel; }",
            ),
            effect.replace("async () => { await refresh(); }", "() => { auditCommit(); } ").replace(
                ", []", ""
            ),
            effect.replace("from 'react'", "from './custom-hooks'"),
            effect.replace("import {", "import type {"),
            effect.replace("{useEffect}", "{type useEffect}"),
            effect.replace("async () => { await refresh(); }", "synchronousSetup"),
            effect.replace(
                "async () => { await refresh(); }", "async function* setup() { yield 1; }"
            ),
        ],
        [
            (
                "/* " + effect + " */",
                False,
                "A comment cannot invoke React or register asynchronous effect setup.",
            ),
            (
                effect.replace(
                    "export function useRefresh()", "export function useRefresh(useEffect: any)"
                ),
                False,
                "A typed parameter shadows the imported hook.",
            ),
            (
                effect + "useEffect = customHook;",
                False,
                "A changed hook binding does not establish React identity.",
            ),
            (
                effect.replace(
                    "{ await refresh(); }",
                    "{ /* returning cleanup asynchronously is still wrong */ return cancel; }",
                ),
                True,
                "Returning cleanup through a Promise is still not synchronous effect cleanup.",
            ),
        ],
    )

    pipe = "import {pipeline} from 'node:stream';\nasync function transfer(source, destination) { await pipeline(source, destination, (error) => { report(error); }); }\n"
    add(
        "SP703",
        "pipeline.ts",
        "https://nodejs.org/api/stream.html#streampipelinesource-transforms-destination-callback",
        "Callback pipeline returns the destination; the stream/promises API supplies completion promises.",
        [
            pipe,
            pipe.replace("node:stream", "stream"),
            pipe.replace("{pipeline}", "{pipeline as pipe}").replace(
                "await pipeline", "await pipe"
            ),
            pipe.replace(
                "(error) => { report(error); }", "function done(error) { report(error); }"
            ),
            pipe.replace(
                "import {pipeline} from 'node:stream';", "const streams = require('node:stream');"
            ).replace("await pipeline", "await streams.pipeline"),
        ],
        [
            pipe.replace("node:stream", "node:stream/promises").replace(
                ", (error) => { report(error); }", ""
            ),
            pipe.replace("await pipeline", "pipeline"),
            pipe.replace("node:stream", "./custom-stream"),
            pipe.replace("import {", "import type {"),
            pipe.replace(
                "await pipeline(source, destination, (error) => { report(error); })",
                "await new Promise((resolve, reject) => pipeline(source, destination, (error) => error ? reject(error) : resolve()))",
            ),
            pipe.replace("source, destination,", "...streams,"),
            pipe.replace("(error) => { report(error); }", "completionHandler"),
            pipe.replace(
                "await pipeline(source, destination, (error) => { report(error); })",
                "await wrappedPipeline(source, destination)",
            ),
        ],
        [
            (
                "/* " + pipe + " */",
                False,
                "A commented pipeline example cannot register streams or a completion callback.",
            ),
            (
                pipe.replace(
                    "transfer(source, destination)", "transfer(source, destination, pipeline)"
                ),
                False,
                "An argument shadows the pipeline import.",
            ),
            (
                pipe.replace("await pipeline", "await object.pipeline"),
                False,
                "A property spelling does not establish native pipeline identity.",
            ),
            (
                pipe.replace("await pipeline", "await /* completion? */ pipeline"),
                True,
                "Comments do not change the awaited callback overload.",
            ),
        ],
    )

    url = "postgresql://db.example/app?sslmode=require"
    pg = (
        "import {Client} from 'pg';\nconst db = new Client({connectionString:'"
        + url
        + "', ssl:{ca: trustedCA}});\n"
    )
    add(
        "SP704",
        "database.ts",
        "https://node-postgres.com/features/ssl",
        "SSL parameters in a connectionString replace the separately supplied SSL object and its extra options.",
        [
            pg,
            pg.replace("Client", "Pool"),
            pg.replace("{Client}", "{Client as Database}").replace("new Client", "new Database"),
            pg.replace("import {Client} from 'pg';", "const pg = require('pg');").replace(
                "new Client", "new pg.Client"
            ),
            pg.replace("sslmode=require", "sslrootcert=%2Fetc%2Ftrusted-ca.pem"),
        ],
        [
            pg.replace("?sslmode=require", ""),
            pg.replace("ssl:{ca: trustedCA}", "ssl:true"),
            pg.replace("ssl:{ca: trustedCA}", "ssl:{cert:clientCertificate}"),
            pg.replace("from 'pg'", "from './database'"),
            pg.replace("import {", "import type {"),
            pg.replace("'" + url + "'", "environmentUrl"),
            pg.replace("sslmode=require", "sslmode=unknown"),
            pg.replace("sslmode=require", "application_name=sslmode-require"),
            pg.replace("sslmode=require", "sslmode=require&sslmode=disable"),
            pg.replace("ssl:{ca: trustedCA}", "ssl:{...tlsDefaults, ca:trustedCA}"),
            pg.replace("ssl:{ca: trustedCA}", "ssl:{ca: trustedCA}, stream:customStream"),
            pg.replace("Client", "Pool").replace(
                "ssl:{ca: trustedCA}", "ssl:{ca: trustedCA}, Client:CustomClient"
            ),
            pg.replace("ssl:{ca: trustedCA}", "ssl:{ca: trustedCA}, connection:customConnection"),
            pg.replace("postgresql:", "https:"),
        ],
        [
            ("/* " + pg + " */", False, "A literal example cannot configure a pool."),
            (
                pg.replace("const db =", "const Client = CustomClient;\nconst db ="),
                False,
                "A local constructor invalidates import provenance.",
            ),
            (
                pg.replace("connectionString:", "...base, connectionString:"),
                False,
                "A spread leaves effective options unresolved.",
            ),
            (
                pg.replace("sslmode", "%73slmode"),
                True,
                "Standard URL parameter decoding preserves the SSL override.",
            ),
        ],
    )

    index = "BEGIN;\nCREATE INDEX CONCURRENTLY account_lookup ON accounts (id);\nCOMMIT;\n"
    add(
        "SP705",
        "migration.sql",
        "https://www.postgresql.org/docs/18/sql-createindex.html",
        "PostgreSQL CREATE INDEX CONCURRENTLY cannot run inside a transaction block.",
        [
            index,
            index.replace("BEGIN", "START TRANSACTION"),
            index.replace("BEGIN", "BEGIN WORK").replace("CREATE INDEX", "CREATE UNIQUE INDEX"),
            index.replace(
                "CONCURRENTLY account_lookup", "CONCURRENTLY IF NOT EXISTS account_lookup"
            ),
            index.replace("BEGIN;", "BEGIN; COMMIT AND CHAIN;"),
            index.replace("BEGIN;", "BEGIN; SAVEPOINT migration; ROLLBACK TO SAVEPOINT migration;"),
        ],
        [
            index.replace("BEGIN;", ""),
            index.replace("CONCURRENTLY ", ""),
            index.replace("BEGIN;", "BEGIN; COMMIT;"),
            index.replace("BEGIN;", "BEGIN; ROLLBACK;"),
            index.replace("BEGIN;", "BEGIN; END;"),
            index.replace("BEGIN;", "BEGIN; COMMIT AND NO CHAIN;"),
            index.replace(
                "CREATE INDEX CONCURRENTLY account_lookup ON accounts (id);",
                "SELECT 'CREATE INDEX CONCURRENTLY account_lookup ON accounts(id)';",
            ),
            "DO $body$ BEGIN CREATE INDEX account_lookup ON accounts(id); END; $body$;\nCREATE INDEX CONCURRENTLY account_lookup ON accounts(id);",
            "CREATE FUNCTION sample() RETURNS void LANGUAGE SQL BEGIN ATOMIC SELECT 1; END;\n"
            + index,
        ],
        [
            (
                "-- " + index.replace("\n", "\n-- "),
                False,
                "Commented transaction text has no DDL effect.",
            ),
            (
                "SELECT $note$" + index + "$note$;",
                False,
                "A dollar-quoted body does not begin a top-level transaction.",
            ),
            (
                "/* outer /* nested " + index + " */ end */",
                False,
                "Nested PostgreSQL comments keep transaction-looking text outside executable SQL.",
            ),
            (
                index.replace("CREATE INDEX", "CREATE /* gap */ INDEX"),
                True,
                "Whitespace and comments preserve concurrent DDL.",
            ),
        ],
    )

    definer = "CREATE FUNCTION lookup_setting() RETURNS text LANGUAGE SQL SECURITY DEFINER SET search_path = pg_temp, private AS $$ SELECT value FROM settings $$;\n"
    add(
        "SP706",
        "definer.sql",
        "https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY",
        "SECURITY DEFINER functions need safe name resolution: pg_temp should follow trusted schemas, and protected relations should be qualified.",
        [
            definer,
            definer.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"),
            definer.replace("pg_temp, private", "'pg_temp, private'"),
            definer.replace("= pg_temp", "TO pg_temp").replace("$$", "$body$"),
            definer.replace("pg_temp, private", '"pg_temp", "private"'),
        ],
        [
            definer.replace("DEFINER", "INVOKER"),
            definer.replace("pg_temp, private", "private, pg_temp"),
            definer.replace("pg_temp, private", "''"),
            definer.replace("FROM settings", "FROM private.settings"),
            definer.replace("FROM settings", "FROM ONLY private.settings"),
            definer.replace("FROM settings", "FROM LATERAL private.get_settings()"),
            definer.replace("SELECT value FROM settings", "SELECT EXTRACT(YEAR FROM current_date)"),
            definer.replace("FROM settings", "FROM settings()"),
            definer.replace("SELECT value FROM settings", "SELECT 'FROM settings'"),
            definer.replace(
                "SELECT value FROM settings",
                "WITH settings AS (SELECT 'fixed' AS value) SELECT value FROM settings",
            ),
            definer.replace("LANGUAGE SQL", "LANGUAGE plpgsql"),
            definer.replace("= pg_temp, private", "FROM CURRENT"),
            definer.replace(
                "SELECT value FROM settings",
                "SET search_path = private; SELECT value FROM settings",
            ),
            definer.replace("pg_temp, private", '"PG_TEMP", private'),
            definer.replace("FROM settings", "FROM (SELECT 'fixed' AS value) AS settings"),
            definer.replace("SECURITY DEFINER", "SECURITY DEFINER SECURITY INVOKER"),
            definer + "ALTER FUNCTION lookup_setting() SET search_path = private, pg_temp;",
            definer + "DROP FUNCTION lookup_setting();",
        ],
        [
            (
                "/* " + definer + " */",
                False,
                "Commented function definitions do not create privileged functions.",
            ),
            (
                "SELECT $example$" + definer + "$example$;",
                False,
                "A nested dollar-quoted example is data and cannot create a privileged SQL function.",
            ),
            (
                definer.replace("pg_temp, private", "pg_temp, get_schema()"),
                False,
                "Computed or malformed path settings are unresolved.",
            ),
            (
                definer.replace("FROM settings", "FROM /* relation */ settings"),
                True,
                "A comment does not qualify the relation.",
            ),
        ],
    )
    from build_io_ownership_contracts import augment_existing_contracts

    return augment_existing_contracts(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    target = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["rules"] = [
        row for row in payload["rules"] if row["rule_id"] not in NEW_IDS | RETIRED_IDS
    ] + authored
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for path, data in (
        (target, payload),
        (ROOT / "tests/web_database_cases.json", {"schema_version": 1, "rules": authored}),
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
