"""Original value/default/trust cases; maintainer generation only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402

NEW_IDS = {"SP699", "SP700", "SP701"}


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
                        "claim": "Maps the local validity/trust/resource boundary, not proof of deployed exposure or exploitation.",
                    },
                ],
                "positive": [{"path": path, "source": value} for value in positive],
                "negative": [{"path": path, "source": value} for value in negative],
                "adversarial": [
                    {"path": path, "source": value, "expected": expected, "rationale": why}
                    for value, expected, why in adversarial
                ],
            }
        )

    zero = "fn build() { let value = unsafe { std::num::NonZeroU32::new_unchecked(0) }; }\n"
    add(
        "SP699",
        "value.rs",
        "https://doc.rust-lang.org/std/num/struct.NonZero.html#method.new_unchecked",
        "The unsafe NonZero constructor requires a nonzero value; zero violates Rust's validity contract.",
        [
            zero,
            zero.replace("std::", "core::").replace("NonZeroU32", "NonZeroI64"),
            zero.replace("(0)", "(0u32)"),
            zero.replace("NonZeroU32", "NonZeroUsize").replace("(0)", "(0_usize)"),
        ],
        [
            zero.replace("(0)", "(1)"),
            zero.replace("new_unchecked", "new"),
            zero.replace("(0)", "(value)"),
            zero.replace("std::", "custom::std::"),
            zero.replace("NonZeroU32", "CustomNumber"),
            zero.replace("(0)", "(0.0)"),
            zero.replace("(0)", "(0u64)"),
        ],
        [
            (
                "/* " + zero + " */",
                False,
                "A comment cannot construct an unsafe integer value or establish reachability.",
            ),
            (
                "use custom::std;\n" + zero,
                False,
                "An imported standard-looking module name has unresolved identity, so its constructors are not presumed native.",
            ),
            (
                "use custom::{core};\n" + zero.replace("std::", "core::"),
                False,
                "A grouped import can bind core to a custom module rather than the Rust standard library.",
            ),
            (
                "mod r#std {}\n" + zero,
                False,
                "A raw identifier declaration can shadow a standard module spelling and must not establish native identity.",
            ),
            (
                "const EXAMPLE: &str = stringify!(" + zero + ");",
                False,
                "stringify consumes token data; a constructor-looking token sequence is not an evaluated call.",
            ),
        ],
    )

    timer = "import {setInterval} from 'node:timers';\nsetInterval(tick, 2147483648);\n"
    add(
        "SP700",
        "timer.ts",
        "https://nodejs.org/api/timers.html",
        "Node coerces delays greater than 2147483647 milliseconds to one millisecond; callback and promise APIs use different delay positions.",
        [
            timer,
            timer.replace("setInterval", "setTimeout"),
            timer.replace("{setInterval}", "{setInterval as repeat}").replace(
                "\nsetInterval", "\nrepeat"
            ),
            "import {setTimeout as wait} from 'node:timers/promises';\nawait wait(3000000000, 'value');",
            timer.replace("2147483648", "30 * 24 * 60 * 60 * 1000"),
            "const timers = require('node:timers');\ntimers.setTimeout(tick, 3000000000);",
        ],
        [
            timer.replace("2147483648", "2147483647"),
            timer.replace("2147483648", "0"),
            timer.replace("2147483648", "-1"),
            timer.replace("2147483648", "delay"),
            timer.replace("2147483648", "1000, 2147483648"),
            timer.replace("node:timers", "./timers"),
            timer.replace("import {", "import type {"),
            "import {setTimeout as wait} from 'node:timers/promises';\nawait wait(1000, 2147483648);",
            timer.replace("2147483648", "2147483648n"),
            timer.replace("2147483648", "0 * 30 * 24 * 60 * 60 * 1000"),
            timer.replace("tick,", "null,"),
            timer.replace("tick,", "0,"),
        ],
        [
            (
                "/* " + timer + " */",
                False,
                "Timer-looking comment text does not create a runtime schedule.",
            ),
            (
                timer.replace("\nsetInterval", "\nfunction run(setInterval: Custom) { setInterval")
                + "}",
                False,
                "A local parameter shadows the imported timer and invalidates its coercion semantics.",
            ),
            (
                timer.replace("2147483648", "9" * 5000),
                False,
                "Oversized numeric tokens remain unresolved without unbounded integer conversion or evaluation.",
            ),
            (
                timer.replace("2147483648", "9007199254740991 * 9007199254740991"),
                False,
                "Products outside exact JavaScript integer range are not evaluated into affirmative evidence.",
            ),
        ],
    )

    pool = "from sqlalchemy.pool import QueuePool\npool = QueuePool(connect, pool_size=0)\n"
    add(
        "SP701",
        "pool.py",
        "https://docs.sqlalchemy.org/en/20/core/pooling.html#sqlalchemy.pool.QueuePool",
        "QueuePool defaults are finite; pool_size=0 or max_overflow=-1 explicitly removes a capacity bound.",
        [
            pool,
            pool.replace("pool_size=0", "max_overflow=-1"),
            pool.replace("import QueuePool", "import QueuePool as Pool").replace(
                "= QueuePool(", "= Pool("
            ),
            "import sqlalchemy.pool as pools\npool = pools.QueuePool(connect, 5, -1)\n",
            pool.replace("connect, pool_size=0", "creator=connect, pool_size=0, max_overflow=10"),
        ],
        [
            pool.replace(", pool_size=0", ""),
            pool.replace("pool_size=0", "pool_size=5, max_overflow=10"),
            pool.replace("pool_size=0", "pool_size=1, max_overflow=0"),
            pool.replace("pool_size=0", "pool_size=limit"),
            pool.replace("pool_size=0", "pool_size=5, max_overflow=-2"),
            pool.replace("pool_size=0", "pool_size=False"),
            pool.replace("pool_size=0", "pool_size=-1"),
            pool.replace("sqlalchemy.pool", "custom.pool"),
            pool.replace("QueuePool", "NullPool"),
            pool.replace("pool_size=0", "**options"),
            pool.replace("connect, pool_size=0", "connect, 5, pool_size=0"),
            "from sqlalchemy import create_engine\nengine = create_engine(url)\n",
        ],
        [
            (
                "# " + pool.replace("\n", "\n# "),
                False,
                "A pool configuration in comments cannot instantiate a connection pool.",
            ),
            (
                pool.replace("pool = QueuePool", "QueuePool = custom\npool = QueuePool"),
                False,
                "A reassigned constructor is no longer the import-bound QueuePool.",
            ),
            (
                pool.replace("pool = QueuePool", "def build(QueuePool):\n    return QueuePool"),
                False,
                "A function parameter masks the imported class; its settings need separate review.",
            ),
        ],
    )

    reference = "unsafe fn invalid() { let value = std::mem::uninitialized::<&u32>(); }\n"
    add(
        "SP673",
        "reference.rs",
        "https://doc.rust-lang.org/std/mem/fn.uninitialized.html",
        "Constructing an uninitialized reference violates its initialized-address invariant even if the resulting reference is not used.",
        [
            reference,
            reference.replace("std::", "core::").replace("&u32", "&mut u8"),
            reference.replace("&u32", "&'static str"),
        ],
        [
            reference.replace("uninitialized::<&u32>()", "MaybeUninit::<&u32>::uninit()"),
            reference.replace("std::", "custom::std::"),
            reference.replace("&u32", "u32"),
            "use custom::std;\n" + reference,
            "use crate::{core};\n" + reference.replace("std::", "core::"),
        ],
        [
            (
                "let example = stringify!(" + reference + ");",
                False,
                "Token stringification is data, not reference construction; no macro expansion is executed by the scanner.",
            ),
            (
                'let example = r#"' + reference + '"#;',
                False,
                "A raw Rust string must not be interpreted as a native memory operation.",
            ),
        ],
    )

    ssl = "using System.Net.Security;\nasync System.Threading.Tasks.Task Connect(SslStream tls) { await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host, RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true }); }\n"
    add(
        "SP104",
        "tls.cs",
        "https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions.remotecertificatevalidationcallback",
        "The callback decides whether to accept the peer certificate; an unconditional true callback ignores reported validation errors.",
        [
            ssl,
            ssl.replace("(sender, cert, chain, errors) => true", "static (_, _, _, _) => true"),
            ssl.replace("=> true", "=> { return true; }"),
        ],
        [
            ssl.replace("=> true", "=> false"),
            ssl.replace("=> true", "=> errors == SslPolicyErrors.None"),
            ssl.replace("(sender, cert, chain, errors) => true", "validatePeer"),
            ssl.replace("using System.Net.Security;", "using Custom.Net.Security;"),
            ssl.replace("AuthenticateAsClientAsync", "AuthenticateAsServerAsync"),
            ssl.replace("new SslClientAuthenticationOptions", "new CustomOptions"),
            ssl.replace("(sender, cert, chain, errors)", "(same, same, same, same)"),
            ssl.replace(
                "RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true",
                "RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true, RemoteCertificateValidationCallback = validatePeer",
            ),
        ],
        [
            (
                "/* " + ssl + " */",
                False,
                "A commented authentication call must not establish effective TLS configuration.",
            ),
            (
                "class SslStream {}\n" + ssl,
                False,
                "A local type makes the standard SslStream binding ambiguous and must stay unresolved.",
            ),
            (
                ssl.replace("await tls.", "tls = custom; await tls."),
                False,
                "Reassignment invalidates the single-use typed receiver evidence.",
            ),
        ],
    )
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    authored = records()
    path = ROOT / "tests/rule_cases_v2.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in NEW_IDS] + [
        row for row in authored if row["rule_id"] in NEW_IDS
    ]
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    for target, data in (
        (path, payload),
        (ROOT / "tests/value_cases.json", {"schema_version": 1, "rules": authored}),
    ):
        rendered = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
        if args.check:
            if target.read_text(encoding="utf-8") != rendered:
                return 1
        else:
            target.write_bytes(rendered.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
