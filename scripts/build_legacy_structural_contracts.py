#!/usr/bin/env python3
"""Build curated v2 contracts for legacy structural and artifact rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
OUTPUT_DIR = ROOT / "tests" / "rule-contracts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import (  # noqa: E402
    RULE_EXPLANATIONS,
    RULE_FRAMEWORK_HINTS,
    RULES,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
    scan_single_file,
)

STRUCTURAL_CASES: dict[str, dict[str, str]] = {
    "SP107": {
        "ecosystem": "python",
        "path": "cors.py",
        "positive": bytes.fromhex(
            "616c6c6f775f6f726967696e733d5b222a225d0a616c6c6f775f63726564656e7469616c733d547275650a"
        ).decode("utf-8"),
        "negative_a": bytes.fromhex(
            "616c6c6f775f6f726967696e733d5b2268747470733a2f2f6170702e696e76616c6964225d"
            "0a616c6c6f775f63726564656e7469616c733d547275650a"
        ).decode("utf-8"),
        "negative_b": bytes.fromhex(
            "616c6c6f775f6f726967696e733d5b222a225d0a616c6c6f775f63726564656e7469616c"
            "733d46616c73650a"
        ).decode("utf-8"),
        "adversarial": bytes.fromhex(
            "636f72735f6f7074696f6e73203d207b226f726967696e73223a205b222a225d2c20226372"
            "6564656e7469616c73223a20547275657d0a"
        ).decode("utf-8"),
    },
    "SP108": {
        "ecosystem": "fastapi",
        "path": "app.py",
        "positive": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/admin/users')\ndef list_users(): ...\n",
        "negative_a": "from fastapi import Depends, FastAPI\napp = FastAPI()\ndef require_admin(): ...\n@app.get('/admin/users', dependencies=[Depends(require_admin)])\ndef list_users(): ...\n",
        "negative_b": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health(): ...\n",
        "adversarial": "from fastapi import FastAPI\napp = FastAPI()\nadmin_path = '/admin/users'\n@app.get(admin_path)\ndef list_users(): ...\n",
    },
    "SP115": {
        "ecosystem": "python",
        "path": "parser.py",
        "positive": "from lxml import etree\nroot = etree.fromstring(xml_payload)\n",
        "negative_a": "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\nroot = etree.fromstring(xml_payload, parser)\n",
        "negative_b": "import xml.etree.ElementTree as etree\nroot = etree.fromstring(xml_payload)\n",
        "adversarial": "from lxml import etree as ET\nroot = ET.fromstring(xml_payload)\n",
    },
    "SP120": {
        "ecosystem": "javascript",
        "path": "legacy.js",
        "positive": "".join(
            (
                "const ser = require('node-",
                "serialize');\nconst obj = ser.",
                "unserialize(payload);\n",
            )
        ),
        "negative_a": "const obj = JSON.parse(payload);\n",
        "negative_b": "const ser = require('node-serialize');\nconst obj = ser.serialize(payload);\n",
        "adversarial": bytes.fromhex(
            "636f6e737420736572203d207265717569726528276e6f64652d27202b202773657269616c"
            "697a6527293b0a636f6e7374206f626a203d207365722e756e73657269616c697a65287061"
            "796c6f6164293b0a"
        ).decode("utf-8"),
    },
    "SP131": {
        "ecosystem": "go",
        "path": "server.go",
        "positive": 'srv := &http.Server{Addr: ":8080"}\n',
        "negative_a": 'srv := &http.Server{Addr: ":8080", ReadTimeout: 5 * time.Second}\n',
        "negative_b": 'http.ListenAndServe(":8080", handler)\n',
        "adversarial": 'config := serverConfig{Addr: ":8080"}\nsrv := &http.Server(config)\n',
    },
    "SP303": {
        "ecosystem": "python",
        "path": "jobs.py",
        "positive": "import time\nasync def run():\n    time.sleep(1)\n",
        "negative_a": "import time\ndef run():\n    time.sleep(1)\n",
        "negative_b": "import asyncio\nasync def run():\n    await asyncio.sleep(1)\n",
        "adversarial": "import time\nsleep = time.sleep\nasync def run():\n    sleep(1)\n",
    },
    "SP304": {
        "ecosystem": "python",
        "path": "client.py",
        "positive": "import requests\nresponse = requests.get('https://api.invalid')\n",
        "negative_a": "import requests\nresponse = requests.get('https://api.invalid', timeout=2)\n",
        "negative_b": "response = cache.get('health')\n",
        "adversarial": "import requests\nget = requests.get\nresponse = get('https://api.invalid')\n",
    },
    "SP305": {
        "ecosystem": "fastapi",
        "path": "app.py",
        "positive": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(limit: int = 50): ...\n",
        "negative_a": "from fastapi import FastAPI, Query\napp = FastAPI()\n@app.get('/items')\ndef items(limit: int = Query(50, ge=1, le=100)): ...\n",
        "negative_b": "def internal_batch(limit: int = 50): ...\n",
        "adversarial": "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items')\ndef items(**params):\n    limit = params.get('limit', 50)\n",
    },
    "SP307": {
        "ecosystem": "python",
        "path": "service.py",
        "positive": "for user in users:\n    profile = db.query(Profile).filter_by(user_id=user.id).first()\n",
        "negative_a": "profiles = db.query(Profile).filter(Profile.user_id.in_(user_ids)).all()\nfor profile in profiles:\n    use(profile)\n",
        "negative_b": "for user in users:\n    use(user.cached_profile)\n",
        "adversarial": "def load_profile(user):\n    return db.query(Profile).filter_by(user_id=user.id).first()\nfor user in users:\n    profile = load_profile(user)\n",
    },
    "SP316": {
        "ecosystem": "python",
        "path": "billing.py",
        "positive": "with db.transaction():\n    requests.post('https://api.invalid', timeout=5)\n",
        "negative_a": "response = requests.post('https://api.invalid', timeout=5)\nwith db.transaction():\n    save(response)\n",
        "negative_b": "with db.transaction():\n    db.execute('UPDATE jobs SET done = true')\n",
        "adversarial": "transaction = db.transaction\nwith transaction():\n    requests.post('https://api.invalid', timeout=5)\n",
    },
    "SP317": {
        "ecosystem": "python",
        "path": "api.py",
        "positive": "async def get_data():\n    return requests.get('https://api.invalid', timeout=5)\n",
        "negative_a": "def get_data():\n    return requests.get('https://api.invalid', timeout=5)\n",
        "negative_b": "async def get_data(client):\n    return await client.get('https://api.invalid')\n",
        "adversarial": "blocking_get = requests.get\nasync def get_data():\n    return blocking_get('https://api.invalid', timeout=5)\n",
    },
    "SP318": {
        "ecosystem": "python",
        "path": "client.py",
        "positive": "from tenacity import retry, wait_fixed\n@retry(wait=wait_fixed(1))\ndef call_upstream(): ...\n",
        "negative_a": "from tenacity import retry, stop_after_attempt\n@retry(stop=stop_after_attempt(3))\ndef call_upstream(): ...\n",
        "negative_b": "def call_upstream(): ...\n",
        "adversarial": "while True:\n    try:\n        call_upstream()\n        break\n    except RetryableError:\n        sleep(1)\n",
    },
    "SP401": {
        "ecosystem": "express",
        "path": "server.js",
        "positive": "const express = require('express');\nconst app = express();\napp.listen(3000);\n",
        "negative_a": "const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\napp.use(helmet());\n",
        "negative_b": "const app = createInternalApp();\napp.listen(3000);\n",
        "adversarial": "const framework = require('express');\nconst app = framework();\napp.listen(3000);\n",
    },
    "SP402": {
        "ecosystem": "express",
        "path": "server.js",
        "positive": "const app = express();\napp.post('/api/auth/login', signIn);\n",
        "negative_a": "const app = express();\nconst limiter = require('express-rate-limit');\napp.use('/api/auth/login', limiter);\napp.post('/api/auth/login', signIn);\n",
        "negative_b": "const app = express();\napp.post('/items', createItem);\n",
        "adversarial": "const app = express();\nconst authPath = '/api/auth/login';\napp.post(authPath, signIn);\n",
    },
    "SP407": {
        "ecosystem": "express",
        "path": "server.js",
        "positive": "const app = express();\napp.use(cookieParser());\napp.post('/profile', updateProfile);\n",
        "negative_a": "const app = express();\napp.use(cookieParser());\napp.use(require('csurf')({ cookie: true }));\napp.post('/profile', updateProfile);\n",
        "negative_b": "const app = express();\napp.post('/profile', updateProfile);\n",
        "adversarial": "const app = express();\nconst sessionReader = require('./session-reader');\napp.use(sessionReader());\napp.post('/profile', updateProfile);\n",
    },
    "SP408": {
        "ecosystem": "nextjs",
        "path": "next.config.js",
        "positive": "const nextConfig = { reactStrictMode: true };\nmodule.exports = nextConfig;\n",
        "negative_a": "const nextConfig = { async headers() { return [{ key: 'Content-Security-Policy', value: \"default-src 'self'\" }]; } };\nmodule.exports = nextConfig;\n",
        "negative_b": "module.exports = { async headers() { return [{ headers: [{ key: 'Content-Security-Policy', value: 'default-src none' }] }]; } };\n",
        "adversarial": "const config = { reactStrictMode: true };\nexport default config;\n",
        "adversarial_path": "next-config-source.ts",
    },
    "SP591": {
        "ecosystem": "nextjs",
        "path": "component.tsx",
        "positive": "'use client';\nimport { PrismaClient } from '@prisma/client';\nexport function Page() { return null; }\n",
        "negative_a": "import { PrismaClient } from '@prisma/client';\nexport async function Page() { return null; }\n",
        "negative_b": "'use client';\nimport { api } from './browser-api';\nexport function Page() { return null; }\n",
        "adversarial": "const directive = 'use ' + 'client';\nimport { PrismaClient } from '@prisma/client';\nexport function Page() { return null; }\n",
    },
    "SP595": {
        "ecosystem": "nextjs",
        "path": "actions.ts",
        "positive": "'use server';\nexport async function updateItem() {\n  await prisma.user.update({ where: { id: '1' } });\n}\n",
        "negative_a": "'use server';\nexport async function updateItem() {\n  await prisma.user.update({ where: { id: '1' } });\n  revalidatePath('/users');\n}\n",
        "negative_b": "export async function readItem() { return prisma.user.findMany(); }\n",
        "adversarial": "'use server';\nconst mutate = prisma.user['up' + 'date'];\nexport async function updateItem() { await mutate({ where: { id: '1' } }); }\n",
    },
    "SP596": {
        "ecosystem": "react",
        "path": "page.tsx",
        "positive": "export default function Page() {\n  const [count] = useState(0);\n  return <div>{count}</div>;\n}\n",
        "negative_a": "'use client';\nexport default function Page() {\n  const [count] = useState(0);\n  return <div>{count}</div>;\n}\n",
        "negative_b": "export default function Page() { return <div>static</div>; }\n",
        "adversarial": "const stateHook = useState;\nexport default function Page() { const [count] = stateHook(0); return <div>{count}</div>; }\n",
    },
    "SP597": {
        "ecosystem": "nextjs",
        "path": "page.tsx",
        "positive": "export default async function Page() {\n  const a = await fetch('https://a.invalid');\n  const b = await fetch('https://b.invalid');\n  return null;\n}\n",
        "negative_a": "export default async function Page() {\n  const [a, b] = await Promise.all([fetch('https://a.invalid'), fetch('https://b.invalid')]);\n  return null;\n}\n",
        "negative_b": "export default async function Page() {\n  const a = await fetch('https://a.invalid');\n  return null;\n}\n",
        "adversarial": "const load = fetch;\nexport default async function Page() { const a = await load('https://a.invalid'); const b = await load('https://b.invalid'); return null; }\n",
    },
    "SP598": {
        "ecosystem": "nextjs",
        "path": "route.ts",
        "positive": "export async function POST(request: Request) {\n  const session = cookies().get('session');\n  return Response.json({ ok: true });\n}\n",
        "negative_a": "export async function POST(request: Request) {\n  verifyOrigin(request.headers.get('origin'));\n  const session = cookies().get('session');\n  return Response.json({ ok: true });\n}\n",
        "negative_b": "export async function GET() { return Response.json({ ok: true }); }\n",
        "adversarial": "import { readSession } from './session-reader';\nexport async function POST() { const session = readSession(); return Response.json({ ok: true }); }\n",
    },
    "SP600": {
        "ecosystem": "nextjs",
        "path": "actions.ts",
        "positive": "'use server';\nexport async function deleteAccount(userId: string) {\n  await prisma.user.delete({ where: { id: userId } });\n}\n",
        "negative_a": "'use server';\nexport async function deleteAccount() {\n  const userId = await requireAuthenticatedUserId();\n  await prisma.user.delete({ where: { id: userId } });\n}\n",
        "negative_b": "export async function listAccounts() { return prisma.user.findMany(); }\n",
        "adversarial": "'use server';\nimport { deleteUser } from './mutations';\nexport async function deleteAccount(userId: string) { await deleteUser(userId); }\n",
    },
    "SP609": {
        "ecosystem": "kubernetes",
        "path": "deployment.yaml",
        "positive": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx\n",
        "negative_a": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx\n        readinessProbe:\n          httpGet:\n            path: /health\n            port: 80\n",
        "negative_b": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n",
        "adversarial": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      workloadContainers:\n      - name: web\n        image: nginx\n",
    },
    "SP612": {
        "ecosystem": "graphql",
        "path": "graphql.ts",
        "positive": "const server = new ApolloServer({ typeDefs, resolvers });\n",
        "negative_a": "const server = new ApolloServer({ typeDefs, resolvers, validationRules: [depthLimit(10)] });\n",
        "negative_b": "const schema = buildSchema(typeDefs);\n",
        "adversarial": "import { createGraphServer } from './server-factory';\nconst server = createGraphServer({ typeDefs, resolvers });\n",
    },
    "SP631": {
        "ecosystem": "nextjs",
        "path": "route.ts",
        "positive": "export const runtime = 'edge';\nimport fs from 'node:fs';\n",
        "negative_a": "export const runtime = 'nodejs';\nimport fs from 'node:fs';\n",
        "negative_b": "export const runtime = 'edge';\nexport async function GET() { return new Response('ok'); }\n",
        "adversarial": "export const runtime = ['ed', 'ge'].join('');\nimport fs from 'node:fs';\n",
    },
}


def encoded_text(source: str) -> dict[str, str]:
    """Keep scanner-positive fixture text executable without self-triggering repository scans."""

    return {"source_hex": source.encode("utf-8").hex()}


def rule_number(rule_id: str) -> int:
    return int(rule_id.removeprefix("SP"))


def structural_findings(rule_id: str, path_value: str, source: str) -> list[Any]:
    path = Path(path_value)
    findings = find_regex_issues(
        path,
        path_value,
        source,
        detected_frameworks=RULE_FRAMEWORK_HINTS.get(rule_id, frozenset()),
    )
    if path.suffix.lower() == ".py":
        findings.extend(find_python_ast_issues(path_value, source))
    active, _ = deduplicate_and_suppress_findings(findings)
    return [finding for finding in active if finding.rule_id == rule_id]


def structural_case_path(rule_id: str, base: dict[str, str], case_id: str) -> str:
    case_kind = case_id.split("-", 1)[0]
    filename = base.get(f"{case_kind}_path", base["path"])
    return f"contract-fixtures/{base['ecosystem']}/{rule_id.lower()}-{case_id}/{filename}"


def positive_case(rule: Any, base: dict[str, str], case_id: str, source: str) -> dict[str, Any]:
    path = structural_case_path(rule.rule_id, base, case_id)
    matches = structural_findings(rule.rule_id, path, source)
    if len(matches) != 1:
        raise ValueError(f"{rule.rule_id}:{case_id} expected one finding, got {len(matches)}")
    finding = matches[0]
    return {
        "path": path,
        **encoded_text(source),
        "expected_line": finding.line,
        "expected_confidence": finding.confidence,
        "expected_detection": finding.detection,
        "expected_proof_level": finding.proof_level,
        "expected_fingerprint": finding.fingerprint,
    }


def structural_entry(rule: Any, base: dict[str, str]) -> dict[str, Any]:
    positive_sources = [base["positive"]]
    if rule.severity in {"critical", "high"}:
        positive_sources.append("\n" + base["positive"])
    positive = [
        positive_case(rule, base, f"positive-{'ab'[index]}", source)
        for index, source in enumerate(positive_sources)
    ]
    negative = []
    for case_id in ("negative_a", "negative_b"):
        source = base[case_id]
        path = structural_case_path(rule.rule_id, base, case_id)
        if structural_findings(rule.rule_id, path, source):
            raise ValueError(f"{rule.rule_id}:{case_id} unexpectedly triggers")
        negative.append({"path": path, **encoded_text(source)})
    adversarial_source = base["adversarial"]
    adversarial_path = structural_case_path(rule.rule_id, base, "adversarial-a")
    if structural_findings(rule.rule_id, adversarial_path, adversarial_source):
        raise ValueError(f"{rule.rule_id}:adversarial unexpectedly triggers")
    return {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "category": rule.category,
        "expected_severity": rule.severity,
        "expected_confidence": rule.confidence,
        "cwe": rule.cwe,
        "frameworks": sorted(RULE_FRAMEWORK_HINTS.get(rule.rule_id, frozenset())),
        "false_positive_analysis": RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        "cases": {
            "positive": positive,
            "negative": negative,
            "adversarial": [
                {
                    "path": adversarial_path,
                    **encoded_text(adversarial_source),
                    "expected": False,
                    "rationale": (
                        "The source preserves the risky operation through an alias, computed value, "
                        "or indirect boundary that the local structural engine intentionally does not "
                        "resolve; the case records a known evasion without overstating proof."
                    ),
                }
            ],
        },
    }


def artifact_entry(rule: Any) -> dict[str, Any]:
    positive_specs = (
        (
            "positive-a",
            "contract-fixtures/artifact/sp314-positive-a.db",
            b"SQLite format 3\x00" + b"\x00" * 32,
        ),
        ("positive-b", "contract-fixtures/artifact/sp314-positive-b.sqlite", b""),
    )
    positive = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for case_id, relative_path, content in positive_specs:
            local = root / f"{case_id}{Path(relative_path).suffix}"
            local.write_bytes(content)
            matches = [
                finding
                for finding in scan_single_file(local, relative_path, 1_000_000, frozenset())
                if finding.rule_id == rule.rule_id
            ]
            if len(matches) != 1:
                raise ValueError(f"SP314:{case_id} expected one finding, got {len(matches)}")
            finding = matches[0]
            positive.append(
                {
                    "path": relative_path,
                    "content_hex": content.hex(),
                    "expected_line": finding.line,
                    "expected_confidence": finding.confidence,
                    "expected_detection": finding.detection,
                    "expected_proof_level": finding.proof_level,
                    "expected_fingerprint": finding.fingerprint,
                }
            )
    return {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "category": rule.category,
        "expected_severity": rule.severity,
        "expected_confidence": rule.confidence,
        "cwe": rule.cwe,
        "frameworks": [],
        "false_positive_analysis": RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        "cases": {
            "positive": positive,
            "negative": [
                {
                    "path": "contract-fixtures/artifact/sp314-negative-a.db",
                    "content_hex": b"not a database".hex(),
                },
                {
                    "path": "contract-fixtures/artifact/sp314-negative-b.bin",
                    "content_hex": (b"SQLite format 3\x00" + b"\x00" * 8).hex(),
                },
            ],
            "adversarial": [
                {
                    "path": "contract-fixtures/artifact/sp314-adversarial-a.db",
                    "content_hex": (b"XSQLite format 3\x00" + b"\x00" * 8).hex(),
                    "expected": False,
                    "rationale": (
                        "A database signature shifted by one byte is not recognized by the current "
                        "artifact header check; the fixture records that binary-container evasion "
                        "without claiming content inspection beyond the first bytes."
                    ),
                }
            ],
        },
    }


def build_payloads() -> dict[str, str]:
    rules = {rule.rule_id: rule for rule in RULES}
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule_id, base in sorted(STRUCTURAL_CASES.items(), key=lambda item: rule_number(item[0])):
        grouped[base["ecosystem"]].append(structural_entry(rules[rule_id], base))
    rendered: dict[str, str] = {}
    rows = []
    for ecosystem, entries in sorted(grouped.items()):
        filename = f"structural-{ecosystem}.v2.json"
        payload = {
            "schema_version": 2,
            "quality_contract_version": 2,
            "engine": "structural",
            "ecosystem": ecosystem,
            "rules": entries,
        }
        content = json.dumps(payload, indent=2) + "\n"
        rendered[filename] = content
        rows.append(
            {
                "path": filename,
                "engine": "structural",
                "ecosystem": ecosystem,
                "rule_count": len(entries),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )
    artifact_payload = {
        "schema_version": 2,
        "quality_contract_version": 2,
        "engine": "artifact",
        "ecosystem": "sqlite",
        "rules": [artifact_entry(rules["SP314"])],
    }
    artifact_content = json.dumps(artifact_payload, indent=2) + "\n"
    artifact_filename = "artifact-sqlite.v2.json"
    rendered[artifact_filename] = artifact_content
    rows.append(
        {
            "path": artifact_filename,
            "engine": "artifact",
            "ecosystem": "sqlite",
            "rule_count": 1,
            "sha256": hashlib.sha256(artifact_content.encode("utf-8")).hexdigest(),
        }
    )
    index = {
        "schema_version": 1,
        "quality_contract_version": 2,
        "scope": "Legacy structural and artifact contracts split by engine and ecosystem",
        "manifests": rows,
    }
    rendered["structural-index.json"] = json.dumps(index, indent=2) + "\n"
    return rendered


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="check generated files without writing"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rendered = build_payloads()
    expected_paths = {OUTPUT_DIR / filename for filename in rendered}
    managed_paths = (
        {
            *OUTPUT_DIR.glob("structural-*.v2.json"),
            *OUTPUT_DIR.glob("artifact-*.v2.json"),
            *(path for path in (OUTPUT_DIR / "structural-index.json",) if path.is_file()),
        }
        if OUTPUT_DIR.is_dir()
        else set()
    )
    stale = sorted(
        path
        for path in expected_paths
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered[path.name]
    )
    unexpected = sorted(managed_paths - expected_paths)
    if args.check:
        if stale or unexpected:
            for path in stale:
                print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
            for path in unexpected:
                print(f"unexpected: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(f"{len(expected_paths)} legacy structural contract files are current")
        return 0
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in unexpected:
        path.unlink()
    for filename, content in rendered.items():
        (OUTPUT_DIR / filename).write_bytes(content.encode("utf-8"))
    print(f"updated {len(expected_paths)} files in {OUTPUT_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
