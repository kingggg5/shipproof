"""Generate original JS/TypeScript configuration contracts, not scanner runtime data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/rule_cases_v2.json"
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS  # noqa: E402


def records() -> list[dict]:
    # These are authored API/configuration cases, not synthesized keyword witnesses.
    cohorts = [
        (
            "SP674",
            "next.config.ts",
            "918",
            "https://nextjs.org/docs/app/api-reference/components/image#dangerouslyallowlocalip",
            "Next.js blocks private IP image optimization by default; this explicit switch permits it and requires review of network exposure.",
            [
                "export default { images: { dangerouslyAllowLocalIP: true } };\n",
                "import type { NextConfig } from 'next';\nconst config: NextConfig = {\n images: { dangerouslyAllowLocalIP: true }\n};\nexport default config;\n",
                "const config = { images: { 'dangerouslyAllowLocalIP': true } };\nmodule.exports = config;\n",
            ],
            [
                "export default { images: { dangerouslyAllowLocalIP: false } };\n",
                "export default { images: { remotePatterns: [{ hostname: 'images.example.com' }] } };\n",
                "export default { images: { dangerouslyAllowLocalIP: true, dangerouslyAllowLocalIP: false } };\n",
                "export default { images: { dangerouslyAllowLocalIP: true, ...reviewedImages } };\n",
                "const unused = { images: { dangerouslyAllowLocalIP: true } };\nexport default {};\n",
                "const config = { images: { dangerouslyAllowLocalIP: true } };\nconfig.images.dangerouslyAllowLocalIP = false;\nexport default config;\n",
                "module.exports = { images: { dangerouslyAllowLocalIP: true } };\nmodule.exports = {};\n",
                "const module = localModule;\nmodule.exports = { images: { dangerouslyAllowLocalIP: true } };\n",
                "export default { images: { dangerouslyAllowLocalIP: true } } && safeConfig;\n",
                "const config = { images: { dangerouslyAllowLocalIP: true } } && safeConfig;\nexport default config;\n",
            ],
        ),
        (
            "SP675",
            "auth.ts",
            "613",
            "https://github.com/auth0/node-jsonwebtoken/blob/master/verify.js",
            "jsonwebtoken verify options can explicitly skip expiration or not-before checks; signature verification is a separate protection.",
            [
                "import jwt from 'jsonwebtoken';\nexport const claims = jwt.verify(token, publicKey, { ignoreExpiration: true });\n",
                "import { verify as check } from 'jsonwebtoken';\ncheck(token, key, {\n ignoreNotBefore: true, algorithms: ['RS256']\n}, callback);\n",
                "const jwt = require('jsonwebtoken');\njwt.verify(token, key, { ignoreExpiration: false, ignoreNotBefore: true });\n",
            ],
            [
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { algorithms: ['RS256'], clockTolerance: 5 });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { ignoreExpiration: false, ignoreNotBefore: false });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { ignoreExpiration: true, ignoreExpiration: false });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { ignoreExpiration: true, ...strictOptions });\n",
                "import jwt from 'jsonwebtoken';\njwt.decode(token, { ignoreExpiration: true });\n",
                "import jwt from './local-token-policy';\njwt.verify(token, key, { ignoreExpiration: true });\n",
                "import jwt from 'jsonwebtoken';\nfunction validate(jwt: CustomTokens): unknown { return jwt.verify(token, key, { ignoreExpiration: true }); }\n",
                "import type { verify } from 'jsonwebtoken';\nconst options = { ignoreExpiration: true };\n",
            ],
        ),
        (
            "SP676",
            "verify.ts",
            "347",
            "https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback",
            "jsonwebtoken documents allowInvalidAsymmetricKeyTypes as a backwards-compatibility switch that should be avoided, not a general signature bypass.",
            [
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { allowInvalidAsymmetricKeyTypes: true });\n",
                "import { verify as validate } from 'jsonwebtoken';\nvalidate(token, key, {\n algorithms: ['RS256'], allowInvalidAsymmetricKeyTypes: true\n});\n",
                "const { verify: validate } = require('jsonwebtoken');\nvalidate(token, key, { 'allowInvalidAsymmetricKeyTypes': true }, callback);\n",
            ],
            [
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { algorithms: ['RS256'] });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { allowInvalidAsymmetricKeyTypes: false });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { allowInvalidAsymmetricKeyTypes: true, allowInvalidAsymmetricKeyTypes: false });\n",
                "import jwt from 'jsonwebtoken';\njwt.verify(token, key, { allowInvalidAsymmetricKeyTypes: true, ...strictOptions });\n",
                "import { verify } from './signature-policy';\nverify(token, key, { allowInvalidAsymmetricKeyTypes: true });\n",
                "import type { verify } from 'jsonwebtoken';\nconst options = { allowInvalidAsymmetricKeyTypes: true };\n",
                "import { verify } from 'jsonwebtoken';\nfunction run(verify: TokenVerifier): unknown { return verify(token, key, { allowInvalidAsymmetricKeyTypes: true }); }\n",
            ],
        ),
        (
            "SP677",
            "encryption.ts",
            "326",
            "https://nodejs.org/api/crypto.html#cryptocreatecipherivalgorithm-key-iv-options",
            "Node crypto expresses GCM authTagLength in bytes and defaults to 16; the signature selects accepted short lengths of 4 or 8 bytes.",
            [
                "import { createCipheriv } from 'node:crypto';\nconst cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 4 });\n",
                "import * as crypto from 'crypto';\ncrypto.createDecipheriv('aes-128-gcm', key, nonce, {\n authTagLength: 8\n});\n",
                "const { createCipheriv: encrypt } = require('node:crypto');\nencrypt('aes-192-gcm', key, nonce, { 'authTagLength': 8 });\n",
            ],
            [
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-gcm', key, nonce);\n",
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });\n",
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-gcm', key, nonce, { authTagLength: 12 });\n",
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-ccm', key, nonce, { authTagLength: 8 });\n",
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-gcm', key, nonce, { authTagLength: 7 });\n",
                "import { createCipheriv } from 'node:crypto';\ncreateCipheriv('aes-256-gcm', key, nonce, { authTagLength: 4, authTagLength: 16 });\n",
                "import { createCipheriv } from './hardware-crypto';\ncreateCipheriv('aes-256-gcm', key, nonce, { authTagLength: 4 });\n",
                "import type { createCipheriv } from 'node:crypto';\nconst options = { authTagLength: 4 };\n",
            ],
        ),
        (
            "SP678",
            "buffer.ts",
            "908",
            "https://nodejs.org/api/buffer.html#what-makes-bufferallocunsafe-and-bufferallocunsafeslow-unsafe",
            "Node unsafe Buffer allocation need not initialize memory; reading it before a complete overwrite can expose old bytes, unlike Buffer.alloc.",
            [
                "import { Buffer } from 'node:buffer';\nexport const text = Buffer.allocUnsafe(64).toString('hex');\n",
                "import { Buffer as Bytes } from 'buffer';\nconst text = Bytes.allocUnsafeSlow(128)\n .toString('base64');\n",
                "const { Buffer } = require('node:buffer');\nconst text = Buffer.allocUnsafe(32).toString();\n",
            ],
            [
                "import { Buffer } from 'node:buffer';\nconst text = Buffer.alloc(64).toString('hex');\n",
                "import { Buffer } from 'node:buffer';\nconst text = Buffer.allocUnsafe(64).fill(0).toString('hex');\n",
                "import { Buffer } from 'node:buffer';\nconst bytes = Buffer.allocUnsafe(32);\nbytes.fill(0);\nconst text = bytes.toString();\n",
                "import { Buffer } from 'node:buffer';\nconst text = Buffer.allocUnsafe(0).toString();\n",
                "import { Buffer } from 'node:buffer';\nconst text = Buffer.allocUnsafe(64).toString('hex', 0, 0);\n",
                "import { Buffer } from './safe-buffer';\nconst text = Buffer.allocUnsafe(64).toString();\n",
                "import { Buffer } from 'node:buffer';\nfunction read(Buffer: SafeBuffer): string { return Buffer.allocUnsafe(64).toString(); }\n",
                "const text = Buffer.allocUnsafe(64).toString();\n",
            ],
        ),
        (
            "SP679",
            "http.ts",
            "444",
            "https://nodejs.org/api/http.html#httpcreateserveroptions-requestlistener",
            "Node HTTP parser leniency is false by default; insecureHTTPParser true is an explicit compatibility opt-out with intermediary parsing risk.",
            [
                "import { createServer } from 'node:http';\ncreateServer({ insecureHTTPParser: true }, handler);\n",
                "import * as https from 'node:https';\nhttps.request(endpoint, {\n insecureHTTPParser: true\n}, callback);\n",
                "const { get: fetchLegacy } = require('http');\nfetchLegacy({ host: host, 'insecureHTTPParser': true }, callback);\n",
            ],
            [
                "import { createServer } from 'node:http';\ncreateServer(handler);\n",
                "import { createServer } from 'node:http';\ncreateServer({ insecureHTTPParser: false }, handler);\n",
                "import { request } from 'node:https';\nrequest(endpoint, { insecureHTTPParser: true, insecureHTTPParser: false });\n",
                "import { request } from 'node:https';\nrequest(endpoint, { insecureHTTPParser: true, ...strictOptions });\n",
                "import { request } from './request-policy';\nrequest(endpoint, { insecureHTTPParser: true });\n",
                "import type { request } from 'node:http';\nconst options = { insecureHTTPParser: true };\n",
                "import { request } from 'node:http';\nfunction run(request: Transport): void { request(endpoint, { insecureHTTPParser: true }); }\n",
                "import * as http from 'node:http';\nconst options = { insecureHTTPParser: true };\nhttp.createServer(handler);\n",
            ],
        ),
        (
            "SP680",
            "desktop.ts",
            "693",
            "https://www.electronjs.org/docs/latest/tutorial/security/#6-do-not-disable-websecurity",
            "Electron recommends retaining webSecurity because disabling it removes renderer same-origin protections; loaded content determines practical exposure.",
            [
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { webSecurity: false } });\n",
                "import * as electron from 'electron';\nnew electron.BrowserWindow({\n webPreferences: { 'webSecurity': false }\n});\n",
                "const { BrowserWindow: Window } = require('electron');\nnew Window({ width: 800, webPreferences: { webSecurity: false } });\n",
            ],
            [
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { webSecurity: true } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ width: 800 });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { webSecurity: false, webSecurity: true } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { webSecurity: false, ...strictPreferences } });\n",
                "import { BrowserWindow } from './window-factory';\nnew BrowserWindow({ webPreferences: { webSecurity: false } });\n",
                "import type { BrowserWindow } from 'electron';\nconst prefs = { webSecurity: false };\n",
                "import { BrowserWindow } from 'electron';\nfunction open(BrowserWindow: SafeWindow): unknown { return new BrowserWindow({ webPreferences: { webSecurity: false } }); }\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webSecurity: false });\n",
            ],
        ),
        (
            "SP681",
            "window.ts",
            "749",
            "https://www.electronjs.org/docs/latest/tutorial/security/#2-do-not-enable-nodejs-integration-for-remote-content",
            "Electron warns against renderer Node integration for untrusted content and recommends context isolation and sandbox containment.",
            [
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n",
                "import { BrowserWindow as Window } from 'electron';\nnew Window({\n webPreferences: { contextIsolation: false, nodeIntegration: true, sandbox: false }\n});\n",
                "const electron = require('electron');\nnew electron.BrowserWindow({ webPreferences: { 'nodeIntegration': true, 'contextIsolation': false } });\n",
            ],
            [
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: true } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, sandbox: true } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, nodeIntegration: false } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false, ...securePreferences } });\n",
                "import { BrowserWindow } from './safe-window';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n",
                "import { app, BrowserWindow } from 'electron';\napp.enableSandbox();\nnew BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } });\n",
                "import { BrowserWindow } from 'electron';\nnew BrowserWindow({ webPreferences: { nodeIntegration: true } });\n",
            ],
        ),
        (
            "SP682",
            "render.ts",
            "693",
            "https://pptr.dev/troubleshooting#setting-up-chrome-linux-sandbox",
            "Puppeteer discourages Chrome --no-sandbox and recommends configuring sandbox containment; equivalent external isolation needs separate review.",
            [
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ args: ['--no-sandbox'] });\n",
                "import { launch as start } from 'puppeteer-core';\nstart({\n browser: 'chrome', args: ['--headless', '--no-sandbox']\n});\n",
                "const browser = require('puppeteer');\nbrowser.launch({ args: ['--no-sandbox'], headless: true });\n",
            ],
            [
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ headless: true });\n",
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ args: ['--disable-dev-shm-usage'] });\n",
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ args: ['--no-sandbox'], args: [] });\n",
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ args: ['--no-sandbox'], ...secureLaunch });\n",
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ browser: 'firefox', args: ['--no-sandbox'] });\n",
                "import { launch } from './isolated-browser';\nlaunch({ args: ['--no-sandbox'] });\n",
                "import puppeteer from 'puppeteer';\nfunction render(puppeteer: LocalBrowser): unknown { return puppeteer.launch({ args: ['--no-sandbox'] }); }\n",
                "import puppeteer from 'puppeteer';\nawait puppeteer.launch({ args: [...approvedArgs, '--no-sandbox'] });\n",
            ],
        ),
    ]
    result = []
    for rule_id, path, cwe, url, claim, positive, negative in cohorts:
        source = positive[0]
        adversarial = [
            {
                "path": path,
                "source": "/*\n" + source + "*/\nexport {};\n",
                "expected": False,
                "rationale": "A complete example inside a block comment is not an import or executable configuration and must remain silent.",
            },
            {
                "path": path,
                "source": "const documentation = " + json.dumps(source) + ";\n",
                "expected": False,
                "rationale": "A quoted example containing imports and unsafe settings is data; source-like string content must not establish API identity.",
            },
            {
                "path": path,
                "source": source.replace("true", "/* reviewed boundary */ true")
                if "true" in source
                else (
                    source.replace("false", "/* explicit value */ false")
                    if "false" in source
                    else source.replace("(", " /* split call */ (\n", 1)
                ),
                "expected": True,
                "rationale": "Comments and whitespace between real tokens must not hide an explicit unsafe setting or change imported API identity.",
            },
        ]
        if rule_id == "SP674":
            negative.append(positive[0].replace("export default", "const notes ="))
        sources = [
            {"url": url, "claim": claim},
            {
                "url": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
                "claim": f"CWE-{cwe} supplies the risk taxonomy only; this bounded signature does not establish exploitability, remote reachability or runtime deployment.",
            },
        ]
        if rule_id == "SP677":
            sources.append(
                {
                    "url": "https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd",
                    "claim": "The 2026 NIST pre-draft announcement proposes removing GCM authentication tags below 96 bits; this is future hardening direction, not a finalized requirement.",
                }
            )
        result.append(
            {
                "rule_id": rule_id,
                "expected_severity": "medium",
                "expected_confidence": "high",
                "blocking_eligible": False,
                "sources": sources,
                "false_positive_analysis": RULE_EXPLANATIONS[rule_id]["false_positive"],
                "positive": [{"path": path, "source": source} for source in positive],
                "negative": [{"path": path, "source": source} for source in negative],
                "adversarial": adversarial,
            }
        )
    return result


def build() -> str:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    cohort = records()
    owned = {row["rule_id"] for row in cohort}
    payload["rules"] = [row for row in payload["rules"] if row["rule_id"] not in owned] + cohort
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = build()
    if args.check:
        if MANIFEST.read_text(encoding="utf-8") != rendered:
            print("stale TypeScript configuration contracts")
            return 1
    else:
        MANIFEST.write_text(rendered, encoding="utf-8")
    print("TypeScript configuration contracts current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
