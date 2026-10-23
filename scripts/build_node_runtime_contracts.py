"""Original declared-runtime cases for the October 2026 Node advisories."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/rule_cases_v2.json"
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
from scan_repo import RULE_EXPLANATIONS, find_rule  # noqa: E402


def case(path: str, source: str, **extra: object) -> dict:
    return {"path": path, "source": source, **extra}


def records() -> list[dict]:
    shared_negatives = [
        case(".nvmrc", value + "\n")
        for value in (
            "lts/*",
            "node",
            "system",
            "24",
            "24.22",
            "24.22.0-1+deb12u1",
            "24.22.0-rc.1",
            "24.022.0",
            "27.0.0",
            "24.22.1\n24.22.0",
        )
    ] + [
        case("package.json", '{"engines":{"node":">=18"},"devDependencies":{"node":"24.22.0"}}'),
        case(".tool-versions", "nodejs 24.22.0 system\n"),
        case(".tool-versions", "nodejs 24.22.0\nnodejs 24.22.1\n"),
        case("Dockerfile", "FROM custom/node:24.22.0\n"),
        case("Dockerfile", "FROM node:24.22.0-vendorfixed\n"),
        case("Dockerfile", "FROM node:24.22.0@sha256:" + "a" * 64 + "\n"),
        case(
            "Dockerfile",
            "FROM node:24.22.0 AS build\nFROM nginx:1.27\nCOPY --from=build /app /app\n",
        ),
        case("Dockerfile", "FROM node:24.22.0 AS unused\nFROM node:24.22.1 AS runtime\n"),
        case(
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps:\n      - uses: actions/setup-node@"
            + "a" * 40
            + "\n        with:\n          node-version: '20.19.0'\n",
        ),
        case("app.js", 'const documentation = "Node.js 24.22.0";\n'),
    ]
    adversarial = [
        case(
            "Dockerfile",
            "FROM node:24.22.1\nRUN cat <<'EOF'\nFROM node:24.22.0\nEOF\n",
            expected=False,
            rationale="A FROM-looking line inside heredoc data does not establish a runtime image. This unsupported context remains unresolved rather than replacing the final stage.",
        ),
        case(
            "Dockerfile",
            "FROM node:24.22.1\nRUN echo text \\\n FROM node:24.22.0\n",
            expected=False,
            rationale="A continued RUN instruction contains text, not a new runtime stage. Physical-line matching would incorrectly replace the patched base image.",
        ),
        case(
            "Dockerfile",
            "ARG BASE=node:24.22.0\nFROM ${BASE}\n",
            expected=False,
            rationale="Build arguments are overridable. This offline rule does not resolve the effective build input and must not claim that the declared default was deployed.",
        ),
        case(
            "Dockerfile",
            "FROM node:24.22.0 AS duplicate\nFROM duplicate AS duplicate\n",
            expected=False,
            rationale="Repeated stage aliases are ambiguous; an invalid or unresolved build graph cannot establish an effective final runtime version.",
        ),
    ]
    rows = [
        {
            "rule_id": "SP684",
            "sources": [
                {
                    "url": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
                    "claim": "The dated upstream bulletin links fixed Node releases 22.23.4, 24.22.1 and 26.12.1; it does not establish application reachability or complete introduced-version ranges.",
                },
                {
                    "url": "https://github.com/docker-library/official-images/blob/master/library/node",
                    "claim": "The official Node image has exact-version and supported variant tags. A floating tag, custom registry or digest override does not establish an exact runtime release.",
                },
            ],
            "positive": [
                case(".nvmrc", "v24.22.0\n"),
                case(".node-version", "22.23.3\n"),
                case(".tool-versions", "python 3.12.10\nnodejs 26.12.0\n"),
                case(".nvmrc", "24.15.0\n"),
                case(".node-version", "22.22.99\n"),
                case(
                    "Dockerfile", "FROM node:24.22.0-bookworm-slim AS base\nFROM base AS runtime\n"
                ),
                case(
                    "Containerfile",
                    "FROM --platform=linux/amd64 docker.io/library/node:22.23.3-alpine3.23\n",
                ),
                case("Dockerfile", "FROM library/node:26.12.0-slim\n"),
            ],
            "negative": shared_negatives
            + [
                case(".nvmrc", version + "\n")
                for version in (
                    "22.23.4",
                    "22.24.0",
                    "24.22.1",
                    "24.23.0",
                    "26.12.1",
                    "26.13.0",
                    "20.19.0",
                )
            ],
            "adversarial": adversarial,
        },
        {
            "rule_id": "SP685",
            "sources": [
                {
                    "url": "https://github.com/nodejs/Release/blob/main/schedule.json",
                    "claim": "The upstream EOL dates for branches 18/20/21/23/25 have passed in October 2026. Vendor extended support is a separate question, and engine compatibility ranges are not deployment pins.",
                },
                {
                    "url": "https://asdf-vm.com/manage/configuration.html#tool-versions",
                    "claim": "asdf documents tool/version entries, comments, custom paths and multiple fallback versions. Only a single exact nodejs entry supports this rule's declared-version evidence.",
                },
                {
                    "url": "https://github.com/nvm-sh/nvm#nvmrc",
                    "claim": "nvm documents one version per .nvmrc with comments, whitespace and aliases. This signature accepts exact releases; aliases, reserved key/value forms and ambiguous entries remain unresolved.",
                },
            ],
            "positive": [
                case(".nvmrc", version + "\n")
                for version in ("18.20.8", "20.19.0", "21.7.3", "23.11.0", "25.0.0")
            ]
            + [
                case("Dockerfile", "FROM node:20.19.0-bookworm-slim\n"),
                case(".tool-versions", "nodejs 20.19.0\n"),
            ],
            "negative": [
                {
                    **item,
                    "source": item["source"]
                    .replace("24.22.0", "20.19.0")
                    .replace("24.022.0", "20.019.0"),
                }
                for item in shared_negatives
            ]
            + [
                case(".node-version", version + "\n")
                for version in ("22.23.3", "22.23.4", "24.22.0", "24.22.1", "26.12.1")
            ],
            "adversarial": [
                {**item, "source": item["source"].replace("24.22.0", "20.19.0")}
                for item in adversarial
            ]
            + [
                case(
                    ".nvmrc",
                    "# historical Node 20.19.0\n24.22.1\n",
                    expected=False,
                    rationale="A comment describing an old release must not override the one active pin for a maintained runtime branch.",
                )
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


def build() -> str:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = records()
    payload["rules"] = [
        row for row in payload["rules"] if row["rule_id"] not in {"SP684", "SP685"}
    ] + rows
    payload["rules"].sort(key=lambda row: int(row["rule_id"][2:]))
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = build()
    if args.check:
        if MANIFEST.read_text(encoding="utf-8") != rendered:
            print("Node runtime contracts are stale", file=sys.stderr)
            return 1
    else:
        MANIFEST.write_bytes(rendered.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
