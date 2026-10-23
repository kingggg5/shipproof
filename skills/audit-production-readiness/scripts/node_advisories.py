"""Offline Node runtime declarations against a dated upstream support snapshot."""

from __future__ import annotations

import re
from pathlib import Path

from php_advisories import docker_runtime

REVIEWED_AT = "2026-10-22"
FIXED_RELEASES = {22: (23, 4), 24: (22, 1), 26: (12, 1)}
ENDED_BRANCHES = frozenset({18, 20, 21, 23, 25})
VERSION = re.compile(r"v?(18|20|21|22|23|24|25|26)\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})")
NODE_IMAGE = re.compile(
    r"(?:node|library/node|docker\.io/library/node):(?P<version>[0-9]+\.[0-9]+\.[0-9]+)"
    r"(?:-(?:alpine(?:[0-9]+\.[0-9]+)?|slim|(?:bookworm|bullseye|trixie)(?:-slim)?))?"
)
DECLARATION_NAMES = frozenset(
    {".nvmrc", ".node-version", ".tool-versions", "dockerfile", "containerfile"}
)


def version_rule(version: str) -> str | None:
    match = VERSION.fullmatch(version)
    if match is None:
        return None
    major, minor, patch = (int(value) for value in match.groups())
    if major in ENDED_BRANCHES:
        return "SP685"
    fixed = FIXED_RELEASES.get(major)
    return "SP684" if fixed is not None and (minor, patch) < fixed else None


def advisory_declarations(path: Path, source: str) -> list[tuple[str, str, int]]:
    name = path.name if path.name.startswith(".") else path.name.lower()
    if name not in DECLARATION_NAMES:
        return []
    declaration = None
    if name in {"dockerfile", "containerfile"}:
        declaration = docker_runtime(source, NODE_IMAGE)
    else:
        for number, line in enumerate(source.splitlines(), 1):
            value = line.split("#", 1)[0].strip()
            if name == ".tool-versions":
                fields = value.split()
                if fields[:1] != ["nodejs"]:
                    continue
                if len(fields) != 2:
                    return []
                value = fields[1]
            elif not value:
                continue
            if declaration is not None:
                return []
            declaration = (value, number)
    if declaration is None:
        return []
    version, number = declaration
    rule_id = version_rule(version)
    return [(rule_id, version.removeprefix("v"), number)] if rule_id is not None else []
