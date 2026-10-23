"""Offline PHP2Shell declared-version evidence, not deployed-runtime detection."""

from __future__ import annotations

import re
from pathlib import Path

REVIEWED_AT = "2026-10-22"
ADVISORY_IDS = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_PATCHES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP_VERSION_PATTERN = re.compile(r"(5|7|8)\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]{0,3})")
WEB_IMAGE = re.compile(
    r"(?:php|library/php|docker\.io/library/php):"
    r"(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-(?:apache|fpm)"
    r"(?:-(?:alpine(?:[0-9]+\.[0-9]+)?|bookworm|bullseye|trixie))?"
)


def version_status(version: str) -> str:
    """Unknown strings/branches are not claimed fixed or affected."""
    match = PHP_VERSION_PATTERN.fullmatch(version)
    if match is None:
        return "unknown"
    major, minor, patch = (int(part) for part in match.groups())
    fixed = FIXED_PATCHES.get((major, minor))
    if fixed is not None:
        return "predates_fix" if patch < fixed else "fixed_upstream"
    if (
        (major == 5 and 4 <= minor <= 6)
        or (major == 7 and minor <= 4)
        or (major == 8 and minor <= 1)
    ):
        return "unsupported_upstream"
    return "unknown"


def docker_runtime(
    source: str, image_pattern: re.Pattern[str] = WEB_IMAGE
) -> tuple[str, int] | None:
    """Follow static stage aliases to the final FROM; never resolve a registry."""
    if "<<" in source:  # Heredocs can contain instruction-looking data.
        return None
    escape = "\\"
    instructions = []
    pending = ""
    start = 0
    directives_open = True
    escape_seen = False
    for number, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            directive = re.fullmatch(r"#\s*escape\s*=\s*([\\`])", stripped, re.IGNORECASE)
            if directive and directives_open:
                if escape_seen:
                    return None
                escape = directive[1]
                escape_seen = True
            elif not re.fullmatch(r"#\s*(?:syntax|check)\s*=.+", stripped, re.IGNORECASE):
                directives_open = False
            continue
        if not stripped:
            directives_open = False
            continue
        directives_open = False
        if not pending:
            start = number
        continued = stripped.endswith(escape)
        pending += (stripped[:-1] if continued else stripped) + " "
        if len(pending) > 8192:
            return None
        if not continued:
            instructions.append((start, pending.strip()))
            pending = ""
    if pending:
        return None
    stages: dict[str, tuple[str, int] | None] = {}
    final = None
    for number, instruction in instructions:
        if not re.match(r"FROM(?:\s|$)", instruction, re.IGNORECASE):
            continue
        final = None
        match = re.fullmatch(
            r"FROM\s+(?:--platform=[A-Za-z0-9_./$:+{}-]+\s+)?([^\s]+)"
            r"(?:\s+AS\s+([A-Za-z0-9_.-]+))?",
            instruction,
            re.IGNORECASE,
        )
        if match is None:
            continue
        image, alias = match.groups()
        pinned = image_pattern.fullmatch(image)
        if pinned:
            final = (pinned["version"], number)
        elif image.lower() in stages:
            final = stages[image.lower()]
        if alias:
            if alias.lower() in stages:
                return None
            stages[alias.lower()] = final
    return final


def advisory_declarations(path: Path, source: str) -> list[tuple[str, int]]:
    name = path.name.lower()
    version_line = None
    if name in {"dockerfile", "containerfile"}:
        version_line = docker_runtime(source)
    elif name == ".php-version":
        declarations = [
            (line.split("#", 1)[0].strip(), number)
            for number, line in enumerate(source.splitlines(), 1)
            if line.split("#", 1)[0].strip()
        ]
        if len(declarations) == 1:
            version_line = declarations[0]
    elif name == ".tool-versions":
        declarations = [
            (line.split("#", 1)[0].split(), number)
            for number, line in enumerate(source.splitlines(), 1)
            if line.split("#", 1)[0].split()[:1] == ["php"]
        ]
        if len(declarations) == 1 and len(declarations[0][0]) == 2:
            fields, number = declarations[0]
            version_line = (fields[1], number)
    if version_line is not None:
        version, number = version_line
        if version_status(version) in {"predates_fix", "unsupported_upstream"}:
            return [(version, number)]
    return []


def advisory_lines(path: Path, source: str) -> list[int]:
    return [number for _version, number in advisory_declarations(path, source)]
